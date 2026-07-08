use libc::c_char;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use tracing::{debug, error, info, warn};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::FmtSubscriber;

// Modules
mod attribution;
pub mod audit;
pub mod evaluator;
mod fs;
mod guardian;
pub mod ipc;
mod net;
mod proc_env;
mod v8;

use attribution::*;
use audit::{AuditEvent, AuditLogger};

// --- Global Context & Guards ---
thread_local! {
    pub static IN_ASTRAEA_HOOK: Cell<bool> = const { Cell::new(false) };
}

// --- Manifest Types ---

#[derive(Deserialize, Debug)]
pub struct Manifest {
    #[serde(default)]
    pub packages: HashMap<String, PackagePolicy>,
    #[serde(default)]
    pub spoofs: HashMap<String, String>,
    #[serde(default)]
    pub seccomp: SeccompConfig,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct SeccompConfig {
    #[serde(default)]
    pub allowed_syscalls: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PackagePolicy {
    #[serde(default)]
    pub fs: Vec<String>,
    #[serde(default)]
    pub native_addons: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub proc: Vec<String>,
}

// --- Global State ---

use evaluator::local::LocalEvaluator;
use evaluator::remote::RemoteEvaluator;
use evaluator::Evaluator;

struct AstraeaEngine {
    evaluator: Box<dyn Evaluator>,
    seccomp: SeccompConfig,
    audit: Option<AuditLogger>,
}

static ENGINE: Lazy<AstraeaEngine> = Lazy::new(|| {
    let audit_path = std::env::var("ASTRAEA_AUDIT").ok();
    let telemetry_path = std::env::var("ASTRAEA_TELEMETRY").ok();

    let audit = if let Some(path) = telemetry_path {
        Some(AuditLogger::new(audit::AuditSink::Uds(path)))
    } else if let Some(path) = audit_path {
        Some(AuditLogger::new(audit::AuditSink::File(path)))
    } else {
        None
    };

    if std::env::var("ASTRAEA_DAEMON").is_ok() {
        let socket_path = std::env::temp_dir().join("astraea.sock");
        let evaluator = Box::new(RemoteEvaluator::new(socket_path.to_str().unwrap()));
        info!("Astraea Engine: Operating in REMOTE (Daemon) mode.");

        AstraeaEngine {
            evaluator,
            seccomp: SeccompConfig::default(), // Seccomp usually managed by daemon or skipped in remote
            audit,
        }
    } else {
        let config_path = std::env::var("ASTRAEA_CONFIG").unwrap_or_else(|_| String::from("astraea.toml"));
        let manifest_str =
            std::fs::read_to_string(&config_path).unwrap_or_else(|_| String::new());
        let manifest: Manifest = toml::from_str(&manifest_str).unwrap_or(Manifest {
            packages: HashMap::new(),
            spoofs: HashMap::new(),
            seccomp: SeccompConfig::default(),
        });

        let seccomp = manifest.seccomp.clone();
        let evaluator = Box::new(LocalEvaluator::new(manifest, None)); // Audit handled by engine
        info!("Astraea Engine: Operating in LOCAL (Standalone) mode.");

        AstraeaEngine {
            evaluator,
            seccomp,
            audit,
        }
    }
});

// --- FFI Interface ---

#[no_mangle]
pub extern "C" fn init_engine() {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_thread_ids(true)
        .with_target(false)
        .finish();

    if tracing::subscriber::set_global_default(subscriber).is_err() {
        eprintln!("Astraea: Failed to set global tracing subscriber");
    }

    info!("Astraea (Robust Security Mesh) initializing...");
    IN_ASTRAEA_HOOK.with(|h| h.set(true));

    // Trigger Lazy initialization
    let engine = &*ENGINE;
    if std::env::var("ASTRAEA_DAEMON").is_err() {
        guardian::apply_policy(&engine.seccomp);
    }

    IN_ASTRAEA_HOOK.with(|h| h.set(false));

    info!("Astraea engine ready.");
}

fn log_event(package: &str, action: &str, target: &str, allowed: bool) {
    if let Some(audit) = &ENGINE.audit {
        audit.log(AuditEvent {
            package: package.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            allowed,
        });
    }
}

/// C-ABI logging interface for the Zig interceptor.
///
/// # Safety
///
/// The `message` pointer must be a valid, null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn astraea_log(level: i32, message: *const c_char) {
    if message.is_null() {
        return;
    }
    let msg = match CStr::from_ptr(message).to_str() {
        Ok(s) => s,
        Err(_) => return,
    };

    match level {
        0 => error!("{}", msg),
        1 => warn!("{}", msg),
        2 => info!("{}", msg),
        3 => debug!("{}", msg),
        _ => info!("{}", msg),
    }
}

#[repr(C)]
pub struct EvaluationResult {
    pub decision: i32,
    pub redirect_path: *mut c_char,
}

const DECISION_DENY: i32 = 0;
const DECISION_ALLOW: i32 = 1;
const DECISION_SPOOF: i32 = 2;

#[no_mangle]
pub unsafe extern "C" fn evaluate_fs_access(
    path: *const c_char,
    _async_context: *const c_char,
) -> EvaluationResult {
    if path.is_null() {
        return EvaluationResult {
            decision: DECISION_ALLOW,
            redirect_path: std::ptr::null_mut(),
        };
    }
    if IN_ASTRAEA_HOOK.with(|h| h.get()) {
        return EvaluationResult {
            decision: DECISION_ALLOW,
            redirect_path: std::ptr::null_mut(),
        };
    }
    IN_ASTRAEA_HOOK.with(|h| h.set(true));

    let res = (|| {
        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return (DECISION_DENY, None),
        };

        let package = get_current_package();
        let (decision, redirect_path) = ENGINE.evaluator.evaluate_fs(&package, path_str);

        if decision == DECISION_SPOOF {
            log_event(&package, "fs", &format!("spoof:{}", path_str), true);
        } else {
            let allowed = decision == DECISION_ALLOW;
            log_event(&package, "fs", &format!("read:{}", path_str), allowed);
            if !allowed {
                warn!(target: "astraea", "DENY FS: package '{}' -> '{}'", package, path_str);
            }
        }
        (decision, redirect_path)
    })();

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    EvaluationResult {
        decision: res.0,
        redirect_path: res
            .1
            .map(|s| CString::new(s).unwrap().into_raw())
            .unwrap_or(std::ptr::null_mut()),
    }
}

/// Evaluates whether a dynamic library (native addon) should be allowed to load.
///
/// # Safety
///
/// The `path` pointer must be a valid, null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn evaluate_dlopen(path: *const c_char) -> i32 {
    if path.is_null() {
        return DECISION_ALLOW;
    }
    if IN_ASTRAEA_HOOK.with(|h| h.get()) {
        return DECISION_ALLOW;
    }
    IN_ASTRAEA_HOOK.with(|h| h.set(true));

    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => {
            IN_ASTRAEA_HOOK.with(|h| h.set(false));
            return DECISION_DENY;
        }
    };

    let package = get_current_package();
    let decision = ENGINE.evaluator.evaluate_dlopen(&package, path_str);
    let allowed = decision == DECISION_ALLOW;

    if path_str.ends_with(".node") {
        log_event(&package, "native_addons", path_str, allowed);
        if !allowed {
            warn!(target: "astraea", "DENY DLOPEN: package '{}' -> '{}'", package, path_str);
        }
    }

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    decision
}

/// Evaluates whether a network connection should be allowed.
///
/// # Safety
///
/// The `host` pointer must be a valid, null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn evaluate_net_access(
    host: *const c_char,
    port: u16,
    action: i32,
    protocol: i32,
) -> i32 {
    if host.is_null() {
        return DECISION_ALLOW;
    }
    if IN_ASTRAEA_HOOK.with(|h| h.get()) {
        return DECISION_ALLOW;
    }
    IN_ASTRAEA_HOOK.with(|h| h.set(true));

    let host_str = match CStr::from_ptr(host).to_str() {
        Ok(s) => s,
        Err(_) => {
            IN_ASTRAEA_HOOK.with(|h| h.set(false));
            return DECISION_DENY;
        }
    };

    let package = get_current_package();
    let decision = ENGINE
        .evaluator
        .evaluate_net(&package, host_str, port, action, protocol);
    let allowed = decision == DECISION_ALLOW;

    let action_str = match action {
        1 => "bind",
        _ => "connect",
    };

    let proto_str = match protocol {
        6 => "tcp",
        17 => "udp",
        _ => "any",
    };

    log_event(
        &package,
        "network",
        &format!("{}:{}:{}:{}", action_str, proto_str, host_str, port),
        allowed,
    );

    if !allowed {
        warn!(target: "astraea", "DENY NET: package '{}' -> '{}:{}' ({}/{})", package, host_str, port, action_str, proto_str);
    }

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    decision
}

/// Evaluates whether an environment variable modification should be allowed.
///
/// # Safety
///
/// The `key` pointer must be a valid, null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn evaluate_env_access(key: *const c_char) -> i32 {
    if key.is_null() {
        return DECISION_ALLOW;
    }
    if IN_ASTRAEA_HOOK.with(|h| h.get()) {
        return DECISION_ALLOW;
    }
    IN_ASTRAEA_HOOK.with(|h| h.set(true));

    let key_str = match CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => {
            IN_ASTRAEA_HOOK.with(|h| h.set(false));
            return DECISION_DENY;
        }
    };

    let package = get_current_package();
    let decision = ENGINE.evaluator.evaluate_env(&package, key_str);
    let allowed = decision == DECISION_ALLOW;

    log_event(&package, "env", key_str, allowed);
    if !allowed {
        warn!(target: "astraea", "DENY ENV: package '{}' -> '{}'", package, key_str);
    }

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    decision
}

/// Evaluates whether a process execution should be allowed.
///
/// # Safety
///
/// The `binary` pointer must be a valid, null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn evaluate_proc_access(binary: *const c_char) -> i32 {
    if binary.is_null() {
        return DECISION_ALLOW;
    }
    if IN_ASTRAEA_HOOK.with(|h| h.get()) {
        return DECISION_ALLOW;
    }
    IN_ASTRAEA_HOOK.with(|h| h.set(true));

    let binary_str = match CStr::from_ptr(binary).to_str() {
        Ok(s) => s,
        Err(_) => {
            IN_ASTRAEA_HOOK.with(|h| h.set(false));
            return DECISION_DENY;
        }
    };

    let package = get_current_package();
    let decision = ENGINE.evaluator.evaluate_proc(&package, binary_str);
    let allowed = decision == DECISION_ALLOW;

    log_event(&package, "proc", binary_str, allowed);
    if !allowed {
        warn!(target: "astraea", "DENY PROC: package '{}' -> '{}'", package, binary_str);
    }

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    decision
}

/// Registers the result of a successful DNS resolution in the local cache.
///
/// # Safety
///
/// Both `domain` and `ip` pointers must be valid, null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn register_dns_result(domain: *const c_char, ip: *const c_char, ttl: u32) {
    if domain.is_null() || ip.is_null() {
        return;
    }
    if IN_ASTRAEA_HOOK.with(|h| h.get()) {
        return;
    }
    IN_ASTRAEA_HOOK.with(|h| h.set(true));

    if let (Ok(d), Ok(i)) = (CStr::from_ptr(domain).to_str(), CStr::from_ptr(ip).to_str()) {
        let package = get_current_package();
        ENGINE.evaluator.register_dns(&package, d, i, ttl);
    }

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
}

/// Safely frees a string that was allocated by the Rust engine and passed to C.
///
/// # Safety
///
/// The `ptr` must have been created by `CString::into_raw` within the Astraea engine.
#[no_mangle]
pub unsafe extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}
