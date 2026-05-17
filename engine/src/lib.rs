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
mod fs;
mod guardian;
mod net;
mod proc_env;
mod v8;

use attribution::*;
use fs::FsManager;
use net::NetManager;
use proc_env::ProcEnvManager;

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

#[derive(Deserialize, Debug, Default)]
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

struct AstraeaEngine {
    fs: FsManager,
    net: NetManager,
    proc_env: ProcEnvManager,
    native_addon_rules: HashMap<String, Vec<String>>,
    seccomp: SeccompConfig,
}

static ENGINE: Lazy<AstraeaEngine> = Lazy::new(|| {
    let manifest_str = std::fs::read_to_string("astraea.toml").unwrap_or_else(|_| String::new());
    let manifest: Manifest = toml::from_str(&manifest_str).unwrap_or(Manifest {
        packages: HashMap::new(),
        spoofs: HashMap::new(),
        seccomp: SeccompConfig::default(),
    });

    let mut native_addon_rules = HashMap::new();
    for (name, policy) in &manifest.packages {
        native_addon_rules.insert(name.clone(), policy.native_addons.clone());
    }

    AstraeaEngine {
        fs: FsManager::new(manifest.packages.clone(), manifest.spoofs),
        net: NetManager::new(manifest.packages.clone()),
        proc_env: ProcEnvManager::new(manifest.packages),
        native_addon_rules,
        seccomp: manifest.seccomp,
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
    guardian::apply_policy(&engine.seccomp);

    IN_ASTRAEA_HOOK.with(|h| h.set(false));

    info!("Astraea engine ready.");
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

/// Primary entry point for filesystem capability evaluation.
///
/// # Safety
///
/// The `path` pointer must be a valid, null-terminated C string.
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

        if let Some(spoof_path) = ENGINE.fs.get_spoof(path_str) {
            info!(target: "astraea", "SPOOF: package '{}' -> '{}' (redirected to mock)", package, path_str);
            return (DECISION_SPOOF, Some(spoof_path));
        }

        if ENGINE.fs.is_allowed(&package, path_str) {
            (DECISION_ALLOW, None)
        } else {
            (DECISION_DENY, None)
        }
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
    let is_addon = path_str.ends_with(".node");

    let allowed = if !is_addon {
        true
    } else if let Some(allowed_addons) = ENGINE.native_addon_rules.get(&package) {
        allowed_addons
            .iter()
            .any(|a| path_str.ends_with(a) || (a == "*.node"))
    } else {
        package == "root"
    };

    IN_ASTRAEA_HOOK.with(|h| h.set(false));

    if !allowed {
        warn!(target: "astraea", "DENY DLOPEN: package '{}' -> '{}' (unauthorized native addon)", package, path_str);
        DECISION_DENY
    } else {
        debug!(target: "astraea", "ALLOW DLOPEN: package '{}' -> '{}'", package, path_str);
        DECISION_ALLOW
    }
}

/// Evaluates whether a network connection should be allowed.
///
/// # Safety
///
/// The `host` pointer must be a valid, null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn evaluate_net_access(host: *const c_char, port: u16) -> i32 {
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
    let allowed = ENGINE.net.is_allowed(&package, host_str, port);

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    if allowed {
        DECISION_ALLOW
    } else {
        DECISION_DENY
    }
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
    let allowed = ENGINE.proc_env.is_env_allowed(&package, key_str);

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    if allowed {
        DECISION_ALLOW
    } else {
        DECISION_DENY
    }
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
    let allowed = ENGINE.proc_env.is_proc_allowed(&package, binary_str);

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    if allowed {
        DECISION_ALLOW
    } else {
        DECISION_DENY
    }
}

/// Registers the result of a successful DNS resolution in the local cache.
///
/// # Safety
///
/// Both `domain` and `ip` pointers must be valid, null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn register_dns_result(domain: *const c_char, ip: *const c_char) {
    if domain.is_null() || ip.is_null() {
        return;
    }
    if IN_ASTRAEA_HOOK.with(|h| h.get()) {
        return;
    }
    IN_ASTRAEA_HOOK.with(|h| h.set(true));

    if let (Ok(d), Ok(i)) = (CStr::from_ptr(domain).to_str(), CStr::from_ptr(ip).to_str()) {
        let package = get_current_package();
        debug!(target: "astraea", "DNS CACHE: package '{}' resolved '{}' -> '{}'", package, d, i);
        ENGINE.net.register_dns(&package, d, vec![i.to_string()]);
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
