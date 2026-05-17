use std::ffi::{CStr, CString};
use libc::{c_char, c_void, c_int};
use std::collections::HashMap;
use once_cell::sync::Lazy;
use serde::Deserialize;
use radix_trie::Trie;
use std::fs;
use std::cell::{Cell, RefCell};
use std::borrow::Cow;
use std::sync::RwLock;
use tracing::{info, warn, error, debug};
use tracing_subscriber::FmtSubscriber;
use tracing_subscriber::filter::EnvFilter;

// --- Global Sticky Context ---
static LAST_USER_CONTEXT: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::from("root")));

// --- Recursion Guard and Buffers ---
thread_local! {
    static IN_ASTRAEA_HOOK: Cell<bool> = const { Cell::new(false) };
    static STRING_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(256));
}

// --- V8 FFI ---
mod v8;
use v8::*;

// --- Policy Engine ---

#[derive(Deserialize, Debug)]
struct Manifest {
    #[serde(default)]
    packages: HashMap<String, PackagePolicy>,
    #[serde(default)]
    spoofs: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct PackagePolicy {
    #[serde(default)]
    fs: Vec<String>,
}

struct PolicyEngine {
    fs_rules: HashMap<String, Trie<String, bool>>,
    spoof_map: HashMap<String, String>,
}

static ENGINE: Lazy<PolicyEngine> = Lazy::new(|| {
    let manifest_str = fs::read_to_string("astraea.toml").unwrap_or_else(|_| String::new());
    let manifest: Manifest = toml::from_str(&manifest_str).unwrap_or(Manifest { packages: HashMap::new(), spoofs: HashMap::new() });
    
    let mut fs_rules = HashMap::new();
    for (name, policy) in manifest.packages {
        let mut trie = Trie::new();
        for rule in policy.fs {
            if rule.starts_with("read:") {
                let path = rule.strip_prefix("read:").unwrap();
                trie.insert(path.to_string(), true);
            }
        }
        fs_rules.insert(name, trie);
    }
    
    for (original, mock_data) in &manifest.spoofs {
        let spoof_path = format!(".astraea_spoof_{}", original.replace('/', "_"));
        fs::write(&spoof_path, mock_data).ok();
    }

    PolicyEngine { fs_rules, spoof_map: manifest.spoofs }
});

#[no_mangle]
pub extern "C" fn init_engine() {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_thread_ids(true)
        .with_target(false)
        .finish();

    if tracing::subscriber::set_global_default(subscriber).is_err() {
        eprintln!("Astraea: Failed to set global tracing subscriber");
    }

    info!("Astraea engine initializing...");
    IN_ASTRAEA_HOOK.with(|h| h.set(true));
    Lazy::force(&ENGINE);
    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    info!("Astraea engine ready.");
}

/// C-ABI logging interface for the Zig interceptor.
///
/// # Safety
///
/// The `message` must be a valid pointer to a null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn astraea_log(level: i32, message: *const c_char) {
    if message.is_null() { return; }
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

// --- Helpers ---

fn get_string_into(isolate: *mut c_void, string_handle: *mut c_void, out: &mut String) -> bool {
    if string_handle.is_null() { return false; }
    unsafe {
        let len = v8_string_utf8_length(string_handle, isolate);
        if len == 0 {
            out.clear();
            return true;
        }
        STRING_BUFFER.with(|cell| {
            let mut buf = cell.borrow_mut();
            let capacity = buf.capacity();
            if capacity < len + 1 {
                buf.reserve((len + 1) - capacity);
            }
            buf.resize(len + 1, 0);
            v8_string_write_utf8(string_handle, isolate, buf.as_mut_ptr() as *mut c_char, (len + 1) as c_int, std::ptr::null_mut(), 0);
            
            if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                out.clear();
                out.push_str(s);
                return true;
            }
            false
        })
    }
}

fn extract_package_name(path: &str) -> &str {
    if path.is_empty() || path == "Unknown (Internal/Async)" { return "root"; }
    if let Some(idx) = path.find("node_modules/") {
        let after_node_modules = &path[idx + 13..];
        if after_node_modules.starts_with('@') {
            if let Some(slash_idx) = after_node_modules.find('/') {
                if let Some(second_slash) = after_node_modules[slash_idx + 1..].find('/') {
                    return &after_node_modules[..slash_idx + 1 + second_slash];
                }
            }
        } else if let Some(slash_idx) = after_node_modules.find('/') {
            return &after_node_modules[..slash_idx];
        }
        return after_node_modules;
    }
    if path.starts_with("node:") || path.starts_with("internal/") { return path; }
    if path == "[eval]" { return "eval"; }
    "root"
}

fn normalize_path(path: &str) -> Cow<'_, str> {
    if !path.contains('.') && !path.contains("//") {
        return Cow::Borrowed(path);
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => { parts.pop(); },
            _ => { parts.push(part); }
        }
    }
    let normalized = if path.starts_with('/') {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    };
    Cow::Owned(normalized)
}

/// Captures the current JS stack and writes the script name of the first user-land frame to the buffer.
///
/// # Safety
///
/// The `buffer` must be a valid pointer to at least `max_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn capture_js_stack(buffer: *mut u8, max_len: usize) -> usize {
    let isolate = v8_isolate_try_get_current();
    if isolate.is_null() { return 0; }
    let mut handle_scope = [0u64; 4]; 
    v8_handle_scope_ctor(handle_scope.as_mut_ptr() as *mut c_void, isolate);
    let mut js_origin = String::with_capacity(128);
    let stack_handle = v8_stack_trace_current(isolate, 10, 0);
    if !stack_handle.is_null() {
        let frame_count = v8_stack_trace_get_frame_count(stack_handle);
        for i in 0..frame_count {
            let frame_handle = v8_stack_trace_get_frame(stack_handle, isolate, i as u32);
            if !frame_handle.is_null() {
                let script_name_handle = v8_stack_frame_get_script_name(frame_handle);
                if get_string_into(isolate, script_name_handle, &mut js_origin) 
                    && !js_origin.is_empty() && !js_origin.starts_with("node:") && !js_origin.starts_with("internal/") {
                    break;
                }
            }
        }
    }
    v8_handle_scope_dtor(handle_scope.as_mut_ptr() as *mut c_void);
    if js_origin.is_empty() { return 0; }
    if let Ok(mut sticky) = LAST_USER_CONTEXT.write() { *sticky = js_origin.clone(); }
    let bytes = js_origin.as_bytes();
    let len = std::cmp::min(bytes.len(), max_len);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, len);
    len
}

/// Frees a string allocated by the brain and returned via `EvaluationResult`.
///
/// # Safety
///
/// The `ptr` must be a valid pointer to a C-compatible string previously returned by `evaluate_fs_access`.
#[no_mangle]
pub unsafe extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() { let _ = CString::from_raw(ptr); }
}

fn is_path_allowed(package_name: &str, requested_path: &str) -> bool {
    // Always allow internal Node.js modules
    if package_name.starts_with("node:") || package_name.starts_with("internal/") {
        return true;
    }

    // Always allow certain system paths required for the runtime to function
    if requested_path.starts_with("/data/data/com.termux/files/usr/etc/") || 
       requested_path.starts_with("/proc/") || 
       requested_path.starts_with("/sys/") ||
       requested_path.starts_with("/dev/") ||
       requested_path == "/etc/hosts" ||
       requested_path == "/etc/resolv.conf" {
        return true;
    }

    if let Some(trie) = ENGINE.fs_rules.get(package_name) {
        if trie.get("**").is_some() { true }
        else { 
            let normalized = normalize_path(requested_path);
            trie.get_ancestor_value(normalized.as_ref()).is_some() 
        }
    } else {
        package_name == "root"
    }
}

/// Evaluates whether a file system access should be allowed, denied, or spoofed.
///
/// # Safety
///
/// The `path` and `_async_context` pointers must be null or point to valid C-compatible strings.
#[no_mangle]
pub unsafe extern "C" fn evaluate_fs_access(path: *const c_char, _async_context: *const c_char) -> EvaluationResult {
    if path.is_null() { return EvaluationResult { decision: DECISION_ALLOW, redirect_path: std::ptr::null_mut() }; }
    if IN_ASTRAEA_HOOK.with(|h| h.get()) { return EvaluationResult { decision: DECISION_ALLOW, redirect_path: std::ptr::null_mut() }; }
    IN_ASTRAEA_HOOK.with(|h| h.set(true));

    let res = (|| {
        let c_str = CStr::from_ptr(path);
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return (DECISION_DENY, None),
        };

        let mut js_origin_local = String::with_capacity(128);
        let js_origin: &str;
        let isolate = v8_isolate_try_get_current();
        
        if !isolate.is_null() {
            let mut handle_scope = [0u64; 4]; 
            v8_handle_scope_ctor(handle_scope.as_mut_ptr() as *mut c_void, isolate);
            let stack_handle = v8_stack_trace_current(isolate, 10, 0);
            if !stack_handle.is_null() {
                let frame_count = v8_stack_trace_get_frame_count(stack_handle);
                for i in 0..frame_count {
                    let frame_handle = v8_stack_trace_get_frame(stack_handle, isolate, i as u32);
                    if !frame_handle.is_null() {
                        let script_name_handle = v8_stack_frame_get_script_name(frame_handle);
                        if get_string_into(isolate, script_name_handle, &mut js_origin_local) 
                            && !js_origin_local.is_empty() && !js_origin_local.starts_with("node:") && !js_origin_local.starts_with("internal/") { 
                            break; 
                        }
                    }
                }
            }
            v8_handle_scope_dtor(handle_scope.as_mut_ptr() as *mut c_void);
            if !js_origin_local.is_empty() {
                if let Ok(mut sticky) = LAST_USER_CONTEXT.write() { *sticky = js_origin_local.clone(); }
            }
        }
        
        // Use Sticky Context if still Unknown
        let sticky_holder;
        if js_origin_local.is_empty() {
            if let Ok(sticky) = LAST_USER_CONTEXT.read() { 
                sticky_holder = sticky.clone();
                js_origin = &sticky_holder; 
            } else {
                js_origin = "Unknown (Internal/Async)";
            }
        } else {
            js_origin = &js_origin_local;
        }

        let package_name = extract_package_name(js_origin);
        
        if let Some(_mock) = ENGINE.spoof_map.get(path_str) {
            info!(target: "astraea", "SPOOF: package '{}' -> '{}' (redirected to mock)", package_name, path_str);
             return (DECISION_SPOOF, Some(format!(".astraea_spoof_{}", path_str.replace('/', "_"))));
        }

        let allowed = is_path_allowed(package_name, path_str);
        
        if !allowed { 
            warn!(target: "astraea", "DENY: package '{}' -> '{}' (unauthorized access)", package_name, path_str);
            (DECISION_DENY, None) 
        } else { 
            debug!(target: "astraea", "ALLOW: package '{}' -> '{}'", package_name, path_str);
            (DECISION_ALLOW, None) 
        }
    })();

    IN_ASTRAEA_HOOK.with(|h| h.set(false));
    EvaluationResult {
        decision: res.0,
        redirect_path: res.1.map(|s| CString::new(s).unwrap().into_raw()).unwrap_or(std::ptr::null_mut()),
    }
}
