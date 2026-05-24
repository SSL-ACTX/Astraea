use crate::v8::*;
use libc::{c_char, c_int};
use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::RwLock;

// --- Global Sticky Context ---
pub static LAST_USER_CONTEXT: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new(String::from("root")));

thread_local! {
    pub static STRING_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(256));
}

fn get_string_into(isolate: *mut c_void, string_handle: *mut c_void, out: &mut String) -> bool {
    if string_handle.is_null() {
        return false;
    }

    let v8 = match V8.as_ref() {
        Some(v) => v,
        None => return false,
    };

    unsafe {
        let len = (v8.string_utf8_length)(string_handle, isolate);
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
            (v8.string_write_utf8)(
                string_handle,
                isolate,
                buf.as_mut_ptr() as *mut c_char,
                (len + 1) as c_int,
                std::ptr::null_mut(),
                0,
            );

            if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                out.clear();
                out.push_str(s);
                return true;
            }
            false
        })
    }
}

pub fn extract_package_name(path: &str) -> &str {
    if path.is_empty() || path == "Unknown (Internal/Async)" {
        return "root";
    }

    // Explicitly handle [eval] which Node uses for -e code
    if path == "[eval]" {
        return "eval";
    }

    // Safety: If the attribution lands on a node: or internal/ module,
    // it means it was called on behalf of the root application or a module.
    if path.starts_with("node:") || path.starts_with("internal/") {
        return "root";
    }

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

    "root"
}

pub fn get_current_package() -> String {
    let mut js_origin_local = String::with_capacity(128);

    if let Some(v8) = V8.as_ref() {
        let isolate = unsafe { (v8.isolate_try_get_current)() };

        if !isolate.is_null() {
            unsafe {
                let mut handle_scope = [0u64; 4];
                (v8.handle_scope_ctor)(handle_scope.as_mut_ptr() as *mut c_void, isolate);
                let stack_handle = (v8.stack_trace_current)(isolate, 50, 0);
                if !stack_handle.is_null() {
                    let frame_count = (v8.stack_trace_get_frame_count)(stack_handle);

                    // Stack Anomaly Detection: Monitor for unusual stack depths
                    if frame_count >= 50 {
                        tracing::warn!(
                            "STACK ANOMALY: Unusual stack depth detected: {}",
                            frame_count
                        );
                        crate::log_event(
                            "root",
                            "stack_anomaly",
                            &format!("depth:{}", frame_count),
                            true,
                        );
                    }

                    for i in 0..frame_count {
                        let frame_handle =
                            (v8.stack_trace_get_frame)(stack_handle, isolate, i as u32);
                        if !frame_handle.is_null() {
                            let script_name_handle = (v8.stack_frame_get_script_name)(frame_handle);
                            if get_string_into(isolate, script_name_handle, &mut js_origin_local)
                                && !js_origin_local.is_empty()
                                && !js_origin_local.starts_with("node:")
                                && !js_origin_local.starts_with("internal/")
                            {
                                break;
                            }
                        }
                    }
                }
                (v8.handle_scope_dtor)(handle_scope.as_mut_ptr() as *mut c_void);
            }
            if !js_origin_local.is_empty() {
                if let Ok(mut sticky) = LAST_USER_CONTEXT.write() {
                    *sticky = js_origin_local.clone();
                }
            }
        }
    }

    let js_origin = if js_origin_local.is_empty() {
        if let Ok(sticky) = LAST_USER_CONTEXT.read() {
            sticky.clone()
        } else {
            String::from("Unknown (Internal/Async)")
        }
    } else {
        js_origin_local
    };

    extract_package_name(&js_origin).to_string()
}
