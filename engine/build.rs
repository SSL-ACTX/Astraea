use std::process::Command;
use std::collections::HashMap;
use std::path::Path;
use std::env;
use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("v8_bindings.rs");

    // 1. Find the node binary
    let mut node_path = String::from("/data/data/com.termux/files/usr/bin/node");
    if !Path::new(&node_path).exists() {
        let which_node = Command::new("which")
            .arg("node")
            .output()
            .expect("failed to run which node");
        if which_node.status.success() {
            node_path = String::from_utf8_lossy(&which_node.stdout).trim().to_string();
        } else {
            panic!("Node.js binary not found. V8 discovery failed. Ensure 'node' is in your PATH.");
        }
    }

    // 2. Get mangled symbols (Address -> Mangled Name)
    let nm_mangled = Command::new("nm").args(["-D", &node_path]).output().expect("failed to run nm");
    let mangled_out = String::from_utf8_lossy(&nm_mangled.stdout);
    let mut addr_to_mangled = HashMap::new();
    for line in mangled_out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            addr_to_mangled.insert(parts[0], parts[2]);
        }
    }

    // 3. Get demangled symbols (Address -> Demangled Name)
    let nm_demangled = Command::new("nm").args(["-D", "--demangle", &node_path]).output().expect("failed to run nm --demangle");
    let demangled_out = String::from_utf8_lossy(&nm_demangled.stdout);
    let mut demangled_to_mangled = HashMap::new();
    for line in demangled_out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let addr = parts[0];
            let demangled = &line[line.find(parts[2]).unwrap()..];
            if let Some(mangled) = addr_to_mangled.get(addr) {
                demangled_to_mangled.insert(demangled.to_string(), mangled.to_string());
            }
        }
    }

    // 4. Define our target functions and their expected signatures
    let targets = vec![
        ("v8_isolate_try_get_current", "v8::Isolate::TryGetCurrent()"),
        ("v8_handle_scope_ctor", "v8::HandleScope::HandleScope(v8::Isolate*)"),
        ("v8_handle_scope_dtor", "v8::HandleScope::~HandleScope()"),
        ("v8_stack_trace_current", "v8::StackTrace::CurrentStackTrace(v8::Isolate*, int, v8::StackTrace::StackTraceOptions)"),
        ("v8_stack_trace_get_frame_count", "v8::StackTrace::GetFrameCount() const"),
        ("v8_stack_trace_get_frame", "v8::StackTrace::GetFrame(v8::Isolate*, unsigned int) const"),
        ("v8_stack_frame_get_script_name", "v8::StackFrame::GetScriptName() const"),
        ("v8_string_utf8_length", "v8::String::Utf8Length(v8::Isolate*) const"),
        ("v8_string_write_utf8", "v8::String::WriteUtf8(v8::Isolate*, char*, int, int*, int) const"),
    ];

    let mut bindings = String::from("extern \"C\" {\n");
    for (rust_name, cpp_sig) in targets {
        let mangled = demangled_to_mangled.get(cpp_sig).unwrap_or_else(|| panic!("Could not find symbol for {}", cpp_sig));
        
        let decl = match rust_name {
            "v8_isolate_try_get_current" => format!("    #[link_name = \"{}\"]\n    pub fn v8_isolate_try_get_current() -> *mut c_void;", mangled),
            "v8_handle_scope_ctor" => format!("    #[link_name = \"{}\"]\n    pub fn v8_handle_scope_ctor(this: *mut c_void, isolate: *mut c_void);", mangled),
            "v8_handle_scope_dtor" => format!("    #[link_name = \"{}\"]\n    pub fn v8_handle_scope_dtor(this: *mut c_void);", mangled),
            "v8_stack_trace_current" => format!("    #[link_name = \"{}\"]\n    pub fn v8_stack_trace_current(isolate: *mut c_void, frame_limit: c_int, options: c_int) -> *mut c_void;", mangled),
            "v8_stack_trace_get_frame_count" => format!("    #[link_name = \"{}\"]\n    pub fn v8_stack_trace_get_frame_count(this: *mut c_void) -> c_int;", mangled),
            "v8_stack_trace_get_frame" => format!("    #[link_name = \"{}\"]\n    pub fn v8_stack_trace_get_frame(this: *mut c_void, isolate: *mut c_void, index: u32) -> *mut c_void;", mangled),
            "v8_stack_frame_get_script_name" => format!("    #[link_name = \"{}\"]\n    pub fn v8_stack_frame_get_script_name(this: *mut c_void) -> *mut c_void;", mangled),
            "v8_string_utf8_length" => format!("    #[link_name = \"{}\"]\n    pub fn v8_string_utf8_length(this: *mut c_void, isolate: *mut c_void) -> usize;", mangled),
            "v8_string_write_utf8" => format!("    #[link_name = \"{}\"]\n    pub fn v8_string_write_utf8(this: *mut c_void, isolate: *mut c_void, buffer: *mut c_char, length: c_int, nchars_ref: *mut c_int, options: c_int) -> c_int;", mangled),
            _ => unreachable!(),
        };
        bindings.push_str(&decl);
        bindings.push('\n');
    }
    bindings.push_str("}\n");

    fs::write(dest_path, bindings).expect("Unable to write bindings file");
}
