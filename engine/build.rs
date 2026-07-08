use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("v8_symbols.rs");

    // Resolve the Node.js binary path for symbol discovery.
    let mut node_path = String::from("/data/data/com.termux/files/usr/bin/node");
    if !Path::new(&node_path).exists() {
        let which_node = Command::new("which")
            .arg("node")
            .output()
            .expect("failed to run which node");
        if which_node.status.success() {
            node_path = String::from_utf8_lossy(&which_node.stdout)
                .trim()
                .to_string();
        } else {
            // Fallback for environments without Node (but we need it for symbol discovery)
            fs::write(dest_path, "").expect("Unable to write empty bindings");
            return;
        }
    }

    // Map virtual addresses to mangled C++ symbols using nm.
    let nm_mangled = Command::new("nm")
        .args(["-D", &node_path])
        .output()
        .expect("failed to run nm");
    let mangled_out = String::from_utf8_lossy(&nm_mangled.stdout);
    let mut addr_to_mangled = HashMap::new();
    for line in mangled_out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            addr_to_mangled.insert(parts[0], parts[2]);
        }
    }

    // Resolve demangled signatures to their corresponding mangled identifiers.
    let nm_demangled = Command::new("nm")
        .args(["-D", "--demangle", &node_path])
        .output()
        .expect("failed to run nm --demangle");
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

    // Define internal V8 target functions and their expected demangled signatures.
    let targets = vec![
        ("V8_ISOLATE_TRY_GET_CURRENT", "v8::Isolate::TryGetCurrent()"),
        ("V8_ISOLATE_GET_CURRENT_CONTEXT", "v8::Isolate::GetCurrentContext()"),
        ("V8_HANDLE_SCOPE_CTOR", "v8::HandleScope::HandleScope(v8::Isolate*)"),
        ("V8_HANDLE_SCOPE_DTOR", "v8::HandleScope::~HandleScope()"),
        ("V8_STACK_TRACE_CURRENT", "v8::StackTrace::CurrentStackTrace(v8::Isolate*, int, v8::StackTrace::StackTraceOptions)"),
        ("V8_STACK_TRACE_GET_FRAME_COUNT", "v8::StackTrace::GetFrameCount() const"),
        ("V8_STACK_TRACE_GET_FRAME", "v8::StackTrace::GetFrame(v8::Isolate*, unsigned int) const"),
        ("V8_STACK_FRAME_GET_SCRIPT_NAME", "v8::StackFrame::GetScriptName() const"),
        ("V8_STRING_UTF8_LENGTH", "v8::String::Utf8Length(v8::Isolate*) const"),
        ("V8_STRING_WRITE_UTF8", "v8::String::WriteUtf8(v8::Isolate*, char*, int, int*, int) const"),
    ];

    let mut bindings = String::new();
    for (rust_name, cpp_sig) in targets {
        if let Some(mangled) = demangled_to_mangled.get(cpp_sig) {
            bindings.push_str(&format!("pub const {}: &[u8] = b\"\\0\";\n", rust_name)); // Placeholder, will fix below
            bindings.push_str(&format!(
                "pub const {}_MANGLED: &[u8] = b\"{}\\0\";\n",
                rust_name, mangled
            ));
        }
    }

    fs::write(dest_path, bindings).expect("Unable to write symbols file");
}
