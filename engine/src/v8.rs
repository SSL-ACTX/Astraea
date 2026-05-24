#![allow(dead_code)]
use libc::{c_char, c_int, c_void};
use once_cell::sync::Lazy;

include!(concat!(env!("OUT_DIR"), "/v8_symbols.rs"));

type IsolateTryGetCurrentFn = unsafe extern "C" fn() -> *mut c_void;
type HandleScopeCtorFn = unsafe extern "C" fn(ptr: *mut c_void, isolate: *mut c_void);
type HandleScopeDtorFn = unsafe extern "C" fn(ptr: *mut c_void);
type StackTraceCurrentFn =
    unsafe extern "C" fn(isolate: *mut c_void, frame_limit: c_int, options: c_int) -> *mut c_void;
type StackTraceGetFrameCountFn = unsafe extern "C" fn(trace: *mut c_void) -> c_int;
type StackTraceGetFrameFn =
    unsafe extern "C" fn(trace: *mut c_void, isolate: *mut c_void, index: u32) -> *mut c_void;
type StackFrameGetScriptNameFn = unsafe extern "C" fn(frame: *mut c_void) -> *mut c_void;
type StringUtf8LengthFn = unsafe extern "C" fn(string: *mut c_void, isolate: *mut c_void) -> usize;
type StringWriteUtf8Fn = unsafe extern "C" fn(
    string: *mut c_void,
    isolate: *mut c_void,
    buffer: *mut c_char,
    length: c_int,
    nchars_sentinel: *mut c_int,
    options: c_int,
) -> c_int;

pub struct V8Bindings {
    pub isolate_try_get_current: IsolateTryGetCurrentFn,
    pub handle_scope_ctor: HandleScopeCtorFn,
    pub handle_scope_dtor: HandleScopeDtorFn,
    pub stack_trace_current: StackTraceCurrentFn,
    pub stack_trace_get_frame_count: StackTraceGetFrameCountFn,
    pub stack_trace_get_frame: StackTraceGetFrameFn,
    pub stack_frame_get_script_name: StackFrameGetScriptNameFn,
    pub string_utf8_length: StringUtf8LengthFn,
    pub string_write_utf8: StringWriteUtf8Fn,
}

pub static V8: Lazy<Option<V8Bindings>> = Lazy::new(|| unsafe {
    let handle = libc::RTLD_DEFAULT;

    let isolate_try_get_current: Option<IsolateTryGetCurrentFn> = std::mem::transmute(libc::dlsym(
        handle,
        V8_ISOLATE_TRY_GET_CURRENT_MANGLED.as_ptr() as *const c_char,
    ));
    let handle_scope_ctor: Option<HandleScopeCtorFn> = std::mem::transmute(libc::dlsym(
        handle,
        V8_HANDLE_SCOPE_CTOR_MANGLED.as_ptr() as *const c_char,
    ));
    let handle_scope_dtor: Option<HandleScopeDtorFn> = std::mem::transmute(libc::dlsym(
        handle,
        V8_HANDLE_SCOPE_DTOR_MANGLED.as_ptr() as *const c_char,
    ));
    let stack_trace_current: Option<StackTraceCurrentFn> = std::mem::transmute(libc::dlsym(
        handle,
        V8_STACK_TRACE_CURRENT_MANGLED.as_ptr() as *const c_char,
    ));
    let stack_trace_get_frame_count: Option<StackTraceGetFrameCountFn> =
        std::mem::transmute(libc::dlsym(
            handle,
            V8_STACK_TRACE_GET_FRAME_COUNT_MANGLED.as_ptr() as *const c_char,
        ));
    let stack_trace_get_frame: Option<StackTraceGetFrameFn> = std::mem::transmute(libc::dlsym(
        handle,
        V8_STACK_TRACE_GET_FRAME_MANGLED.as_ptr() as *const c_char,
    ));
    let stack_frame_get_script_name: Option<StackFrameGetScriptNameFn> =
        std::mem::transmute(libc::dlsym(
            handle,
            V8_STACK_FRAME_GET_SCRIPT_NAME_MANGLED.as_ptr() as *const c_char,
        ));
    let string_utf8_length: Option<StringUtf8LengthFn> = std::mem::transmute(libc::dlsym(
        handle,
        V8_STRING_UTF8_LENGTH_MANGLED.as_ptr() as *const c_char,
    ));
    let string_write_utf8: Option<StringWriteUtf8Fn> = std::mem::transmute(libc::dlsym(
        handle,
        V8_STRING_WRITE_UTF8_MANGLED.as_ptr() as *const c_char,
    ));

    if let (
        Some(isolate_try_get_current),
        Some(handle_scope_ctor),
        Some(handle_scope_dtor),
        Some(stack_trace_current),
        Some(stack_trace_get_frame_count),
        Some(stack_trace_get_frame),
        Some(stack_frame_get_script_name),
        Some(string_utf8_length),
        Some(string_write_utf8),
    ) = (
        isolate_try_get_current,
        handle_scope_ctor,
        handle_scope_dtor,
        stack_trace_current,
        stack_trace_get_frame_count,
        stack_trace_get_frame,
        stack_frame_get_script_name,
        string_utf8_length,
        string_write_utf8,
    ) {
        Some(V8Bindings {
            isolate_try_get_current,
            handle_scope_ctor,
            handle_scope_dtor,
            stack_trace_current,
            stack_trace_get_frame_count,
            stack_trace_get_frame,
            stack_frame_get_script_name,
            string_utf8_length,
            string_write_utf8,
        })
    } else {
        None
    }
});
