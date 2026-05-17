const std = @import("std");
const c = @cImport({
    @cInclude("uv.h");
    @cInclude("dlfcn.h");
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
});

const EvaluationResult = extern struct {
    decision: i32,
    redirect_path: [*c]u8,
};

extern fn evaluate_fs_access(path: [*c]const u8, async_context: [*c]const u8) EvaluationResult;
extern fn init_engine() void;
extern fn free_string(ptr: [*c]u8) void;
extern fn astraea_log(level: i32, message: [*c]const u8) void;

const LOG_ERROR: i32 = 0;
const LOG_WARN: i32 = 1;
const LOG_INFO: i32 = 2;
const LOG_DEBUG: i32 = 3;

fn log_info(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    astraea_log(LOG_INFO, msg.ptr);
}

fn log_warn(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    astraea_log(LOG_WARN, msg.ptr);
}

const RTLD_NEXT = @as(?*anyopaque, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))));
const EACCES = 13;
const DECISION_DENY = 0;
const DECISION_ALLOW = 1;
const DECISION_SPOOF = 2;

extern fn __errno() *c_int;

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    _ = error_return_trace;
    std.debug.print("Astraea Critical Panic: {s}\n", .{msg});
    std.process.exit(1);
}

export fn astraea_init() callconv(.c) void {
    init_engine();
    log_info("Astraea interceptor attached and initialized.", .{});
}

export const init_array: [1]*const fn () callconv(.c) void linksection(".init_array") = .{astraea_init};

fn getRealSymbol(comptime T: type, name: [:0]const u8) ?T {
    const handle = c.dlsym(RTLD_NEXT, name);
    return if (handle == null) null else @ptrCast(@alignCast(handle));
}

fn evaluate(pathname: [*c]const u8) struct { path: [*c]const u8, allowed: bool, spoofed: bool } {
    if (pathname == null) return .{ .path = pathname, .allowed = true, .spoofed = false };
    
    // We pass null for async_context to trigger the Sticky Heuristic in Rust
    const res = evaluate_fs_access(pathname, null);
    if (res.decision == DECISION_ALLOW) {
        return .{ .path = pathname, .allowed = true, .spoofed = false };
    } else if (res.decision == DECISION_SPOOF) {
        return .{ .path = res.redirect_path, .allowed = true, .spoofed = true };
    }
    return .{ .path = pathname, .allowed = false, .spoofed = false };
}

// --- Hooks ---

const openat_fn = *const fn (dirfd: c_int, pathname: [*c]const u8, flags: c_int, mode: c.mode_t) callconv(.c) c_int;
var real_openat: ?openat_fn = null;

export fn openat(dirfd: c_int, pathname: [*c]const u8, flags: c_int, mode: c.mode_t) callconv(.c) c_int {
    if (real_openat == null) real_openat = getRealSymbol(openat_fn, "openat");
    const res = evaluate(pathname);
    if (!res.allowed) {
        __errno().* = EACCES;
        return -1;
    }
    const fd = if (real_openat) |func| func(dirfd, res.path, flags, mode) else -1;
    if (res.spoofed) free_string(@constCast(res.path));
    return fd;
}

const open_fn = *const fn (pathname: [*c]const u8, flags: c_int, mode: c.mode_t) callconv(.c) c_int;
var real_open: ?open_fn = null;

export fn open(pathname: [*c]const u8, flags: c_int, mode: c.mode_t) callconv(.c) c_int {
    if (real_open == null) real_open = getRealSymbol(open_fn, "open");
    const res = evaluate(pathname);
    if (!res.allowed) {
        __errno().* = EACCES;
        return -1;
    }
    const fd = if (real_open) |func| func(res.path, flags, mode) else -1;
    if (res.spoofed) free_string(@constCast(res.path));
    return fd;
}

const uv_fs_open_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, flags: c_int, mode: c_int, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_open: ?uv_fs_open_fn = null;

export fn uv_fs_open(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, flags: c_int, mode: c_int, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_open == null) real_uv_fs_open = getRealSymbol(uv_fs_open_fn, "uv_fs_open");
    
    // Evaluate immediately on the main thread for synchronous check
    const res = evaluate(path);
    if (!res.allowed) return -1;
    
    // We must pass the original path to the real uv_fs_open as it will be used asynchronously
    const fd = if (real_uv_fs_open) |func| func(loop, req, path, flags, mode, cb) else -1;
    
    if (res.spoofed) free_string(@constCast(res.path));
    return fd;
}
