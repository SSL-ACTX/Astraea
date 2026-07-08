const std = @import("std");
const common = @import("common.zig");
const c = common.c;

fn evaluate(pathname: [*c]const u8) struct { path: [*c]const u8, allowed: bool, spoofed: bool } {
    if (pathname == null) return .{ .path = pathname, .allowed = true, .spoofed = false };

    // We pass null for async_context to trigger the Sticky Heuristic in Rust
    const res = common.evaluate_fs_access(pathname, null);
    if (res.decision == common.DECISION_ALLOW) {
        return .{ .path = pathname, .allowed = true, .spoofed = false };
    } else if (res.decision == common.DECISION_SPOOF) {
        return .{ .path = res.redirect_path, .allowed = true, .spoofed = true };
    }
    return .{ .path = pathname, .allowed = false, .spoofed = false };
}

const openat_fn = *const fn (dirfd: c_int, pathname: [*c]const u8, flags: c_int, mode: c.mode_t) callconv(.c) c_int;
var real_openat: ?openat_fn = null;

export fn openat(dirfd: c_int, pathname: [*c]const u8, flags: c_int, mode: c.mode_t) callconv(.c) c_int {
    if (real_openat == null) real_openat = common.getRealSymbol(openat_fn, "openat");
    const res = evaluate(pathname);
    if (!res.allowed) {
        common.__errno().* = common.EACCES;
        return -1;
    }
    const fd = if (real_openat) |func| func(dirfd, res.path, flags, mode) else -1;
    if (res.spoofed) common.free_string(@constCast(res.path));
    return fd;
}

const open_fn = *const fn (pathname: [*c]const u8, flags: c_int, mode: c.mode_t) callconv(.c) c_int;
var real_open: ?open_fn = null;

export fn open(pathname: [*c]const u8, flags: c_int, mode: c.mode_t) callconv(.c) c_int {
    if (real_open == null) real_open = common.getRealSymbol(open_fn, "open");
    const res = evaluate(pathname);
    if (!res.allowed) {
        common.__errno().* = common.EACCES;
        return -1;
    }
    const fd = if (real_open) |func| func(res.path, flags, mode) else -1;
    if (res.spoofed) common.free_string(@constCast(res.path));
    return fd;
}

const uv_fs_open_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, flags: c_int, mode: c_int, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_open: ?uv_fs_open_fn = null;

export fn uv_fs_open(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, flags: c_int, mode: c_int, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_open == null) real_uv_fs_open = common.getRealSymbol(uv_fs_open_fn, "uv_fs_open");

    // Evaluate immediately on the main thread for synchronous check
    const res = evaluate(path);
    if (!res.allowed) return -1;

    // We pass the evaluated/spoofed path to the real uv_fs_open, which copies it internally
    const fd = if (real_uv_fs_open) |func| func(loop, req, res.path, flags, mode, cb) else -1;

    if (res.spoofed) common.free_string(@constCast(res.path));
    return fd;
}
