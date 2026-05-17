const std = @import("std");
const common = @import("common.zig");
const c = common.c;

const dlopen_fn = *const fn (filename: [*c]const u8, flag: c_int) callconv(.c) ?*anyopaque;
var real_dlopen: ?dlopen_fn = null;

export fn dlopen(filename: [*c]const u8, flag: c_int) callconv(.c) ?*anyopaque {
    if (real_dlopen == null) real_dlopen = common.getRealSymbol(dlopen_fn, "dlopen");

    if (filename != null) {
        if (common.evaluate_dlopen(filename) == common.DECISION_DENY) {
            // Force dlerror to be populated so the caller (Node/OpenSSL) doesn't crash
            _ = if (real_dlopen) |func| func("/dev/null/astraea_denied", flag) else null;
            return null;
        }
    }

    return if (real_dlopen) |func| func(filename, flag) else null;
}

// Android-specific dlopen
const android_dlopen_ext_fn = *const fn (filename: [*c]const u8, flag: c_int, extinfo: ?*anyopaque) callconv(.c) ?*anyopaque;
var real_android_dlopen_ext: ?android_dlopen_ext_fn = null;

export fn android_dlopen_ext(filename: [*c]const u8, flag: c_int, extinfo: ?*anyopaque) callconv(.c) ?*anyopaque {
    if (real_android_dlopen_ext == null) real_android_dlopen_ext = common.getRealSymbol(android_dlopen_ext_fn, "android_dlopen_ext");

    if (filename != null) {
        if (common.evaluate_dlopen(filename) == common.DECISION_DENY) {
            // Force dlerror to be populated
            _ = if (real_android_dlopen_ext) |func| func("/dev/null/astraea_denied", flag, extinfo) else null;
            return null;
        }
    }

    return if (real_android_dlopen_ext) |func| func(filename, flag, extinfo) else null;
}
