const std = @import("std");

pub const c = @cImport({
    @cInclude("uv.h");
    @cInclude("dlfcn.h");
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/socket.h");
    @cInclude("netdb.h");
    @cInclude("arpa/inet.h");
    @cInclude("netinet/in.h");
});

pub const EvaluationResult = extern struct {
    decision: i32,
    redirect_path: [*c]u8,
};

pub extern fn evaluate_fs_access(path: [*c]const u8, async_context: [*c]const u8) EvaluationResult;
pub extern fn evaluate_dlopen(path: [*c]const u8) i32;
pub extern fn evaluate_net_access(host: [*c]const u8, port: u16) i32;
pub extern fn register_dns_result(domain: [*c]const u8, ip: [*c]const u8) void;
pub extern fn init_engine() void;
pub extern fn free_string(ptr: [*c]u8) void;
pub extern fn astraea_log(level: i32, message: [*c]const u8) void;

pub const LOG_ERROR: i32 = 0;
pub const LOG_WARN: i32 = 1;
pub const LOG_INFO: i32 = 2;
pub const LOG_DEBUG: i32 = 3;

pub fn log_info(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    astraea_log(LOG_INFO, msg.ptr);
}

pub fn log_warn(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    astraea_log(LOG_WARN, msg.ptr);
}

pub const RTLD_NEXT = @as(?*anyopaque, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))));
pub const EACCES = 13;
pub const DECISION_DENY = 0;
pub const DECISION_ALLOW = 1;
pub const DECISION_SPOOF = 2;

pub extern fn __errno() *c_int;

pub fn getRealSymbol(comptime T: type, name: [:0]const u8) ?T {
    const handle = c.dlsym(RTLD_NEXT, name);
    return if (handle == null) null else @ptrCast(@alignCast(handle));
}
