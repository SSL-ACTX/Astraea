const std = @import("std");
const common = @import("common.zig");

// Force inclusion of modules to ensure their exports are included in the final binary
comptime {
    _ = @import("fs.zig");
    _ = @import("net.zig");
    _ = @import("dlfcn.zig");
    _ = @import("proc.zig");
}

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    _ = error_return_trace;
    std.debug.print("Astraea Critical Panic: {s}\n", .{msg});
    std.process.exit(1);
}

export fn astraea_init() callconv(.c) void {
    common.init_engine();
    common.log_info("Astraea interceptor attached and initialized.", .{});
}

export const init_array: [1]*const fn () callconv(.c) void linksection(".init_array") = .{astraea_init};
