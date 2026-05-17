const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 1. Build the Astraea Engine
    const cargo_cmd = b.addSystemCommand(&.{ "cargo", "build" });
    if (optimize != .Debug) {
        cargo_cmd.addArg("--release");
    }
    cargo_cmd.setCwd(b.path("engine"));

    // 2. Build the Interceptor Object File
    const obj = b.addObject(.{
        .name = "interceptor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("interceptor/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true, // Force PIC for shared library compatibility
        }),
    });

    // Platform detection
    const is_android = target.result.abi == .android or target.result.abi == .androideabi;

    if (is_android) {
        obj.root_module.addCMacro("_Nullable", "");
        obj.root_module.addCMacro("_Nonnull", "");
        obj.root_module.addCMacro("__BIONIC_COMPLICATED_NULLNESS", "");
        obj.root_module.addCMacro("BIONIC_IOCTL_NO_SIGNEDNESS_OVERLOAD", "");
        obj.root_module.addIncludePath(.{ .cwd_relative = "/data/data/com.termux/files/usr/include" });
        const arch_name = if (target.result.cpu.arch == .aarch64) "aarch64-linux-android" else "arm-linux-androideabi";
        obj.root_module.addIncludePath(.{ .cwd_relative = b.fmt("/data/data/com.termux/files/usr/include/{s}", .{arch_name}) });
    }

    // 3. Link everything using Clang
    const rust_profile = if (optimize == .Debug) "debug" else "release";
    const rust_lib_path = b.path(b.fmt("engine/target/{s}/libengine.a", .{rust_profile}));

    const output_dir = b.getInstallPath(.lib, "");

    const mkdir_cmd = b.addSystemCommand(&.{ "mkdir", "-p", output_dir });

    const link_cmd = b.addSystemCommand(&.{ "clang", "-shared", "-o" });
    const out_path = b.fmt("{s}/libastraea.so", .{output_dir});
    link_cmd.addArg(out_path);
    link_cmd.addArtifactArg(obj);
    link_cmd.addFileArg(rust_lib_path);
    link_cmd.addArg("-luv");

    // Ensure all dependencies are met
    link_cmd.step.dependOn(&cargo_cmd.step);
    link_cmd.step.dependOn(&obj.step);
    link_cmd.step.dependOn(&mkdir_cmd.step);

    // Make the link command the default install step
    b.getInstallStep().dependOn(&link_cmd.step);
}
