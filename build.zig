const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Compile the Astraea Engine (Rust Static Library).
    const cargo_cmd = b.addSystemCommand(&.{ "cargo", "build" });
    if (optimize != .Debug) {
        cargo_cmd.addArg("--release");
    }
    cargo_cmd.setCwd(b.path("engine"));

    // Compile the Interceptor Object (Zig C-ABI Layer).
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

    // Final link stage using Clang to produce the shared library.
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

    // Optimization and stripping flags for the final shared library
    if (optimize != .Debug) {
        link_cmd.addArg("-Wl,-s"); // Strip all symbols
        link_cmd.addArg("-Wl,--gc-sections"); // Dead code elimination
        link_cmd.addArg("-Wl,--exclude-libs,ALL"); // Hide statically linked symbols from dynamic table
    }

    // Ensure all dependencies are met
    link_cmd.step.dependOn(&cargo_cmd.step);
    link_cmd.step.dependOn(&obj.step);
    link_cmd.step.dependOn(&mkdir_cmd.step);

    // Make the link command the default install step
    b.getInstallStep().dependOn(&link_cmd.step);
}
