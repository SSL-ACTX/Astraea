const std = @import("std");
const common = @import("common.zig");
const c = common.c;

// --- Exec Hooks ---

const execve_fn = *const fn (pathname: [*c]const u8, argv: [*c]const [*c]u8, envp: [*c]const [*c]u8) callconv(.c) c_int;
var real_execve: ?execve_fn = null;

export fn execve(pathname: [*c]const u8, argv: [*c]const [*c]u8, envp: [*c]const [*c]u8) callconv(.c) c_int {
    if (real_execve == null) real_execve = common.getRealSymbol(execve_fn, "execve");

    if (pathname != null) {
        if (common.evaluate_proc_access(pathname) == common.DECISION_DENY) {
            common.__errno().* = common.EACCES;
            return -1;
        }
    }

    return if (real_execve) |func| func(pathname, argv, envp) else -1;
}

const execvp_fn = *const fn (file: [*c]const u8, argv: [*c]const [*c]u8) callconv(.c) c_int;
var real_execvp: ?execvp_fn = null;

export fn execvp(file: [*c]const u8, argv: [*c]const [*c]u8) callconv(.c) c_int {
    if (real_execvp == null) real_execvp = common.getRealSymbol(execvp_fn, "execvp");

    if (file != null) {
        if (common.evaluate_proc_access(file) == common.DECISION_DENY) {
            common.__errno().* = common.EACCES;
            return -1;
        }
    }

    return if (real_execvp) |func| func(file, argv) else -1;
}

const execv_fn = *const fn (pathname: [*c]const u8, argv: [*c]const [*c]u8) callconv(.c) c_int;
var real_execv: ?execv_fn = null;

export fn execv(pathname: [*c]const u8, argv: [*c]const [*c]u8) callconv(.c) c_int {
    if (real_execv == null) real_execv = common.getRealSymbol(execv_fn, "execv");

    if (pathname != null) {
        if (common.evaluate_proc_access(pathname) == common.DECISION_DENY) {
            common.__errno().* = common.EACCES;
            return -1;
        }
    }

    return if (real_execv) |func| func(pathname, argv) else -1;
}

const posix_spawn_fn = *const fn (pid: [*c]c.pid_t, path: [*c]const u8, file_actions: ?*anyopaque, attrp: ?*anyopaque, argv: [*c]const [*c]u8, envp: [*c]const [*c]u8) callconv(.c) c_int;
var real_posix_spawn: ?posix_spawn_fn = null;

export fn posix_spawn(pid: [*c]c.pid_t, path: [*c]const u8, file_actions: ?*anyopaque, attrp: ?*anyopaque, argv: [*c]const [*c]u8, envp: [*c]const [*c]u8) callconv(.c) c_int {
    if (real_posix_spawn == null) real_posix_spawn = common.getRealSymbol(posix_spawn_fn, "posix_spawn");

    if (path != null) {
        if (common.evaluate_proc_access(path) == common.DECISION_DENY) {
            return common.EACCES;
        }
    }

    return if (real_posix_spawn) |func| func(pid, path, file_actions, attrp, argv, envp) else -1;
}

const posix_spawnp_fn = *const fn (pid: [*c]c.pid_t, file: [*c]const u8, file_actions: ?*anyopaque, attrp: ?*anyopaque, argv: [*c]const [*c]u8, envp: [*c]const [*c]u8) callconv(.c) c_int;
var real_posix_spawnp: ?posix_spawnp_fn = null;

export fn posix_spawnp(pid: [*c]c.pid_t, file: [*c]const u8, file_actions: ?*anyopaque, attrp: ?*anyopaque, argv: [*c]const [*c]u8, envp: [*c]const [*c]u8) callconv(.c) c_int {
    if (real_posix_spawnp == null) real_posix_spawnp = common.getRealSymbol(posix_spawnp_fn, "posix_spawnp");

    if (file != null) {
        if (common.evaluate_proc_access(file) == common.DECISION_DENY) {
            return common.EACCES;
        }
    }

    return if (real_posix_spawnp) |func| func(pid, file, file_actions, attrp, argv, envp) else -1;
}

// --- Env Hooks ---

const setenv_fn = *const fn (name: [*c]const u8, value: [*c]const u8, overwrite: c_int) callconv(.c) c_int;
var real_setenv: ?setenv_fn = null;

export fn setenv(name: [*c]const u8, value: [*c]const u8, overwrite: c_int) callconv(.c) c_int {
    if (real_setenv == null) real_setenv = common.getRealSymbol(setenv_fn, "setenv");

    if (name != null) {
        if (common.evaluate_env_access(name) == common.DECISION_DENY) {
            common.__errno().* = common.EACCES;
            return -1;
        }
    }

    return if (real_setenv) |func| func(name, value, overwrite) else -1;
}

const putenv_fn = *const fn (string: [*c]u8) callconv(.c) c_int;
var real_putenv: ?putenv_fn = null;

export fn putenv(string: [*c]u8) callconv(.c) c_int {
    if (real_putenv == null) real_putenv = common.getRealSymbol(putenv_fn, "putenv");

    if (string != null) {
        // Extract key from "KEY=VALUE"
        const span = std.mem.span(string);
        if (std.mem.indexOfScalar(u8, span, '=')) |idx| {
            const key = span[0..idx];
            var key_buf: [256]u8 = undefined;
            if (key.len < key_buf.len) {
                @memcpy(key_buf[0..key.len], key);
                key_buf[key.len] = 0;
                if (common.evaluate_env_access(&key_buf) == common.DECISION_DENY) {
                    common.__errno().* = common.EACCES;
                    return -1;
                }
            }
        }
    }

    return if (real_putenv) |func| func(string) else -1;
}

const sigaction_fn = *const fn (signum: c_int, act: ?*const anyopaque, oldact: ?*anyopaque) callconv(.c) c_int;
var real_sigaction: ?sigaction_fn = null;

export fn sigaction(signum: c_int, act: ?*const anyopaque, oldact: ?*anyopaque) callconv(.c) c_int {
    if (real_sigaction == null) real_sigaction = common.getRealSymbol(sigaction_fn, "sigaction");

    if (signum == 31) { // SIGSYS
        common.log_info("sigaction: blocked attempt to register handler for SIGSYS", .{});
        return if (real_sigaction) |func| func(signum, null, oldact) else 0;
    }

    return if (real_sigaction) |func| func(signum, act, oldact) else -1;
}

const signal_fn = *const fn (signum: c_int, handler: ?*const anyopaque) callconv(.c) ?*anyopaque;
var real_signal: ?signal_fn = null;

export fn signal(signum: c_int, handler: ?*const anyopaque) callconv(.c) ?*anyopaque {
    if (real_signal == null) real_signal = common.getRealSymbol(signal_fn, "signal");

    if (signum == 31) { // SIGSYS
        common.log_info("signal: blocked attempt to register handler for SIGSYS", .{});
        return null;
    }

    return if (real_signal) |func| func(signum, handler) else null;
}
