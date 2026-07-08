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

const unlink_fn = *const fn (pathname: [*c]const u8) callconv(.c) c_int;
var real_unlink: ?unlink_fn = null;

export fn unlink(pathname: [*c]const u8) callconv(.c) c_int {
    if (real_unlink == null) real_unlink = common.getRealSymbol(unlink_fn, "unlink");

    if (pathname != null) {
        const res = evaluate(pathname);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) {
            const fd = if (real_unlink) |func| func(res.path) else -1;
            common.free_string(@constCast(res.path));
            return fd;
        }
    }

    return if (real_unlink) |func| func(pathname) else -1;
}

const unlinkat_fn = *const fn (dirfd: c_int, pathname: [*c]const u8, flags: c_int) callconv(.c) c_int;
var real_unlinkat: ?unlinkat_fn = null;

export fn unlinkat(dirfd: c_int, pathname: [*c]const u8, flags: c_int) callconv(.c) c_int {
    if (real_unlinkat == null) real_unlinkat = common.getRealSymbol(unlinkat_fn, "unlinkat");

    if (pathname != null) {
        const res = evaluate(pathname);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) {
            const fd = if (real_unlinkat) |func| func(dirfd, res.path, flags) else -1;
            common.free_string(@constCast(res.path));
            return fd;
        }
    }

    return if (real_unlinkat) |func| func(dirfd, pathname, flags) else -1;
}

const creat_fn = *const fn (pathname: [*c]const u8, mode: c.mode_t) callconv(.c) c_int;
var real_creat: ?creat_fn = null;

export fn creat(pathname: [*c]const u8, mode: c.mode_t) callconv(.c) c_int {
    if (real_creat == null) real_creat = common.getRealSymbol(creat_fn, "creat");

    if (pathname != null) {
        const res = evaluate(pathname);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) {
            const fd = if (real_creat) |func| func(res.path, mode) else -1;
            common.free_string(@constCast(res.path));
            return fd;
        }
    }

    return if (real_creat) |func| func(pathname, mode) else -1;
}

const rename_fn = *const fn (oldpath: [*c]const u8, newpath: [*c]const u8) callconv(.c) c_int;
var real_rename: ?rename_fn = null;

export fn rename(oldpath: [*c]const u8, newpath: [*c]const u8) callconv(.c) c_int {
    if (real_rename == null) real_rename = common.getRealSymbol(rename_fn, "rename");

    if (oldpath != null) {
        const res = evaluate(oldpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) {
            common.free_string(@constCast(res.path));
        }
    }
    if (newpath != null) {
        const res = evaluate(newpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) {
            common.free_string(@constCast(res.path));
        }
    }

    return if (real_rename) |func| func(oldpath, newpath) else -1;
}

const renameat_fn = *const fn (olddirfd: c_int, oldpath: [*c]const u8, newdirfd: c_int, newpath: [*c]const u8) callconv(.c) c_int;
var real_renameat: ?renameat_fn = null;

export fn renameat(olddirfd: c_int, oldpath: [*c]const u8, newdirfd: c_int, newpath: [*c]const u8) callconv(.c) c_int {
    if (real_renameat == null) real_renameat = common.getRealSymbol(renameat_fn, "renameat");

    if (oldpath != null) {
        const res = evaluate(oldpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) {
            common.free_string(@constCast(res.path));
        }
    }
    if (newpath != null) {
        const res = evaluate(newpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) {
            common.free_string(@constCast(res.path));
        }
    }

    return if (real_renameat) |func| func(olddirfd, oldpath, newdirfd, newpath) else -1;
}

const uv_fs_unlink_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_unlink: ?uv_fs_unlink_fn = null;

export fn uv_fs_unlink(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_unlink == null) real_uv_fs_unlink = common.getRealSymbol(uv_fs_unlink_fn, "uv_fs_unlink");

    if (path != null) {
        const res = evaluate(path);
        if (!res.allowed) return -13; // -EACCES in libuv
        if (res.spoofed) {
            const fd = if (real_uv_fs_unlink) |func| func(loop, req, res.path, cb) else -13;
            common.free_string(@constCast(res.path));
            return fd;
        }
    }

    return if (real_uv_fs_unlink) |func| func(loop, req, path, cb) else -13;
}

const uv_fs_mkdir_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, mode: c_int, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_mkdir: ?uv_fs_mkdir_fn = null;

export fn uv_fs_mkdir(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, mode: c_int, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_mkdir == null) real_uv_fs_mkdir = common.getRealSymbol(uv_fs_mkdir_fn, "uv_fs_mkdir");

    if (path != null) {
        const res = evaluate(path);
        if (!res.allowed) return -13; // -EACCES in libuv
        if (res.spoofed) {
            const fd = if (real_uv_fs_mkdir) |func| func(loop, req, res.path, mode, cb) else -13;
            common.free_string(@constCast(res.path));
            return fd;
        }
    }

    return if (real_uv_fs_mkdir) |func| func(loop, req, path, mode, cb) else -13;
}

const uv_fs_rmdir_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_rmdir: ?uv_fs_rmdir_fn = null;

export fn uv_fs_rmdir(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_rmdir == null) real_uv_fs_rmdir = common.getRealSymbol(uv_fs_rmdir_fn, "uv_fs_rmdir");

    if (path != null) {
        const res = evaluate(path);
        if (!res.allowed) return -13; // -EACCES in libuv
        if (res.spoofed) {
            const fd = if (real_uv_fs_rmdir) |func| func(loop, req, res.path, cb) else -13;
            common.free_string(@constCast(res.path));
            return fd;
        }
    }

    return if (real_uv_fs_rmdir) |func| func(loop, req, path, cb) else -13;
}

const uv_fs_rename_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, new_path: [*c]const u8, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_rename: ?uv_fs_rename_fn = null;

export fn uv_fs_rename(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, new_path: [*c]const u8, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_rename == null) real_uv_fs_rename = common.getRealSymbol(uv_fs_rename_fn, "uv_fs_rename");

    if (path != null) {
        const res = evaluate(path);
        if (!res.allowed) return -13;
        if (res.spoofed) common.free_string(@constCast(res.path));
    }
    if (new_path != null) {
        const res = evaluate(new_path);
        if (!res.allowed) return -13;
        if (res.spoofed) common.free_string(@constCast(res.path));
    }

    return if (real_uv_fs_rename) |func| func(loop, req, path, new_path, cb) else -13;
}

const uv_fs_chmod_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, mode: c_int, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_chmod: ?uv_fs_chmod_fn = null;

export fn uv_fs_chmod(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, mode: c_int, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_chmod == null) real_uv_fs_chmod = common.getRealSymbol(uv_fs_chmod_fn, "uv_fs_chmod");

    if (path != null) {
        const res = evaluate(path);
        if (!res.allowed) return -13;
        if (res.spoofed) {
            const fd = if (real_uv_fs_chmod) |func| func(loop, req, res.path, mode, cb) else -13;
            common.free_string(@constCast(res.path));
            return fd;
        }
    }

    return if (real_uv_fs_chmod) |func| func(loop, req, path, mode, cb) else -13;
}

const uv_fs_chown_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, uid: c_int, gid: c_int, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_chown: ?uv_fs_chown_fn = null;

export fn uv_fs_chown(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, uid: c_int, gid: c_int, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_chown == null) real_uv_fs_chown = common.getRealSymbol(uv_fs_chown_fn, "uv_fs_chown");

    if (path != null) {
        const res = evaluate(path);
        if (!res.allowed) return -13;
        if (res.spoofed) {
            const fd = if (real_uv_fs_chown) |func| func(loop, req, res.path, uid, gid, cb) else -13;
            common.free_string(@constCast(res.path));
            return fd;
        }
    }

    return if (real_uv_fs_chown) |func| func(loop, req, path, uid, gid, cb) else -13;
}

const symlink_fn = *const fn (target: [*c]const u8, linkpath: [*c]const u8) callconv(.c) c_int;
var real_symlink: ?symlink_fn = null;

export fn symlink(target: [*c]const u8, linkpath: [*c]const u8) callconv(.c) c_int {
    if (real_symlink == null) real_symlink = common.getRealSymbol(symlink_fn, "symlink");

    if (target != null) {
        const res = evaluate(target);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) common.free_string(@constCast(res.path));
    }
    if (linkpath != null) {
        const res = evaluate(linkpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) common.free_string(@constCast(res.path));
    }

    return if (real_symlink) |func| func(target, linkpath) else -1;
}

const symlinkat_fn = *const fn (target: [*c]const u8, newdirfd: c_int, linkpath: [*c]const u8) callconv(.c) c_int;
var real_symlinkat: ?symlinkat_fn = null;

export fn symlinkat(target: [*c]const u8, newdirfd: c_int, linkpath: [*c]const u8) callconv(.c) c_int {
    if (real_symlinkat == null) real_symlinkat = common.getRealSymbol(symlinkat_fn, "symlinkat");

    if (target != null) {
        const res = evaluate(target);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) common.free_string(@constCast(res.path));
    }
    if (linkpath != null) {
        const res = evaluate(linkpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) common.free_string(@constCast(res.path));
    }

    return if (real_symlinkat) |func| func(target, newdirfd, linkpath) else -1;
}

const link_fn = *const fn (oldpath: [*c]const u8, newpath: [*c]const u8) callconv(.c) c_int;
var real_link: ?link_fn = null;

export fn link(oldpath: [*c]const u8, newpath: [*c]const u8) callconv(.c) c_int {
    if (real_link == null) real_link = common.getRealSymbol(link_fn, "link");

    if (oldpath != null) {
        const res = evaluate(oldpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) common.free_string(@constCast(res.path));
    }
    if (newpath != null) {
        const res = evaluate(newpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) common.free_string(@constCast(res.path));
    }

    return if (real_link) |func| func(oldpath, newpath) else -1;
}

const linkat_fn = *const fn (olddirfd: c_int, oldpath: [*c]const u8, newdirfd: c_int, newpath: [*c]const u8, flags: c_int) callconv(.c) c_int;
var real_linkat: ?linkat_fn = null;

export fn linkat(olddirfd: c_int, oldpath: [*c]const u8, newdirfd: c_int, newpath: [*c]const u8, flags: c_int) callconv(.c) c_int {
    if (real_linkat == null) real_linkat = common.getRealSymbol(linkat_fn, "linkat");

    if (oldpath != null) {
        const res = evaluate(oldpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) common.free_string(@constCast(res.path));
    }
    if (newpath != null) {
        const res = evaluate(newpath);
        if (!res.allowed) {
            common.__errno().* = common.EACCES;
            return -1;
        }
        if (res.spoofed) common.free_string(@constCast(res.path));
    }

    return if (real_linkat) |func| func(olddirfd, oldpath, newdirfd, newpath, flags) else -1;
}

const uv_fs_symlink_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, new_path: [*c]const u8, flags: c_int, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_symlink: ?uv_fs_symlink_fn = null;

export fn uv_fs_symlink(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, new_path: [*c]const u8, flags: c_int, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_symlink == null) real_uv_fs_symlink = common.getRealSymbol(uv_fs_symlink_fn, "uv_fs_symlink");

    if (path != null) {
        const res = evaluate(path);
        if (!res.allowed) return -13;
        if (res.spoofed) common.free_string(@constCast(res.path));
    }
    if (new_path != null) {
        const res = evaluate(new_path);
        if (!res.allowed) return -13;
        if (res.spoofed) common.free_string(@constCast(res.path));
    }

    return if (real_uv_fs_symlink) |func| func(loop, req, path, new_path, flags, cb) else -13;
}

const uv_fs_link_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, new_path: [*c]const u8, cb: c.uv_fs_cb) callconv(.c) c_int;
var real_uv_fs_link: ?uv_fs_link_fn = null;

export fn uv_fs_link(loop: ?*c.uv_loop_t, req: ?*c.uv_fs_t, path: [*c]const u8, new_path: [*c]const u8, cb: c.uv_fs_cb) callconv(.c) c_int {
    if (real_uv_fs_link == null) real_uv_fs_link = common.getRealSymbol(uv_fs_link_fn, "uv_fs_link");

    if (path != null) {
        const res = evaluate(path);
        if (!res.allowed) return -13;
        if (res.spoofed) common.free_string(@constCast(res.path));
    }
    if (new_path != null) {
        const res = evaluate(new_path);
        if (!res.allowed) return -13;
        if (res.spoofed) common.free_string(@constCast(res.path));
    }

    return if (real_uv_fs_link) |func| func(loop, req, path, new_path, cb) else -13;
}
