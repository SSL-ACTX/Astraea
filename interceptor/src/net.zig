const std = @import("std");
const common = @import("common.zig");
const c = common.c;

extern fn getenv(name: [*c]const u8) [*c]const u8;


const socket_fn = *const fn (domain: c_int, type_: c_int, protocol: c_int) callconv(.c) c_int;
var real_socket: ?socket_fn = null;

export fn socket(domain: c_int, type_: c_int, protocol: c_int) callconv(.c) c_int {
    if (real_socket == null) real_socket = common.getRealSymbol(socket_fn, "socket");

    if (type_ == c.SOCK_RAW) {
        common.log_warn("DENY SOCK_RAW creation", .{});
        common.__errno().* = common.EACCES; // EACCES
        return -1;
    }

    return if (real_socket) |func| func(domain, type_, protocol) else -1;
}

const bind_fn = *const fn (sockfd: c_int, addr: *const c.sockaddr, addrlen: c.socklen_t) callconv(.c) c_int;
var real_bind: ?bind_fn = null;

export fn bind(sockfd: c_int, addr: *const c.sockaddr, addrlen: c.socklen_t) callconv(.c) c_int {
    if (real_bind == null) real_bind = common.getRealSymbol(bind_fn, "bind");

    var ip_buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
    var port: u16 = 0;

    if (addr.sa_family == c.AF_INET) {
        const addr_in: *const c.sockaddr_in = @ptrCast(@alignCast(addr));
        _ = c.inet_ntop(c.AF_INET, &addr_in.sin_addr, &ip_buf, c.INET_ADDRSTRLEN);
        port = std.mem.bigToNative(u16, addr_in.sin_port);
    } else if (addr.sa_family == c.AF_INET6) {
        const addr_in6: *const c.sockaddr_in6 = @ptrCast(@alignCast(addr));
        _ = c.inet_ntop(c.AF_INET6, &addr_in6.sin6_addr, &ip_buf, c.INET6_ADDRSTRLEN);
        port = std.mem.bigToNative(u16, addr_in6.sin6_port);
    } else if (addr.sa_family == c.AF_UNIX) {
        const addr_un: *const c.sockaddr_un = @ptrCast(@alignCast(addr));
        const path_ptr = &addr_un.sun_path;
        const socket_path = std.mem.sliceTo(@as([*c]const u8, @ptrCast(path_ptr)), 0);
        var is_telemetry = false;
        const tel_path_c = getenv("ASTRAEA_TELEMETRY");
        if (tel_path_c != null) {
            const tel_path = std.mem.span(tel_path_c);
            if (std.mem.eql(u8, socket_path, tel_path)) {
                is_telemetry = true;
            }
        }
        if (!is_telemetry) {
            const res = common.evaluate_fs_access(path_ptr, null);
            if (res.decision == common.DECISION_DENY) {
                common.__errno().* = 13; // EACCES
                return -1;
            }
        }
    }

    const ip_slice = std.mem.sliceTo(&ip_buf, 0);

    if (port != 0) {
        // We pass 1 for action (Bind), 0 for protocol (Any)
        if (common.evaluate_net_access(ip_slice.ptr, port, 1, 0) == common.DECISION_DENY) {
            common.__errno().* = 13; // EACCES
            return -1;
        }
    }

    return if (real_bind) |func| func(sockfd, addr, addrlen) else -1;
}

const getaddrinfo_fn = *const fn (node: [*c]const u8, service: [*c]const u8, hints: ?*const c.addrinfo, res: [*c][*c]c.addrinfo) callconv(.c) c_int;
var real_getaddrinfo: ?getaddrinfo_fn = null;

export fn getaddrinfo(node: [*c]const u8, service: [*c]const u8, hints: ?*const c.addrinfo, res: [*c][*c]c.addrinfo) callconv(.c) c_int {
    if (real_getaddrinfo == null) real_getaddrinfo = common.getRealSymbol(getaddrinfo_fn, "getaddrinfo");

    if (node != null) {
        common.log_info("HOOK getaddrinfo called for node: {s}", .{std.mem.span(node)});
        var port: u16 = 0;
        if (service != null) {
            const service_span = std.mem.span(service);
            port = std.fmt.parseInt(u16, service_span, 10) catch 0;
        }
        if (common.evaluate_net_access(node, port, 0, 0) == common.DECISION_DENY) {
            return c.EAI_NONAME;
        }
    }

    const ret = if (real_getaddrinfo) |func| func(node, service, hints, res) else c.EAI_SYSTEM;

    // If resolution was successful, populate the DNS cache in Rust
    if (ret == 0 and node != null and res != null) {
        var curr = res.*;
        while (curr != null) : (curr = curr.*.ai_next) {
            var ip_buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
            if (curr.*.ai_family == c.AF_INET) {
                const addr_in: *const c.sockaddr_in = @ptrCast(@alignCast(curr.*.ai_addr));
                _ = c.inet_ntop(c.AF_INET, &addr_in.sin_addr, &ip_buf, c.INET_ADDRSTRLEN);
                const ip_slice = std.mem.sliceTo(&ip_buf, 0);
                common.log_info("DNS RESOLVED: {s} -> {s}", .{ node, ip_slice });
                common.register_dns_result(node, &ip_buf, 60);
            } else if (curr.*.ai_family == c.AF_INET6) {
                const addr_in6: *const c.sockaddr_in6 = @ptrCast(@alignCast(curr.*.ai_addr));
                _ = c.inet_ntop(c.AF_INET6, &addr_in6.sin6_addr, &ip_buf, c.INET6_ADDRSTRLEN);
                const ip_slice = std.mem.sliceTo(&ip_buf, 0);
                common.log_info("DNS RESOLVED: {s} -> {s}", .{ node, ip_slice });
                common.register_dns_result(node, &ip_buf, 60);
            }
        }
    }

    return ret;
}

const android_getaddrinfofornet_fn = *const fn (node: [*c]const u8, service: [*c]const u8, hints: ?*const c.addrinfo, netid: u32, mark: u32, res: [*c][*c]c.addrinfo) callconv(.c) c_int;
var real_android_getaddrinfofornet: ?android_getaddrinfofornet_fn = null;

export fn android_getaddrinfofornet(node: [*c]const u8, service: [*c]const u8, hints: ?*const c.addrinfo, netid: u32, mark: u32, res: [*c][*c]c.addrinfo) callconv(.c) c_int {
    if (real_android_getaddrinfofornet == null) real_android_getaddrinfofornet = common.getRealSymbol(android_getaddrinfofornet_fn, "android_getaddrinfofornet");

    if (node != null) {
        if (common.evaluate_net_access(node, 0, 0, 0) == common.DECISION_DENY) {
            return c.EAI_NONAME;
        }
    }

    const ret = if (real_android_getaddrinfofornet) |func| func(node, service, hints, netid, mark, res) else c.EAI_SYSTEM;

    if (ret == 0 and node != null and res != null) {
        var curr = res.*;
        while (curr != null) : (curr = curr.*.ai_next) {
            var ip_buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
            if (curr.*.ai_family == c.AF_INET) {
                const addr_in: *const c.sockaddr_in = @ptrCast(@alignCast(curr.*.ai_addr));
                _ = c.inet_ntop(c.AF_INET, &addr_in.sin_addr, &ip_buf, c.INET_ADDRSTRLEN);
                common.register_dns_result(node, &ip_buf, 60);
            } else if (curr.*.ai_family == c.AF_INET6) {
                const addr_in6: *const c.sockaddr_in6 = @ptrCast(@alignCast(curr.*.ai_addr));
                _ = c.inet_ntop(c.AF_INET6, &addr_in6.sin6_addr, &ip_buf, c.INET6_ADDRSTRLEN);
                common.register_dns_result(node, &ip_buf, 60);
            }
        }
    }

    return ret;
}

const uv_getaddrinfo_fn = *const fn (loop: ?*c.uv_loop_t, req: ?*c.uv_getaddrinfo_t, cb: c.uv_getaddrinfo_cb, node: [*c]const u8, service: [*c]const u8, hints: ?*const c.addrinfo) callconv(.c) c_int;
var real_uv_getaddrinfo: ?uv_getaddrinfo_fn = null;

export fn uv_getaddrinfo(loop: ?*c.uv_loop_t, req: ?*c.uv_getaddrinfo_t, cb: c.uv_getaddrinfo_cb, node: [*c]const u8, service: [*c]const u8, hints: ?*const c.addrinfo) callconv(.c) c_int {
    if (real_uv_getaddrinfo == null) real_uv_getaddrinfo = common.getRealSymbol(uv_getaddrinfo_fn, "uv_getaddrinfo");

    if (node != null) {
        common.log_info("HOOK uv_getaddrinfo called for node: {s}", .{std.mem.span(node)});
        var port: u16 = 0;
        if (service != null) {
            const service_span = std.mem.span(service);
            port = std.fmt.parseInt(u16, service_span, 10) catch 0;
        }
        if (common.evaluate_net_access(node, port, 0, 0) == common.DECISION_DENY) {
            return -1; // UV error codes are negative
        }
    }

    return if (real_uv_getaddrinfo) |func| func(loop, req, cb, node, service, hints) else -1;
}

const connect_fn = *const fn (sockfd: c_int, addr: *const c.sockaddr, addrlen: c.socklen_t) callconv(.c) c_int;
var real_connect: ?connect_fn = null;

export fn connect(sockfd: c_int, addr: *const c.sockaddr, addrlen: c.socklen_t) callconv(.c) c_int {
    if (real_connect == null) real_connect = common.getRealSymbol(connect_fn, "connect");

    var ip_buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
    var port: u16 = 0;

    if (addr.sa_family == c.AF_INET) {
        const addr_in: *const c.sockaddr_in = @ptrCast(@alignCast(addr));
        _ = c.inet_ntop(c.AF_INET, &addr_in.sin_addr, &ip_buf, c.INET_ADDRSTRLEN);
        port = std.mem.bigToNative(u16, addr_in.sin_port);
    } else if (addr.sa_family == c.AF_INET6) {
        const addr_in6: *const c.sockaddr_in6 = @ptrCast(@alignCast(addr));
        _ = c.inet_ntop(c.AF_INET6, &addr_in6.sin6_addr, &ip_buf, c.INET6_ADDRSTRLEN);
        port = std.mem.bigToNative(u16, addr_in6.sin6_port);
    } else if (addr.sa_family == c.AF_UNIX) {
        const addr_un: *const c.sockaddr_un = @ptrCast(@alignCast(addr));
        const path_ptr = &addr_un.sun_path;
        const socket_path = std.mem.sliceTo(@as([*c]const u8, @ptrCast(path_ptr)), 0);
        var is_telemetry = false;
        const tel_path_c = getenv("ASTRAEA_TELEMETRY");
        if (tel_path_c != null) {
            const tel_path = std.mem.span(tel_path_c);
            if (std.mem.eql(u8, socket_path, tel_path)) {
                is_telemetry = true;
            }
        }
        if (!is_telemetry) {
            const res = common.evaluate_fs_access(path_ptr, null);
            if (res.decision == common.DECISION_DENY) {
                common.__errno().* = 13; // EACCES
                return -1;
            }
        }
    }

    const ip_slice = std.mem.sliceTo(&ip_buf, 0);

    if (port == 53) {
        if (common.evaluate_net_access(ip_slice.ptr, port, 0, 0) == common.DECISION_DENY) {
            common.__errno().* = 13;
            return -1;
        }
    } else if (port != 0) {
        if (common.evaluate_net_access(ip_slice.ptr, port, 0, 0) == common.DECISION_DENY) {
            common.__errno().* = 13; // EACCES
            return -1;
        }
    }

    return if (real_connect) |func| func(sockfd, addr, addrlen) else -1;
}

const sendto_fn = *const fn (sockfd: c_int, buf: ?*const anyopaque, len: usize, flags: c_int, dest_addr: ?*const c.sockaddr, addrlen: c.socklen_t) callconv(.c) isize;
var real_sendto: ?sendto_fn = null;

export fn sendto(sockfd: c_int, buf: ?*const anyopaque, len: usize, flags: c_int, dest_addr: ?*const c.sockaddr, addrlen: c.socklen_t) callconv(.c) isize {
    if (real_sendto == null) real_sendto = common.getRealSymbol(sendto_fn, "sendto");

    if (dest_addr) |addr| {
        var ip_buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
        var port: u16 = 0;

        if (addr.sa_family == c.AF_INET) {
            const addr_in: *const c.sockaddr_in = @ptrCast(@alignCast(addr));
            _ = c.inet_ntop(c.AF_INET, &addr_in.sin_addr, &ip_buf, c.INET_ADDRSTRLEN);
            port = std.mem.bigToNative(u16, addr_in.sin_port);
        } else if (addr.sa_family == c.AF_INET6) {
            const addr_in6: *const c.sockaddr_in6 = @ptrCast(@alignCast(addr));
            _ = c.inet_ntop(c.AF_INET6, &addr_in6.sin6_addr, &ip_buf, c.INET6_ADDRSTRLEN);
            port = std.mem.bigToNative(u16, addr_in6.sin6_port);
        }

        const ip_slice = std.mem.sliceTo(&ip_buf, 0);

        if (port == 53) {
            if (common.evaluate_net_access(ip_slice.ptr, port, 0, 17) == common.DECISION_DENY) { // UDP = 17
                common.__errno().* = 13;
                return -1;
            }
        } else if (port != 0) {
            if (common.evaluate_net_access(ip_slice.ptr, port, 0, 17) == common.DECISION_DENY) {
                common.__errno().* = 13; // EACCES
                return -1;
            }
        }
    }

    return if (real_sendto) |func| func(sockfd, buf, len, flags, dest_addr, addrlen) else -1;
}

const recvfrom_fn = *const fn (sockfd: c_int, buf: ?*anyopaque, len: usize, flags: c_int, src_addr: ?*c.sockaddr, addrlen: ?*c.socklen_t) callconv(.c) isize;
var real_recvfrom: ?recvfrom_fn = null;

export fn recvfrom(sockfd: c_int, buf: ?*anyopaque, len: usize, flags: c_int, src_addr: ?*c.sockaddr, addrlen: ?*c.socklen_t) callconv(.c) isize {
    if (real_recvfrom == null) real_recvfrom = common.getRealSymbol(recvfrom_fn, "recvfrom");

    const ret = if (real_recvfrom) |func| func(sockfd, buf, len, flags, src_addr, addrlen) else -1;

    if (ret > 0 and src_addr != null and buf != null) {
        const addr = src_addr.?;
        var port: u16 = 0;
        if (addr.sa_family == c.AF_INET) {
            const addr_in: *const c.sockaddr_in = @ptrCast(@alignCast(addr));
            port = std.mem.bigToNative(u16, addr_in.sin_port);
        } else if (addr.sa_family == c.AF_INET6) {
            const addr_in6: *const c.sockaddr_in6 = @ptrCast(@alignCast(addr));
            port = std.mem.bigToNative(u16, addr_in6.sin6_port);
        }

        if (port == 53) {
            parse_and_register_dns(buf.?, @intCast(ret));
        }
    }

    return ret;
}

const recv_fn = *const fn (sockfd: c_int, buf: ?*anyopaque, len: usize, flags: c_int) callconv(.c) isize;
var real_recv: ?recv_fn = null;

export fn recv(sockfd: c_int, buf: ?*anyopaque, len: usize, flags: c_int) callconv(.c) isize {
    if (real_recv == null) real_recv = common.getRealSymbol(recv_fn, "recv");

    const ret = if (real_recv) |func| func(sockfd, buf, len, flags) else -1;

    if (ret > 0 and buf != null) {
        var addr: c.sockaddr_storage = undefined;
        var addr_len: c.socklen_t = @sizeOf(c.sockaddr_storage);
        if (c.getpeername(sockfd, @ptrCast(&addr), &addr_len) == 0) {
            const sa: *const c.sockaddr = @ptrCast(&addr);
            var port: u16 = 0;
            if (sa.sa_family == c.AF_INET) {
                const addr_in: *const c.sockaddr_in = @ptrCast(@alignCast(sa));
                port = std.mem.bigToNative(u16, addr_in.sin_port);
            } else if (sa.sa_family == c.AF_INET6) {
                const addr_in6: *const c.sockaddr_in6 = @ptrCast(@alignCast(sa));
                port = std.mem.bigToNative(u16, addr_in6.sin6_port);
            }

            if (port == 53) {
                parse_and_register_dns(buf.?, @intCast(ret));
            }
        }
    }

    return ret;
}

fn parse_and_register_dns(buf: *anyopaque, len: usize) void {
    const data: [*]u8 = @ptrCast(buf);
    if (len < 12) return;

    // DNS Header
    // const id = std.mem.readInt(u16, data[0..2][0..2], .big);
    const flags = std.mem.readInt(u16, data[2..4][0..2], .big);
    const qdcount = std.mem.readInt(u16, data[4..6][0..2], .big);
    const ancount = std.mem.readInt(u16, data[6..8][0..2], .big);

    // Check if it's a response (QR=1)
    if ((flags & 0x8000) == 0) return;

    var pos: usize = 12;

    // Skip questions
    var i: usize = 0;
    while (i < qdcount and pos < len) : (i += 1) {
        pos = skip_name(data, len, pos);
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answers
    i = 0;
    while (i < ancount and pos < len) : (i += 1) {
        const name_start = pos;
        pos = skip_name(data, len, pos);
        if (pos + 10 > len) break;

        const atype = std.mem.readInt(u16, data[pos .. pos + 2][0..2], .big);
        const ttl = std.mem.readInt(u32, data[pos + 4 .. pos + 8][0..4], .big);
        const rdlen = std.mem.readInt(u16, data[pos + 8 .. pos + 10][0..2], .big);
        pos += 10;

        if (atype == 1 and rdlen == 4) { // A record
            if (pos + 4 <= len) {
                var domain_buf: [256]u8 = undefined;
                const domain_len = parse_name(data, len, name_start, &domain_buf);
                if (domain_len > 0) {
                    var ip_buf: [c.INET_ADDRSTRLEN]u8 = undefined;
                    _ = c.inet_ntop(c.AF_INET, data + pos, &ip_buf, c.INET_ADDRSTRLEN);
                    common.log_info("DNS SNOOPED (A): {s} -> {s}", .{ domain_buf[0..domain_len], std.mem.span(@as([*c]u8, @ptrCast(&ip_buf))) });
                    common.register_dns_result(&domain_buf, &ip_buf, ttl);
                }
            }
        } else if (atype == 28 and rdlen == 16) { // AAAA record
            if (pos + 16 <= len) {
                var domain_buf: [256]u8 = undefined;
                const domain_len = parse_name(data, len, name_start, &domain_buf);
                if (domain_len > 0) {
                    var ip_buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
                    _ = c.inet_ntop(c.AF_INET6, data + pos, &ip_buf, c.INET6_ADDRSTRLEN);
                    common.log_info("DNS SNOOPED (AAAA): {s} -> {s}", .{ domain_buf[0..domain_len], std.mem.span(@as([*c]u8, @ptrCast(&ip_buf))) });
                    common.register_dns_result(&domain_buf, &ip_buf, ttl);
                }
            }
        }

        pos += rdlen;
    }
}

fn skip_name(data: [*]u8, len: usize, start_pos: usize) usize {
    var pos = start_pos;
    while (pos < len) {
        const b = data[pos];
        if (b == 0) {
            pos += 1;
            break;
        } else if ((b & 0xC0) == 0xC0) {
            pos += 2;
            break;
        } else {
            pos += @as(usize, b) + 1;
        }
    }
    return pos;
}

fn parse_name(data: [*]u8, len: usize, start_pos: usize, out: []u8) usize {
    var pos = start_pos;
    var out_pos: usize = 0;
    var jumped = false;
    var jump_pos: usize = 0;
    var limit: usize = 0;

    while (pos < len and limit < 10) { // limit to avoid infinite loops
        const b = data[pos];
        if (b == 0) {
            if (!jumped) pos += 1;
            break;
        } else if ((b & 0xC0) == 0xC0) {
            if (!jumped) {
                jump_pos = pos + 2;
                jumped = true;
            }
            pos = @as(usize, b & 0x3F) << 8 | data[pos + 1];
            limit += 1;
        } else {
            const label_len = @as(usize, b);
            if (out_pos + label_len + 1 > out.len) break;
            if (out_pos > 0) {
                out[out_pos] = '.';
                out_pos += 1;
            }
            @memcpy(out[out_pos .. out_pos + label_len], data[pos + 1 .. pos + 1 + label_len]);
            out_pos += label_len;
            pos += label_len + 1;
        }
    }

    out[out_pos] = 0;
    return out_pos;
}

const sendmsg_fn = *const fn (sockfd: c_int, msg: ?*const c.msghdr, flags: c_int) callconv(.c) isize;
var real_sendmsg: ?sendmsg_fn = null;

export fn sendmsg(sockfd: c_int, msg: ?*const c.msghdr, flags: c_int) callconv(.c) isize {
    if (real_sendmsg == null) real_sendmsg = common.getRealSymbol(sendmsg_fn, "sendmsg");

    if (msg) |m| {
        if (m.msg_name != null and m.msg_namelen > 0) {
            const addr: *const c.sockaddr = @ptrCast(@alignCast(m.msg_name));
            var ip_buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
            var port: u16 = 0;

            if (addr.sa_family == c.AF_INET) {
                const addr_in: *const c.sockaddr_in = @ptrCast(@alignCast(addr));
                _ = c.inet_ntop(c.AF_INET, &addr_in.sin_addr, &ip_buf, c.INET_ADDRSTRLEN);
                port = std.mem.bigToNative(u16, addr_in.sin_port);
            } else if (addr.sa_family == c.AF_INET6) {
                const addr_in6: *const c.sockaddr_in6 = @ptrCast(@alignCast(addr));
                _ = c.inet_ntop(c.AF_INET6, &addr_in6.sin6_addr, &ip_buf, c.INET6_ADDRSTRLEN);
                port = std.mem.bigToNative(u16, addr_in6.sin6_port);
            }

            const ip_slice = std.mem.sliceTo(&ip_buf, 0);
            if (port != 0) {
                if (common.evaluate_net_access(ip_slice.ptr, port, 0, 17) == common.DECISION_DENY) { // UDP = 17
                    common.__errno().* = 13; // EACCES
                    return -1;
                }
            }
        }
    }

    return if (real_sendmsg) |func| func(sockfd, msg, flags) else -1;
}

const sendmmsg_fn = *const fn (sockfd: c_int, msgvec: ?[*]c.mmsghdr, vlen: c_uint, flags: c_int) callconv(.c) c_int;
var real_sendmmsg: ?sendmmsg_fn = null;

export fn sendmmsg(sockfd: c_int, msgvec: ?[*]c.mmsghdr, vlen: c_uint, flags: c_int) callconv(.c) c_int {
    if (real_sendmmsg == null) real_sendmmsg = common.getRealSymbol(sendmmsg_fn, "sendmmsg");

    if (msgvec) |vec| {
        var idx: c_uint = 0;
        while (idx < vlen) : (idx += 1) {
            const m = &vec[idx].msg_hdr;
            if (m.msg_name != null and m.msg_namelen > 0) {
                const addr: *const c.sockaddr = @ptrCast(@alignCast(m.msg_name));
                var ip_buf: [c.INET6_ADDRSTRLEN]u8 = undefined;
                var port: u16 = 0;

                if (addr.sa_family == c.AF_INET) {
                    const addr_in: *const c.sockaddr_in = @ptrCast(@alignCast(addr));
                    _ = c.inet_ntop(c.AF_INET, &addr_in.sin_addr, &ip_buf, c.INET_ADDRSTRLEN);
                    port = std.mem.bigToNative(u16, addr_in.sin_port);
                } else if (addr.sa_family == c.AF_INET6) {
                    const addr_in6: *const c.sockaddr_in6 = @ptrCast(@alignCast(addr));
                    _ = c.inet_ntop(c.AF_INET6, &addr_in6.sin6_addr, &ip_buf, c.INET6_ADDRSTRLEN);
                    port = std.mem.bigToNative(u16, addr_in6.sin6_port);
                }

                const ip_slice = std.mem.sliceTo(&ip_buf, 0);
                if (port != 0) {
                    if (common.evaluate_net_access(ip_slice.ptr, port, 0, 17) == common.DECISION_DENY) { // UDP = 17
                        common.__errno().* = 13; // EACCES
                        return -1;
                    }
                }
            }
        }
    }

    return if (real_sendmmsg) |func| func(sockfd, msgvec, vlen, flags) else -1;
}
