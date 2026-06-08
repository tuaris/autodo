const std = @import("std");
const ucl = @import("ucl");
const posix = std.posix;

const AUTODO_BITMAP_WORDS = 11;
const AUTODO_MAX_GROUPS = 16;
const AUTODO_RING_SIZE = 1024;

const AutodoEvent = extern struct {
    ae_timestamp: u64,
    ae_pid: u32,
    ae_uid: u32,
    ae_gid: u32,
    ae_priv: i32,
    ae_granted: u8,
    ae_pad: [3]u8,
    ae_comm: [20]u8,
};

const AutodoScope = extern struct {
    as_bitmap: [AUTODO_BITMAP_WORDS]u64,
};

const AutodoPolicyEntry = extern struct {
    ape_gid: u32,
    ape_pad: u32,
    ape_bitmap: [AUTODO_BITMAP_WORDS]u64,
};

const AutodoPolicy = extern struct {
    ap_count: u32,
    ap_pad: u32,
    ap_entries: [AUTODO_MAX_GROUPS]AutodoPolicyEntry,
};

const AUTODO_SET_SCOPE: c_ulong = 0x80584101; // _IOW('A', 1, struct autodo_scope)  88 bytes
const AUTODO_GET_SCOPE: c_ulong = 0x40584102; // _IOR('A', 2, struct autodo_scope)
const AUTODO_FLUSH: c_ulong = 0x20004103; // _IO('A', 3)
// _IOW('A', 4, struct autodo_policy) — sizeof = 8 + 16*96 = 1544 = 0x608
const AUTODO_SET_POLICY: c_ulong = 0x86084104;
const AUTODO_GET_POLICY: c_ulong = 0x46084105;

const default_config_path = "/usr/local/etc/autodo/autodo.conf";
const default_log_path = "/var/log/autodo/events.json";
const default_template_dir = "/usr/local/etc/autodo/templates";
const dev_path = "/dev/autodo";

const PrivCategory = struct {
    name: []const u8,
    start: u16,
    end: u16,
};

const priv_categories = [_]PrivCategory{
    .{ .name = "system", .start = 2, .end = 18 },
    .{ .name = "audit", .start = 40, .end = 44 },
    .{ .name = "cred", .start = 50, .end = 62 },
    .{ .name = "debug", .start = 80, .end = 92 },
    .{ .name = "jail", .start = 110, .end = 112 },
    .{ .name = "kld", .start = 130, .end = 141 },
    .{ .name = "proc", .start = 160, .end = 242 },
    .{ .name = "vfs", .start = 310, .end = 345 },
    .{ .name = "vm", .start = 360, .end = 364 },
    .{ .name = "dev", .start = 370, .end = 380 },
    .{ .name = "net", .start = 390, .end = 540 },
    .{ .name = "misc", .start = 550, .end = 702 },
};

const PrivMapping = struct {
    name: []const u8,
    value: u16,
};

const priv_names = [_]PrivMapping{
    .{ .name = "PRIV_ACCT", .value = 2 },
    .{ .name = "PRIV_MAXFILES", .value = 3 },
    .{ .name = "PRIV_MAXPROC", .value = 4 },
    .{ .name = "PRIV_KTRACE", .value = 5 },
    .{ .name = "PRIV_CLOCK_SETTIME", .value = 6 },
    .{ .name = "PRIV_NFSD", .value = 7 },
    .{ .name = "PRIV_ADJTIME", .value = 10 },
    .{ .name = "PRIV_NTP_ADJTIME", .value = 11 },
    .{ .name = "PRIV_SETHOSTNAME", .value = 14 },
    .{ .name = "PRIV_SETHOSTID", .value = 15 },
    .{ .name = "PRIV_SETDOMAINNAME", .value = 16 },
    .{ .name = "PRIV_REBOOT", .value = 18 },
    .{ .name = "PRIV_AUDIT_CONTROL", .value = 40 },
    .{ .name = "PRIV_AUDIT_GETAUDIT", .value = 41 },
    .{ .name = "PRIV_AUDIT_SETAUDIT", .value = 42 },
    .{ .name = "PRIV_AUDIT_SUBMIT", .value = 43 },
    .{ .name = "PRIV_CRED_SETUID", .value = 50 },
    .{ .name = "PRIV_CRED_SETEUID", .value = 51 },
    .{ .name = "PRIV_CRED_SETGID", .value = 52 },
    .{ .name = "PRIV_CRED_SETEGID", .value = 53 },
    .{ .name = "PRIV_CRED_SETGROUPS", .value = 54 },
    .{ .name = "PRIV_CRED_SETREUID", .value = 55 },
    .{ .name = "PRIV_CRED_SETREGID", .value = 56 },
    .{ .name = "PRIV_CRED_SETRESUID", .value = 57 },
    .{ .name = "PRIV_CRED_SETRESGID", .value = 58 },
    .{ .name = "PRIV_DEBUG_DIFFCRED", .value = 80 },
    .{ .name = "PRIV_DEBUG_SUGID", .value = 81 },
    .{ .name = "PRIV_DEBUG_UNPRIV", .value = 82 },
    .{ .name = "PRIV_DTRACE_KERNEL", .value = 90 },
    .{ .name = "PRIV_DTRACE_PROC", .value = 91 },
    .{ .name = "PRIV_DTRACE_USER", .value = 92 },
    .{ .name = "PRIV_JAIL_ATTACH", .value = 110 },
    .{ .name = "PRIV_JAIL_SET", .value = 111 },
    .{ .name = "PRIV_JAIL_REMOVE", .value = 112 },
    .{ .name = "PRIV_KLD_LOAD", .value = 130 },
    .{ .name = "PRIV_KLD_UNLOAD", .value = 131 },
    .{ .name = "PRIV_MAC_PARTITION", .value = 140 },
    .{ .name = "PRIV_MAC_PRIVS", .value = 141 },
    .{ .name = "PRIV_PROC_LIMIT", .value = 160 },
    .{ .name = "PRIV_PROC_SETLOGIN", .value = 161 },
    .{ .name = "PRIV_PROC_SETRLIMIT", .value = 162 },
    .{ .name = "PRIV_SIGNAL_DIFFCRED", .value = 200 },
    .{ .name = "PRIV_SIGNAL_SUGID", .value = 201 },
    .{ .name = "PRIV_SYSCTL_WRITE", .value = 220 },
    .{ .name = "PRIV_SYSCTL_WRITEJAIL", .value = 221 },
    .{ .name = "PRIV_VFS_READ", .value = 310 },
    .{ .name = "PRIV_VFS_WRITE", .value = 311 },
    .{ .name = "PRIV_VFS_ADMIN", .value = 312 },
    .{ .name = "PRIV_VFS_EXEC", .value = 313 },
    .{ .name = "PRIV_VFS_LOOKUP", .value = 314 },
    .{ .name = "PRIV_VFS_CHFLAGS_DEV", .value = 315 },
    .{ .name = "PRIV_VFS_CHOWN", .value = 316 },
    .{ .name = "PRIV_VFS_CHROOT", .value = 317 },
    .{ .name = "PRIV_VFS_FCHROOT", .value = 319 },
    .{ .name = "PRIV_VFS_LINK", .value = 320 },
    .{ .name = "PRIV_VFS_MOUNT", .value = 323 },
    .{ .name = "PRIV_VFS_UNMOUNT", .value = 325 },
    .{ .name = "PRIV_VFS_SETGID", .value = 327 },
    .{ .name = "PRIV_VFS_STICKYDIR", .value = 329 },
    .{ .name = "PRIV_VFS_STAT", .value = 331 },
    .{ .name = "PRIV_VM_MLOCK", .value = 360 },
    .{ .name = "PRIV_VM_MUNLOCK", .value = 361 },
    .{ .name = "PRIV_DEVFS_RULE", .value = 370 },
    .{ .name = "PRIV_NET_BRIDGE", .value = 390 },
    .{ .name = "PRIV_NET_RAW", .value = 400 },
    .{ .name = "PRIV_NET_ROUTE", .value = 410 },
    .{ .name = "PRIV_NETINET_RAW", .value = 430 },
    .{ .name = "PRIV_KMEM_READ", .value = 550 },
    .{ .name = "PRIV_KMEM_WRITE", .value = 551 },
};

fn lookupPrivByName(name: []const u8) ?u16 {
    for (priv_names) |pm| {
        if (std.mem.eql(u8, name, pm.name)) return pm.value;
    }
    return null;
}

fn buildBitmap(categories: []const []const u8) AutodoScope {
    var scope = AutodoScope{ .as_bitmap = [_]u64{0} ** AUTODO_BITMAP_WORDS };

    for (categories) |cat| {
        if (std.mem.eql(u8, cat, "all")) {
            for (&scope.as_bitmap) |*w| w.* = ~@as(u64, 0);
            return scope;
        }
        for (priv_categories) |pc| {
            if (std.mem.eql(u8, cat, pc.name)) {
                var p: u16 = pc.start;
                while (p <= pc.end) : (p += 1) {
                    const word = @as(usize, p) / 64;
                    const bit: u6 = @intCast(@as(usize, p) % 64);
                    scope.as_bitmap[word] |= @as(u64, 1) << bit;
                }
            }
        }
    }
    return scope;
}

fn clearPrivBit(bitmap: *[AUTODO_BITMAP_WORDS]u64, priv: u16) void {
    const word = @as(usize, priv) / 64;
    const bit: u6 = @intCast(@as(usize, priv) % 64);
    if (word < AUTODO_BITMAP_WORDS) {
        bitmap[word] &= ~(@as(u64, 1) << bit);
    }
}

extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;

fn pushScope(dev_fd: posix.fd_t, scope: *AutodoScope) !void {
    const rc = ioctl(dev_fd, AUTODO_SET_SCOPE, @as(*anyopaque, @ptrCast(scope)));
    if (rc < 0) return error.IoctlFailed;
}

fn pushPolicy(dev_fd: posix.fd_t, policy: *AutodoPolicy) !void {
    const rc = ioctl(dev_fd, AUTODO_SET_POLICY, @as(*anyopaque, @ptrCast(policy)));
    if (rc < 0) return error.IoctlFailed;
}

const c_grp = @cImport({
    @cInclude("grp.h");
});

fn resolveGroupGid(name: [*:0]const u8) ?u32 {
    const gr = c_grp.getgrnam(name);
    if (gr == null) return null;
    return gr.*.gr_gid;
}

const GroupEntry = struct {
    gid: u32,
    bitmap: [AUTODO_BITMAP_WORDS]u64,
};

const Config = struct {
    enabled: bool = true,
    categories: [12][]const u8 = undefined,
    num_categories: usize = 0,
    audit_enabled: bool = true,
    log_file: []const u8 = default_log_path,
    template_dir: []const u8 = default_template_dir,
    all: bool = true,
    groups: [AUTODO_MAX_GROUPS]GroupEntry = undefined,
    num_groups: usize = 0,
    has_groups: bool = false,

    fn setAll(self: *Config) void {
        self.all = true;
        self.num_categories = 1;
        self.categories[0] = "all";
    }
};

fn loadTemplate(template_dir: []const u8, name: []const u8) ?AutodoScope {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}.conf", .{ template_dir, name }) catch return null;
    // Null-terminate for C API
    if (path.len >= path_buf.len) return null;
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = path_buf[0..path.len :0];

    const parser = ucl.Parser.init(0) orelse return null;
    defer parser.deinit();

    if (!parser.addFile(path_z)) return null;

    const root = parser.getObject() orelse return null;
    defer ucl.unref(root);

    var cats: [12][]const u8 = undefined;
    var num_cats: usize = 0;

    if (root.lookup("scope")) |scope_obj| {
        if (scope_obj.lookup("categories")) |cats_arr| {
            var it = cats_arr.iterate();
            while (it.next()) |item| {
                if (num_cats >= 12) break;
                if (item.toString()) |s| {
                    cats[num_cats] = s;
                    num_cats += 1;
                }
            }
        }
    }

    if (num_cats == 0) {
        cats[0] = "all";
        num_cats = 1;
    }

    var scope = buildBitmap(cats[0..num_cats]);

    // Apply deny list
    if (root.lookup("deny")) |deny_obj| {
        if (deny_obj.lookup("privileges")) |privs| {
            var it = privs.iterate();
            while (it.next()) |item| {
                if (item.toString()) |s| {
                    if (lookupPrivByName(s)) |pval| {
                        clearPrivBit(&scope.as_bitmap, pval);
                    } else {
                        log(.warn, "unknown privilege in deny: {s}", .{s});
                    }
                }
            }
        }
    }

    return scope;
}

fn parseScopeAndDeny(obj: ucl.Object) AutodoScope {
    var cats: [12][]const u8 = undefined;
    var num_cats: usize = 0;

    if (obj.lookup("scope")) |scope_obj| {
        if (scope_obj.lookup("categories")) |cats_arr| {
            var it = cats_arr.iterate();
            while (it.next()) |item| {
                if (num_cats >= 12) break;
                if (item.toString()) |s| {
                    cats[num_cats] = s;
                    num_cats += 1;
                }
            }
        }
    }

    if (num_cats == 0) {
        cats[0] = "all";
        num_cats = 1;
    }

    var scope = buildBitmap(cats[0..num_cats]);

    if (obj.lookup("deny")) |deny_obj| {
        if (deny_obj.lookup("privileges")) |privs| {
            var it = privs.iterate();
            while (it.next()) |item| {
                if (item.toString()) |s| {
                    if (lookupPrivByName(s)) |pval| {
                        clearPrivBit(&scope.as_bitmap, pval);
                    }
                }
            }
        }
    }

    return scope;
}

fn loadConfig(path: [*:0]const u8) ?Config {
    const parser = ucl.Parser.init(0) orelse return null;
    defer parser.deinit();

    if (!parser.addFile(path)) {
        const err = parser.getError();
        if (err) |e| {
            log(.err, "config parse error: {s}", .{e});
        }
        return null;
    }

    const root = parser.getObject() orelse return null;
    defer ucl.unref(root);

    var cfg = Config{};

    if (root.lookup("enabled")) |obj| {
        cfg.enabled = obj.toBool();
    }

    // Template directory override
    if (root.lookup("template_dir")) |obj| {
        if (obj.toString()) |s| {
            cfg.template_dir = s;
        }
    }

    // Multi-group policy: groups { wheel { ... }; developers { ... }; }
    if (root.lookup("groups")) |groups_obj| {
        var git = groups_obj.iterate();
        while (git.next()) |group_obj| {
            if (cfg.num_groups >= AUTODO_MAX_GROUPS) break;
            const group_name = group_obj.key() orelse continue;

            // Null-terminate group name for getgrnam
            var name_buf: [64]u8 = undefined;
            if (group_name.len >= name_buf.len) continue;
            @memcpy(name_buf[0..group_name.len], group_name);
            name_buf[group_name.len] = 0;
            const name_z: [*:0]const u8 = name_buf[0..group_name.len :0];

            const gid = resolveGroupGid(name_z) orelse {
                log(.warn, "unknown group: {s}", .{group_name});
                continue;
            };

            // Determine scope: template reference or inline scope/deny
            var bitmap: [AUTODO_BITMAP_WORDS]u64 = undefined;
            if (group_obj.lookup("template")) |tmpl_obj| {
                if (tmpl_obj.toString()) |tmpl_name| {
                    if (loadTemplate(cfg.template_dir, tmpl_name)) |scope| {
                        bitmap = scope.as_bitmap;
                    } else {
                        log(.warn, "template not found: {s}", .{tmpl_name});
                        continue;
                    }
                } else continue;
            } else {
                // Inline scope + deny
                const scope = parseScopeAndDeny(group_obj);
                bitmap = scope.as_bitmap;
            }

            cfg.groups[cfg.num_groups] = GroupEntry{
                .gid = gid,
                .bitmap = bitmap,
            };
            cfg.num_groups += 1;
            log(.info, "group {s} (gid={d}): policy loaded", .{ group_name, gid });
        }
        cfg.has_groups = cfg.num_groups > 0;
    }

    // Legacy single-scope (used when no groups block)
    if (!cfg.has_groups) {
        if (root.lookup("scope")) |scope_obj| {
            if (scope_obj.objectType() == .string) {
                const val = scope_obj.toString() orelse "all";
                if (std.mem.eql(u8, val, "all")) {
                    cfg.setAll();
                }
            } else if (scope_obj.objectType() == .object) {
                if (scope_obj.lookup("categories")) |cats| {
                    var it = cats.iterate();
                    cfg.num_categories = 0;
                    cfg.all = false;
                    while (it.next()) |item| {
                        if (cfg.num_categories >= 12) break;
                        if (item.toString()) |s| {
                            cfg.categories[cfg.num_categories] = s;
                            cfg.num_categories += 1;
                        }
                    }
                }
            }
        }
    }

    if (root.lookup("audit")) |audit_obj| {
        if (audit_obj.lookup("enabled")) |obj| {
            cfg.audit_enabled = obj.toBool();
        }
        if (audit_obj.lookup("log_file")) |obj| {
            if (obj.toString()) |s| {
                cfg.log_file = s;
            }
        }
    }

    return cfg;
}

fn commSlice(comm: *const [20]u8) []const u8 {
    var len: usize = 0;
    while (len < 20 and comm[len] != 0) : (len += 1) {}
    return comm[0..len];
}

fn log(comptime level: std.log.Level, comptime fmt: []const u8, args: anytype) void {
    const prefix = switch (level) {
        .err => "error",
        .warn => "warn",
        .info => "info",
        .debug => "debug",
    };
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "autodo-eventd: {s}: " ++ fmt ++ "\n", .{prefix} ++ args) catch return;
    _ = posix.write(2, msg) catch {};
}

const c_event = @cImport({
    @cInclude("sys/event.h");
});

const KEvent = c_event.struct_kevent;

extern "c" fn kqueue() c_int;
extern "c" fn kevent(
    kq: c_int,
    changelist: ?[*]const KEvent,
    nchanges: c_int,
    eventlist: ?[*]KEvent,
    nevents: c_int,
    timeout: ?*const std.c.timespec,
) c_int;

fn makeKevent(ident: usize, filter: c_short, flags: c_ushort, fflags: c_uint) KEvent {
    return KEvent{
        .ident = ident,
        .filter = filter,
        .flags = flags,
        .fflags = fflags,
        .data = 0,
        .udata = null,
        .ext = [_]u64{ 0, 0, 0, 0 },
    };
}

fn applyConfig(dev_fd: posix.fd_t, cfg: *const Config) void {
    if (!cfg.enabled) {
        // Disabled: push a policy with one entry (GID 0, empty bitmap).
        // This activates multi-group mode with zero permissions,
        // ensuring no privileges are granted to anyone.
        var policy = std.mem.zeroes(AutodoPolicy);
        policy.ap_count = 1;
        policy.ap_entries[0].ape_gid = 0;
        // bitmap is already all-zero from zeroes()
        pushPolicy(dev_fd, &policy) catch {
            // Fallback to legacy empty scope
            var scope = AutodoScope{ .as_bitmap = [_]u64{0} ** AUTODO_BITMAP_WORDS };
            pushScope(dev_fd, &scope) catch {
                log(.err, "failed to push disabled scope", .{});
            };
        };
        log(.info, "module disabled via config", .{});
        return;
    }

    if (cfg.has_groups) {
        // Multi-group policy path
        var policy = std.mem.zeroes(AutodoPolicy);
        policy.ap_count = @intCast(cfg.num_groups);
        for (0..cfg.num_groups) |i| {
            policy.ap_entries[i].ape_gid = cfg.groups[i].gid;
            policy.ap_entries[i].ape_pad = 0;
            policy.ap_entries[i].ape_bitmap = cfg.groups[i].bitmap;
        }
        pushPolicy(dev_fd, &policy) catch {
            log(.err, "ioctl SET_POLICY failed", .{});
            return;
        };
        log(.info, "pushed multi-group policy ({d} groups)", .{cfg.num_groups});
    } else {
        // Legacy single-scope path
        var scope = buildBitmap(cfg.categories[0..cfg.num_categories]);
        pushScope(dev_fd, &scope) catch {
            log(.err, "ioctl SET_SCOPE failed", .{});
            return;
        };
        log(.info, "pushed legacy scope bitmap", .{});
    }
}

pub fn main() !void {
    var config_path: [*:0]const u8 = default_config_path;
    var log_path: []const u8 = default_log_path;

    var args = std.process.args();
    _ = args.skip(); // program name
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--config=")) {
            config_path = arg[9.. :0];
        } else if (std.mem.startsWith(u8, arg, "--log=")) {
            log_path = arg[6..];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            const help =
                "usage: autodo-eventd [options]\n" ++
                "\n" ++
                "Options:\n" ++
                "  --config=PATH   Config file (default: " ++ default_config_path ++ ")\n" ++
                "  --log=PATH      Audit log file (default: " ++ default_log_path ++ ")\n" ++
                "  --help          Show this help\n";
            _ = posix.write(1, help) catch {};
            return;
        }
    }

    // Open /dev/autodo
    const dev_fd = posix.open(dev_path, .{ .ACCMODE = .RDWR }, 0) catch |err| {
        log(.err, "cannot open {s}: {s}", .{ dev_path, @errorName(err) });
        return err;
    };
    defer posix.close(dev_fd);

    // Load and apply config
    if (loadConfig(config_path)) |cfg| {
        log(.info, "loaded config from {s}", .{config_path});
        applyConfig(dev_fd, &cfg);
        log_path = cfg.log_file;
    } else {
        log(.warn, "no config at {s}, using defaults (scope=all)", .{config_path});
        var scope = AutodoScope{ .as_bitmap = [_]u64{~@as(u64, 0)} ** AUTODO_BITMAP_WORDS };
        pushScope(dev_fd, &scope) catch |err| {
            log(.err, "ioctl SET_SCOPE failed: {s}", .{@errorName(err)});
            return err;
        };
    }

    // Open config file fd for vnode monitoring
    const config_fd = posix.open(
        std.mem.span(config_path),
        .{ .ACCMODE = .RDONLY },
        0,
    ) catch blk: {
        log(.warn, "cannot open config for monitoring", .{});
        break :blk @as(posix.fd_t, -1);
    };

    // Open audit log
    var log_file: ?std.fs.File = null;
    if (log_path.len > 0) {
        log_file = std.fs.cwd().createFile(log_path, .{ .truncate = false }) catch |err| blk: {
            log(.err, "cannot open log {s}: {s}", .{ log_path, @errorName(err) });
            break :blk null;
        };
        if (log_file) |f| {
            f.seekFromEnd(0) catch {};
        }
    }
    defer if (log_file) |f| f.close();

    // Set up kqueue
    const kq = kqueue();
    if (kq < 0) {
        log(.err, "kqueue() failed", .{});
        return error.KqueueFailed;
    }

    var changes: [4]KEvent = undefined;
    var nchanges: c_int = 0;

    // Watch /dev/autodo for readable events
    changes[@intCast(nchanges)] = makeKevent(
        @intCast(dev_fd),
        c_event.EVFILT_READ,
        c_event.EV_ADD | c_event.EV_ENABLE,
        0,
    );
    nchanges += 1;

    // Watch config file for writes
    if (config_fd >= 0) {
        changes[@intCast(nchanges)] = makeKevent(
            @intCast(config_fd),
            c_event.EVFILT_VNODE,
            c_event.EV_ADD | c_event.EV_ENABLE | c_event.EV_CLEAR,
            c_event.NOTE_WRITE | c_event.NOTE_RENAME,
        );
        nchanges += 1;
    }

    // Catch SIGTERM
    changes[@intCast(nchanges)] = makeKevent(
        15, // SIGTERM
        c_event.EVFILT_SIGNAL,
        c_event.EV_ADD | c_event.EV_ENABLE,
        0,
    );
    nchanges += 1;

    // Catch SIGHUP for config reload
    changes[@intCast(nchanges)] = makeKevent(
        1, // SIGHUP
        c_event.EVFILT_SIGNAL,
        c_event.EV_ADD | c_event.EV_ENABLE,
        0,
    );
    nchanges += 1;

    // Block SIGTERM/SIGHUP from default handling
    var mask = std.posix.sigemptyset();
    const sigaddset = std.c.sigaddset;
    _ = sigaddset(&mask, 15); // SIGTERM
    _ = sigaddset(&mask, 1); // SIGHUP
    _ = std.c.sigprocmask(std.c.SIG.BLOCK, &mask, null);

    log(.info, "event loop started, monitoring {s}", .{dev_path});

    var running = true;
    var events: [16]KEvent = undefined;
    var buf: [4096]u8 align(@alignOf(AutodoEvent)) = undefined;
    var reg_changes: ?[*]const KEvent = &changes;
    var reg_nchanges: c_int = nchanges;

    while (running) {
        const nevents = kevent(kq, reg_changes, reg_nchanges, &events, 16, null);
        // After first call, changelist is consumed — clear for subsequent iterations
        reg_changes = null;
        reg_nchanges = 0;
        if (nevents < 0) {
            const err = std.c._errno().*;
            if (err != 4) // EINTR
                log(.err, "kevent wait failed, errno={d}", .{err});
            continue;
        }

        var i: usize = 0;
        while (i < @as(usize, @intCast(nevents))) : (i += 1) {
            const ev = &events[i];

            if (ev.filter == c_event.EVFILT_SIGNAL) {
                if (ev.ident == 15) {
                    log(.info, "received SIGTERM, shutting down", .{});
                    running = false;
                } else if (ev.ident == 1) {
                    log(.info, "received SIGHUP, reloading config", .{});
                    if (loadConfig(config_path)) |cfg| {
                        applyConfig(dev_fd, &cfg);
                        log(.info, "config reloaded via SIGHUP", .{});
                    } else {
                        log(.err, "config reload failed", .{});
                    }
                }
            } else if (ev.filter == c_event.EVFILT_VNODE) {
                log(.info, "config file changed, reloading", .{});
                if (loadConfig(config_path)) |cfg| {
                    applyConfig(dev_fd, &cfg);
                    log(.info, "config reloaded via file change", .{});
                }
            } else if (ev.filter == c_event.EVFILT_READ) {
                // Read events from /dev/autodo
                const n = posix.read(dev_fd, &buf) catch |err| {
                    log(.err, "read /dev/autodo: {s}", .{@errorName(err)});
                    continue;
                };
                if (n == 0) continue;

                const event_count = n / @sizeOf(AutodoEvent);
                const event_ptr: [*]const AutodoEvent = @ptrCast(@alignCast(&buf));

                if (log_file) |f| {
                    var j: usize = 0;
                    while (j < event_count) : (j += 1) {
                        var line_buf: [512]u8 = undefined;
                        const aev = &event_ptr[j];
                        const comm = commSlice(&aev.ae_comm);
                        const line = std.fmt.bufPrint(
                            &line_buf,
                            "{{\"ts\":{d},\"pid\":{d},\"uid\":{d},\"gid\":{d},\"priv\":{d},\"granted\":{},\"comm\":\"{s}\"}}\n",
                            .{
                                aev.ae_timestamp, aev.ae_pid,  aev.ae_uid,
                                aev.ae_gid,       aev.ae_priv, aev.ae_granted != 0,
                                comm,
                            },
                        ) catch continue;
                        f.writeAll(line) catch |err| {
                            log(.err, "write log: {s}", .{@errorName(err)});
                        };
                    }
                }
            }
        }
    }

    log(.info, "shutdown complete", .{});
}
