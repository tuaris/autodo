const std = @import("std");
const ucl = @import("ucl");
const posix = std.posix;

const AUTODO_BITMAP_WORDS = 11;
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

const AUTODO_SET_SCOPE: c_ulong = 0x80584101; // _IOW('A', 1, struct autodo_scope)  88 bytes
const AUTODO_GET_SCOPE: c_ulong = 0x40584102; // _IOR('A', 2, struct autodo_scope)
const AUTODO_FLUSH: c_ulong = 0x20004103; // _IO('A', 3)

const default_config_path = "/usr/local/etc/autodo/autodo.conf";
const default_log_path = "/var/log/autodo/events.json";
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

extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;

fn pushScope(dev_fd: posix.fd_t, scope: *AutodoScope) !void {
    const rc = ioctl(dev_fd, AUTODO_SET_SCOPE, @as(*anyopaque, @ptrCast(scope)));
    if (rc < 0) return error.IoctlFailed;
}

const Config = struct {
    enabled: bool = true,
    categories: [12][]const u8 = undefined,
    num_categories: usize = 0,
    audit_enabled: bool = true,
    log_file: []const u8 = default_log_path,
    all: bool = true,

    fn setAll(self: *Config) void {
        self.all = true;
        self.num_categories = 1;
        self.categories[0] = "all";
    }
};

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

    // Load config
    var scope = AutodoScope{ .as_bitmap = [_]u64{~@as(u64, 0)} ** AUTODO_BITMAP_WORDS };
    if (loadConfig(config_path)) |cfg| {
        log(.info, "loaded config from {s}", .{config_path});
        if (!cfg.enabled) {
            // Push empty bitmap
            scope = AutodoScope{ .as_bitmap = [_]u64{0} ** AUTODO_BITMAP_WORDS };
        } else {
            scope = buildBitmap(cfg.categories[0..cfg.num_categories]);
        }
        log_path = cfg.log_file;
    } else {
        log(.warn, "no config at {s}, using defaults (scope=all)", .{config_path});
    }

    // Open /dev/autodo
    const dev_fd = posix.open(dev_path, .{ .ACCMODE = .RDWR }, 0) catch |err| {
        log(.err, "cannot open {s}: {s}", .{ dev_path, @errorName(err) });
        return err;
    };
    defer posix.close(dev_fd);

    // Push scope to kernel
    pushScope(dev_fd, &scope) catch |err| {
        log(.err, "ioctl SET_SCOPE failed: {s}", .{@errorName(err)});
        return err;
    };
    log(.info, "pushed scope bitmap to kernel", .{});

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

    // Register changelist
    const rc = kevent(kq, &changes, nchanges, null, 0, null);
    if (rc < 0) {
        const errno_val = std.c._errno().*;
        log(.err, "kevent register failed, errno={d}", .{errno_val});
        return error.KeventFailed;
    }

    log(.info, "event loop started, monitoring {s}", .{dev_path});

    var running = true;
    var events: [16]KEvent = undefined;
    var buf: [4096]u8 align(@alignOf(AutodoEvent)) = undefined;

    while (running) {
        const nevents = kevent(kq, null, 0, &events, 16, null);
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
                        if (!cfg.enabled) {
                            scope = AutodoScope{ .as_bitmap = [_]u64{0} ** AUTODO_BITMAP_WORDS };
                        } else {
                            scope = buildBitmap(cfg.categories[0..cfg.num_categories]);
                        }
                        pushScope(dev_fd, &scope) catch {
                            log(.err, "ioctl SET_SCOPE failed on reload", .{});
                        };
                        log(.info, "config reloaded, scope pushed", .{});
                    } else {
                        log(.err, "config reload failed", .{});
                    }
                }
            } else if (ev.filter == c_event.EVFILT_VNODE) {
                log(.info, "config file changed, reloading", .{});
                if (loadConfig(config_path)) |cfg| {
                    if (!cfg.enabled) {
                        scope = AutodoScope{ .as_bitmap = [_]u64{0} ** AUTODO_BITMAP_WORDS };
                    } else {
                        scope = buildBitmap(cfg.categories[0..cfg.num_categories]);
                    }
                    pushScope(dev_fd, &scope) catch {
                        log(.err, "ioctl SET_SCOPE failed on reload", .{});
                    };
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
