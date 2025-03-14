qid: std.posix.fd_t,
next_key: usize = 1,

pub fn init(rws: u24) !IpcMessageQueue {
    return .{ .qid = try IpcMessageQueue.get(0, .init(rws, true, false)) };
}

pub fn get(key: u64, flags: IpcFlags) !std.posix.fd_t {
    const flags_int: u32 = @bitCast(flags);
    const qid_res = std.os.linux.syscall2(.msgget, key, @as(usize, flags_int));
    switch (std.posix.errno(qid_res)) {
        .SUCCESS => {},
        .ACCES => return error.ACCES,
        .EXIST => return error.EXIST,
        .NOENT => return error.NOENT,
        .NOMEM => return error.NOMEM,
        .NOSPC => return error.NOSPC,
        else => unreachable,
    }
    // return @as(std.posix.fd_t, qid_res);
    return @intCast(qid_res);
}

// This error is intended to be ignored, it will only fail if the user hass
// manually changed the queue or deinited twice.
// TODO: implement full msgctl interface rather than syscall here.
pub fn deinit(self: IpcMessageQueue) !void {
    const msgctl_res = std.os.linux.syscall3(.msgctl, @intCast(self.qid), 0, 0);
    switch (std.posix.errno(msgctl_res)) {
        .SUCCESS => {},
        .IDRM => return error.IDRM,
        .PERM => return error.PERM,
        else => unreachable,
    }
}

const Message = struct {
    key: u64,
    data: []const u8,

    pub fn destroy(self: Message, gpa: std.mem.Allocator) void {
        var slice: []const u8 = undefined;
        slice.ptr = self.data.ptr - 8;
        slice.len = self.data.len + 8;
        gpa.free(slice);
    }
};

const MsgFlags = packed struct(u32) {
    pad_0: u11 = 0,
    NOWAIT: bool = false,
    NOERROR: bool = false,
    EXCEPT: bool = false,
    pad_1: u18 = 0,
};

pub fn sendRaw(self: IpcMessageQueue, gpa: std.mem.Allocator, message: Message, flags: MsgFlags) !void {
    const message_bytes = try gpa.alloc(u8, message.data.len + 8);
    defer gpa.free(message_bytes);
    @memcpy(message_bytes[0..8], std.mem.asBytes(&message.key));
    @memcpy(message_bytes[8..message_bytes.len], message.data);
    const flags_int: u32 = @bitCast(flags);

    const send_res = std.os.linux.syscall4(
        .msgsnd,
        @intCast(self.qid),
        @intFromPtr(message_bytes.ptr),
        message.data.len,
        @intCast(flags_int),
    );
    return switch (std.posix.errno(send_res)) {
        .SUCCESS => {},
        .ACCES => error.ACCES,
        .AGAIN => error.AGAIN,
        .FAULT => error.FAULT,
        .IDRM => error.IDRM,
        .INTR => error.INTR,
        .INVAL => error.INVAL,
        .NOMEM => error.NOMEM,
        else => unreachable,
    };
}

pub fn send(self: *IpcMessageQueue, gpa: std.mem.Allocator, data: []const u8, flags: MsgFlags) !u64 {
    try self.sendRaw(gpa, .{ .key = self.next_key, .data = data }, flags);
    self.next_key += 1;
    return self.next_key - 1;
}

fn sendSize(self: *IpcMessageQueue, gpa: std.mem.Allocator, comptime size: usize, char: u8, flags: MsgFlags) !u64 {
    var buf: [size]u8 = undefined;
    for (0..size) |idx| buf[idx] = char;
    return try self.send(gpa, &buf, flags);
}

pub fn send64(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 64 - 0x30, char, flags);
}

pub fn send96(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 96 - 0x30, char, flags);
}

pub fn send128(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 128 - 0x30, char, flags);
}

pub fn send192(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 192 - 0x30, char, flags);
}

pub fn send256(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 256 - 0x30, char, flags);
}

pub fn send512(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 512 - 0x30, char, flags);
}

pub fn send1k(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 0x400 - 0x30, char, flags);
}

pub fn send2k(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 0x800 - 0x30, char, flags);
}

pub fn send4k(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 0x1000 - 0x30, char, flags);
}

pub fn send8k(self: *IpcMessageQueue, gpa: std.mem.Allocator, char: u8, flags: MsgFlags) !u64 {
    return try self.sendSize(gpa, 0x2000 - 0x30, char, flags);
}

pub fn recvRaw(self: IpcMessageQueue, buf: []u8, key: u64, flags: MsgFlags) !Message {
    const flags_int: u32 = @bitCast(flags);
    const recv_res = std.os.linux.syscall5(
        .msgrcv,
        @intCast(self.qid),
        @intFromPtr(buf.ptr),
        buf.len,
        key,
        @intCast(flags_int),
    );

    switch (std.posix.errno(recv_res)) {
        .SUCCESS => {},
        .@"2BIG" => return error.@"2BIG",
        .ACCES => return error.ACCES,
        .AGAIN => return error.AGAIN,
        .FAULT => return error.FAULT,
        .IDRM => return error.IDRM,
        .INTR => return error.INTR,
        .INVAL => return error.INVAL,
        .NOMSG => return error.NOMSG,
        else => unreachable,
    }

    const recv_key_ptr: *u64 = @alignCast(@ptrCast(buf[0..8]));
    return .{
        .key = recv_key_ptr.*,
        .data = buf[8..buf.len],
    };
}

pub fn recv(self: IpcMessageQueue, gpa: std.mem.Allocator, len: u64, key: u64, flags: MsgFlags) !Message {
    const msg_buf = try gpa.alloc(u8, len + 8);
    return try self.recvRaw(msg_buf, key, flags);
}

const IpcFlags = packed struct(u32) {
    pad_0: u1 = 0,
    other_write: bool = false,
    other_read: bool = false,
    pad_1: u1 = 0,
    group_write: bool = false,
    group_read: bool = false,
    pad_2: u1 = 0,
    user_write: bool = false,
    user_read: bool = false,
    creat: bool = false,
    excl: bool = false,
    pad_3: u21 = 0,

    pub fn init(rws: u24, creat: bool, excl: bool) IpcFlags {
        var flags: IpcFlags = .{
            .creat = creat,
            .excl = excl,
        };

        flags.other_write = (rws & 0o2) == 0o2;
        flags.other_read = (rws & 0o4) == 0o4;
        flags.group_write = (rws & 0o20) == 0o20;
        flags.group_read = (rws & 0o40) == 0o40;
        flags.user_write = (rws & 0o200) == 0o200;
        flags.user_read = (rws & 0o400) == 0o400;

        return flags;
    }
};

test "create queue" {
    var msg_queue = IpcMessageQueue.init(0o644) catch {
        std.debug.assert(false);
        return;
    };
    msg_queue.deinit() catch {
        std.debug.assert(false);
        return;
    };
}

test "send and recv nowait" {
    const gpa = std.testing.allocator;

    var msg_queue: IpcMessageQueue = try .init(0o644);
    defer msg_queue.deinit() catch unreachable;

    const msg_key = try msg_queue.send(gpa, &[_]u8{'A'} ** 4, .{ .NOWAIT = true });
    std.debug.assert(msg_key == 1);

    const msg = try msg_queue.recv(gpa, 4, msg_key, .{ .NOWAIT = true });
    defer msg.destroy(gpa);

    std.debug.assert(msg.key == msg_key);
    std.debug.assert(std.mem.eql(u8, &[_]u8{'A'} ** 4, msg.data));
}

fn testRecvSized(gpa: std.mem.Allocator, queue: IpcMessageQueue, comptime chunk_size: u64, key: u64, char: u8) !void {
    const msg = try queue.recv(gpa, chunk_size - 0x30, key, .{ .NOWAIT = true });
    std.debug.assert(msg.key == key);
    std.debug.assert(std.mem.eql(u8, &[_]u8{char} ** (chunk_size - 0x30), msg.data));
    msg.destroy(gpa);
}

test "send sized" {
    const gpa = std.testing.allocator;

    var msg_queue: IpcMessageQueue = try .init(0o644);
    defer msg_queue.deinit() catch unreachable;

    const key_64 = try msg_queue.send64(gpa, 'A', .{ .NOWAIT = true });
    const key_96 = try msg_queue.send96(gpa, 'B', .{ .NOWAIT = true });
    const key_128 = try msg_queue.send128(gpa, 'C', .{ .NOWAIT = true });
    const key_192 = try msg_queue.send192(gpa, 'D', .{ .NOWAIT = true });
    const key_256 = try msg_queue.send256(gpa, 'E', .{ .NOWAIT = true });
    const key_512 = try msg_queue.send512(gpa, 'F', .{ .NOWAIT = true });
    const key_1k = try msg_queue.send1k(gpa, 'G', .{ .NOWAIT = true });
    const key_2k = try msg_queue.send2k(gpa, 'H', .{ .NOWAIT = true });
    const key_4k = try msg_queue.send4k(gpa, 'I', .{ .NOWAIT = true });
    const key_8k = try msg_queue.send8k(gpa, 'J', .{ .NOWAIT = true });

    try testRecvSized(gpa, msg_queue, 64, key_64, 'A');
    try testRecvSized(gpa, msg_queue, 96, key_96, 'B');
    try testRecvSized(gpa, msg_queue, 128, key_128, 'C');
    try testRecvSized(gpa, msg_queue, 192, key_192, 'D');
    try testRecvSized(gpa, msg_queue, 256, key_256, 'E');
    try testRecvSized(gpa, msg_queue, 512, key_512, 'F');
    try testRecvSized(gpa, msg_queue, 0x400, key_1k, 'G');
    try testRecvSized(gpa, msg_queue, 0x800, key_2k, 'H');
    try testRecvSized(gpa, msg_queue, 0x1000, key_4k, 'I');
    try testRecvSized(gpa, msg_queue, 0x2000, key_8k, 'J');
}

const IpcMessageQueue = @This();
const std = @import("std");
