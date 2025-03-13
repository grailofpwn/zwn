page: []u8,

uf_fd: UserfaultFD,

full_chunk: []align(page_size) u8,
copy_buf: []u8,
thread: std.Thread,

const Context = struct {
    data: ?[]const u8 = null,
    offset: usize = 0,
    size_min: usize = 0,
};

// TODO: data splicing into used chunk
pub fn init(
    gpa: std.mem.Allocator,
    context: Context,
    comptime func: anytype,
    func_args: anytype,
) !FaultPage {
    const uf_fd = try UserfaultFD.init(.{ .NONBLOCK = true });
    errdefer uf_fd.deinit();

    const norm_len = ((context.offset / page_size) + 1) * page_size;
    const uf_len = if (context.data) |d|
        @max(ceilToPage(d.len - context.offset), ceilToPage(context.size_min))
    else
        ceilToPage(context.size_min);

    const full_chunk = try std.posix.mmap(
        null,
        norm_len + uf_len,
        std.posix.PROT.READ | std.posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        0,
        0,
    );
    errdefer std.posix.munmap(full_chunk);

    if (context.data) |d| {
        @memcpy(full_chunk[norm_len - context.offset .. norm_len], d[0..context.offset]);
    } else {
        @memset(full_chunk[0..norm_len], 0);
    }

    try uf_fd.register(.{ .MISSING = true }, full_chunk[norm_len..full_chunk.len]);

    var page: []u8 = undefined;
    page.ptr = full_chunk.ptr + norm_len - context.offset;
    page.len = if (context.data) |d| d.len else uf_len + context.offset;

    const copy_buf = try gpa.alloc(u8, uf_len);
    errdefer gpa.free(copy_buf);

    @memset(copy_buf, 0);
    if (context.data) |d| {
        @memcpy(copy_buf[0 .. d.len - context.offset], d[context.offset..d.len]);
    }

    const uf_page: []align(page_size) u8 = @alignCast(full_chunk[norm_len..full_chunk.len]);

    return .{
        .page = page,
        .uf_fd = uf_fd,
        .full_chunk = full_chunk,
        .copy_buf = copy_buf,
        .thread = try std.Thread.spawn(
            .{},
            handler,
            .{
                func,
                func_args,
                uf_fd,
                uf_page,
                copy_buf,
            },
        ),
    };
}

pub fn deinit(self: FaultPage, gpa: std.mem.Allocator) void {
    self.thread.join();
    self.uf_fd.deinit();
    std.posix.munmap(self.full_chunk);
    gpa.free(self.copy_buf);
}

fn handler(
    comptime function: anytype,
    args: anytype,
    uf_fd: UserfaultFD,
    fault_page: []align(page_size) u8,
    copy_buf: []u8,
) anyerror!void {
    const poll_fd: std.os.linux.pollfd = .{
        .fd = uf_fd.fd,
        .events = std.os.linux.POLL.IN,
        .revents = 0,
    };
    var arr = [_]std.os.linux.pollfd{poll_fd};

    // TODO: handle polling properly
    if (try std.posix.poll(&arr, -1) != 1)
        @panic("Poll Return Value Incorrect.");

    const ReturnType = @typeInfo(@TypeOf(function)).@"fn".return_type.?;
    if (@typeInfo(ReturnType) != .error_union) {
        @call(.auto, function, args);
    } else {
        try @call(.auto, function, args);
    }

    try uf_fd.copy(fault_page, copy_buf);
}

fn ceilToPage(size: usize) usize {
    return ((size / page_size) + 1) * page_size;
}

/// Written in line with linux kernel v6.14-rc6, however, should be backwards
/// compatible as api hasn't changed. This will detect api incompatibility and
/// will require handling if the kernel adds a new interface.
///
/// See here for source:
/// https://elixir.bootlin.com/linux/v6.14-rc6/source/include/uapi/linux/userfaultfd.h
const UserfaultFD = struct {
    fd: std.posix.fd_t,

    pub fn init(flags: Flags) !UserfaultFD {
        const flags_int: u32 = @bitCast(flags);
        const userfaultfd_res = std.os.linux.syscall1(.userfaultfd, @intCast(flags_int));
        switch (std.posix.errno(userfaultfd_res)) {
            .SUCCESS => {},
            .INVAL => return error.INVAL,
            .MFILE => return error.MFILE,
            .NFILE => return error.NFILE,
            .NOMEM => return error.NOMEM,
            .PERM => return error.PERM,
            else => unreachable,
        }
        const fd: std.posix.fd_t = @intCast(userfaultfd_res);
        errdefer std.posix.close(fd);

        var api: uffdio_api = .{ .api = UFFDIO };
        switch (std.posix.errno(std.os.linux.ioctl(fd, UFFDIO_API, @intFromPtr(&api)))) {
            .SUCCESS => {},
            .FAULT => return error.FAULT,
            .INVAL => return error.INVAL,
            .PERM => return error.PERM,
            else => unreachable,
        }
        if (api.api != UFFDIO) return error.UnexpectedApiVersion;
        // TODO: check ioctls validity

        return .{ .fd = fd };
    }

    pub fn deinit(self: UserfaultFD) void {
        std.posix.close(self.fd);
    }

    pub fn register(self: UserfaultFD, mode: Mode, page: []const u8) !void {
        var reg: uffdio_register = .{
            .range = .{ .start = @intFromPtr(page.ptr), .len = page.len },
            .mode = @bitCast(mode),
        };
        switch (std.posix.errno(std.os.linux.ioctl(self.fd, UFFDIO_REGISTER, @intFromPtr(&reg)))) {
            .SUCCESS => {},
            .BUSY => return error.BUSY,
            .FAULT => return error.FAULT,
            .INVAL => return error.INVAL,
            else => unreachable,
        }
        // TODO: check ioctls validity
    }

    pub fn copy(self: UserfaultFD, dst: []u8, src: []u8) !void {
        const ctx: uffdio_copy = .{
            .dst = @intFromPtr(dst.ptr),
            .src = @intFromPtr(src.ptr),
            .len = src.len,
        };
        switch (std.posix.errno(std.os.linux.ioctl(self.fd, UFFDIO_COPY, @intFromPtr(&ctx)))) {
            .SUCCESS => {},
            .AGAIN => return error.AGAIN,
            .INVAL => return error.INVAL,
            .NOENT => return error.NOENT,
            .NOSPC => return error.NOSPC,
            .SRCH => return error.SRCH,
            else => unreachable,
        }
    }

    pub const Flags = packed struct(u32) {
        UFFD_USER_MODE_ONLY: bool = false,
        pad_0: u10 = 0,
        NONBLOCK: bool = false,
        pad_1: u6 = 0,
        CLOEXEC: bool = false,
        pad_2: u13 = 0,
    };

    const Mode = packed struct(u64) {
        MISSING: bool = false,
        WP: bool = false,
        MINOR: bool = false,
        pad: u61 = 0,
    };

    const UFFDIO: u8 = 0xAA; // API Version

    const uffdio_api = extern struct {
        api: u64,
        features: u64 = 0,
        ioctls: u64 = 0,
    };
    const _UFFDIO_API: u8 = 0x3f; // Api Registration IOCTL op
    const UFFDIO_API = std.os.linux.IOCTL.IOWR(UFFDIO, _UFFDIO_API, uffdio_api);

    const uffdio_range = extern struct { start: u64, len: u64 };
    const uffdio_register = extern struct {
        range: uffdio_range = std.mem.zeroes(uffdio_range),
        mode: u64 = 0,
        ioctls: u64 = 0,
    };
    const _UFFDIO_REGISTER: u8 = 0x00; // Page Registration IOCTL op
    const UFFDIO_REGISTER = std.os.linux.IOCTL.IOWR(UFFDIO, _UFFDIO_REGISTER, uffdio_register);

    const uffdio_copy = extern struct {
        dst: u64 = 0,
        src: u64 = 0,
        len: u64 = 0,
        mode: u64 = 0,
        copy: i64 = 0,
    };
    const _UFFDIO_COPY: u8 = 0x03; // Page Copy IOCTL op
    const UFFDIO_COPY = std.os.linux.IOCTL.IOWR(UFFDIO, _UFFDIO_COPY, uffdio_copy);
};

test "hang on write" {
    const gpa = std.testing.allocator;
    var sem: std.Thread.Semaphore = .{};

    const uf_page = try FaultPage.init(
        gpa,
        .{},
        std.Thread.Semaphore.post,
        .{&sem},
    );
    defer uf_page.deinit(gpa);

    std.debug.assert(sem.permits == 0);
    uf_page.page[0] = 'A';
    std.debug.assert(sem.permits == 1);
}

test "hang on write offset" {
    const gpa = std.testing.allocator;
    var sem: std.Thread.Semaphore = .{};

    const uf_page = try FaultPage.init(
        gpa,
        .{ .offset = 1 },
        std.Thread.Semaphore.post,
        .{&sem},
    );
    defer uf_page.deinit(gpa);

    std.debug.assert(sem.permits == 0);
    uf_page.page[0] = 'A';
    std.debug.assert(sem.permits == 0);
    uf_page.page[1] = 'A';
    std.debug.assert(sem.permits == 1);
}

test "hang on write min size" {
    const gpa = std.testing.allocator;
    var sem: std.Thread.Semaphore = .{};

    const uf_page = try FaultPage.init(
        gpa,
        .{ .size_min = page_size * 2 },
        std.Thread.Semaphore.post,
        .{&sem},
    );
    defer uf_page.deinit(gpa);

    std.debug.assert(sem.permits == 0);
    uf_page.page[page_size] = 'A';
    std.debug.assert(sem.permits == 1);
    uf_page.page[0] = 'A';
    std.debug.assert(sem.permits == 1);
}

test "hang on read" {
    const gpa = std.testing.allocator;
    var sem: std.Thread.Semaphore = .{};

    const uf_page = try FaultPage.init(
        gpa,
        .{ .data = &[_]u8{'A'} },
        std.Thread.Semaphore.post,
        .{&sem},
    );
    defer uf_page.deinit(gpa);

    std.debug.assert(sem.permits == 0);
    std.debug.assert(uf_page.page[0] == 'A');
    std.debug.assert(sem.permits == 1);
}

test "hang on read offset" {
    const gpa = std.testing.allocator;
    var sem: std.Thread.Semaphore = .{};

    const uf_page = try FaultPage.init(
        gpa,
        .{ .data = &[_]u8{'A'} ** 2, .offset = 1 },
        std.Thread.Semaphore.post,
        .{&sem},
    );
    defer uf_page.deinit(gpa);

    std.debug.assert(sem.permits == 0);
    std.debug.assert(uf_page.page[0] == 'A');
    std.debug.assert(sem.permits == 0);
    std.debug.assert(uf_page.page[1] == 'A');
    std.debug.assert(sem.permits == 1);
}

const page_size = std.heap.page_size_min;

const FaultPage = @This();
const std = @import("std");
