const std = @import("std");

pub fn hi() i32 {
    std.debug.print("hi\n", .{});
}
