const std = @import("std");
const Advisory = @import("Advisory.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    if (!args.skip()) return error.InvalidNumberOfArguments;

    const path = args.next() orelse return error.InvalidNumberOfArguments;

    var f = try std.fs.openFileAbsolute(path, .{});
    defer f.close();

    const s_ = try f.readToEndAlloc(allocator, 50_000_000);
    defer allocator.free(s_);

    const s = try allocator.dupeZ(u8, s_);
    defer allocator.free(s);

    const advisory = try std.zon.parse.fromSlice(
        Advisory,
        allocator,
        s,
        null,
        .{ .ignore_unknown_fields = true },
    );
    _ = advisory;
}
