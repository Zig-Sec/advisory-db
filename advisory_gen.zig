const std = @import("std");
const Advisory = @import("src/Advisory.zig");

pub fn main() !void {
    var allocator = std.heap.page_allocator;

    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // TODO: sort this
    var advisories_page = std.ArrayList(u8).init(arena);
    defer advisories_page.deinit();
    try advisories_page.appendSlice(alladvisories_template);

    const alladvisories = std.fs.cwd().openDir("content/advisories", .{
        .iterate = true,
    }) catch |err| {
        fatal("unable to open '{s}': {s}", .{ "content/advisories", @errorName(err) });
    };

    var packages = std.fs.cwd().openDir("packages", .{
        .iterate = true,
    }) catch |err| {
        fatal("unable to open '{s}': {s}", .{ "packages", @errorName(err) });
    };

    var walker = try packages.walk(arena);
    while (try walker.next()) |d| {
        var adv_iter = d.dir.iterate();
        while (try adv_iter.next()) |f| {
            if (f.kind == .file) {
                var adv = try d.dir.openFile(f.name, .{});
                defer adv.close();

                const content = try adv.readToEndAlloc(allocator, 50_000_000);
                defer allocator.free(content);

                const s = try allocator.dupeZ(u8, content);
                defer allocator.free(s);

                const advisory = try std.zon.parse.fromSlice(
                    Advisory,
                    allocator,
                    s,
                    null,
                    .{ .ignore_unknown_fields = true },
                );
                defer advisory.deinit(allocator);

                alladvisories.makeDir(advisory.id) catch {};
                var adv_dir = try alladvisories.openDir(advisory.id, .{});
                defer adv_dir.close();

                var adv_file = try adv_dir.createFile("index.smd", .{});
                defer adv_file.close();

                var categories = std.ArrayList(u8).init(allocator);
                defer categories.deinit();
                if (advisory.categories) |cats| {
                    for (cats) |cat| {
                        try categories.writer().print("`{s}` ", .{cat.toString()});
                    }
                }

                var keywords = std.ArrayList(u8).init(allocator);
                defer keywords.deinit();
                if (advisory.keywords) |words| {
                    for (words) |word| {
                        try keywords.writer().print("`{s}` ", .{word});
                    }
                }

                var patched = std.ArrayList(u8).init(allocator);
                defer patched.deinit();
                for (advisory.versions.patched) |p| {
                    try patched.writer().print("`{s}` ", .{p});
                }

                var package = std.ArrayList(u8).init(allocator);
                defer package.deinit();
                if (advisory.url) |url| {
                    try package.writer().print("[{s}]({s})", .{ advisory.package, url });
                } else {
                    try package.appendSlice(advisory.package);
                }

                try adv_file.writer().print(
                    template,
                    .{
                        advisory.id,
                        advisory.date,
                        package.items,
                        if (advisory.informational) |_| "Informational" else "Vulnerability",
                        categories.items,
                        patched.items,
                        advisory.description,
                        advisory.detail,
                        if (advisory.recommended) |rec| rec else "n.a.",
                    },
                );

                // ---------------------
                // TODO: make a temporary sorted list before writing this to file
                // ---------------------
                try advisories_page.appendSlice(advisory.date);
                try advisories_page.appendSlice("\n\n");
                try advisories_page.writer().print("[{s}]($link.page('advisories/{s}'))", .{ advisory.id, advisory.id });
                try advisories_page.appendSlice("\n\n");
                try advisories_page.appendSlice(advisory.description);
                try advisories_page.appendSlice("\n\n---\n\n");
            }
        }
    }

    var advisories_file = try std.fs.cwd().createFile("content/advisories/index.smd", .{});
    defer advisories_file.close();
    try advisories_file.writeAll(advisories_page.items);
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.debug.print(format, args);
    std.process.exit(1);
}

const template =
    \\---
    \\.title = "{s}",
    \\.date = @date("2025-04-21T00:00:00"),
    \\.author = "Zig-Sec",
    \\.layout = "index.shtml",
    \\.draft = false,
    \\--- 
    \\
    \\ |       |          |
    \\ |:------|---------:|
    \\| **Reported** | {s} |
    \\| **Package** | {s} |
    \\| **Type** | {s} |
    \\| **Categories** | {s} |
    \\| **Patched** | {s} |
    \\
    \\## Description
    \\{s}
    \\
    \\{s}
    \\
    \\## Recommendations
    \\{s}
;

const alladvisories_template =
    \\---
    \\.title = "Advisories",
    \\.date = @date("2025-04-21T00:00:00"),
    \\.author = "Zig-Sec",
    \\.layout = "index.shtml",
    \\.draft = false,
    \\--- 
    \\
    \\
;
