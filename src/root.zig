const std = @import("std");

pub const Advisory = @import("Advisory.zig");

test {
    _ = Advisory;
}

test "find affected version #1" {
    const adv: Advisory =
        .{
            .id = "ZIGSEC-2025-0001",
            .package = "zbor",
            .fingerprint = 0x32fbe7d2a082bf92,
            .date = "2025-03-16",
            .purl = "pkg:github/r4gus/zbor",
            .categories = &.{
                .memory_corruption,
            },
            .keywords = &.{ "cbor", "memory" },
            .versions = .{
                .patched = &.{">= 0.16.1"},
            },
            .description = "This is the first advisory published to zig-sec/advisory-db.",
            .detail = "This advisory does not describe a real vulnerability.",
            .recommended = "Don't worry! But you should upgrade anyway as a new zbor release is available.",
        };

    try std.testing.expect(adv.vulnerable(try std.SemanticVersion.parse("0.15.0")));
    try std.testing.expect(adv.vulnerable(try std.SemanticVersion.parse("0.1.0")));
    try std.testing.expect(adv.vulnerable(try std.SemanticVersion.parse("0.1.9")));
    try std.testing.expect(adv.vulnerable(try std.SemanticVersion.parse("0.16.0")));
    try std.testing.expect(adv.vulnerable(try std.SemanticVersion.parse("0.16.2")) == false);
    try std.testing.expect(adv.vulnerable(try std.SemanticVersion.parse("0.17.0")) == false);
    try std.testing.expect(adv.vulnerable(try std.SemanticVersion.parse("1.0.0")) == false);
}
