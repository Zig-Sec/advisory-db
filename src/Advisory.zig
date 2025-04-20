const std = @import("std");

id: []const u8,
package: []const u8,
fingerprint: u64,
date: []const u8,
purl: ?[]const u8 = null,
url: ?[]const u8 = null,
references: ?[]const []const u8 = null,
license: ?License = null,
informational: ?Informational = null,
categories: ?[]const Category = null,
cvss: ?[]const u8 = null,
keywords: ?[]const []const u8 = null,
aliases: ?[]const []const u8 = null,
related: ?[]const []const u8 = null,
affected: ?Affected = null,
versions: Versions,
description: []const u8,
detail: []const u8,
recommended: ?[]const u8 = null,

pub const License = struct {
    id: []const u8,
    ref: ?[]const u8 = null,
};

pub const Informational = enum {
    unmaintained,
    notice,
};

pub const Category = enum {
    code_execution,
    crypto_failure,
    denial_of_service,
    file_disclosure,
    format_injection,
    memory_corruption,
    memory_exposure,
    privilege_escalation,
};

pub const Affected = struct {
    arch: ?[]const []const u8 = null,
    os: ?[]const []const u8 = null,
};

pub const Versions = struct {
    patched: []const []const u8,
    unaffected: ?[]const []const u8 = null,
};

pub fn vulnerable(self: *const @This(), v: std.SemanticVersion) bool {
    // TODO: this is just a very simplistic approach
    for (self.versions.patched) |v2_| {
        if (std.mem.containsAtLeast(u8, v2_, 1, ">= ")) {
            const v2 = std.SemanticVersion.parse(v2_[3..]) catch continue;
            if (v.major < v2.major) continue;
            if (v.major == v2.major and v.minor < v2.minor) continue;
            if (v.major == v2.major and v.minor == v2.minor and v.patch < v2.patch) continue;

            return false;
        } else {
            const v2 = std.SemanticVersion.parse(v2_) catch continue;
            if (v2.major == v.major and v2.minor == v.minor and v2.patch == v.patch) return false;
        }
    }

    return true;
}
