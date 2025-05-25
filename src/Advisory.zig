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

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.id);
    allocator.free(self.package);
    allocator.free(self.date);
    if (self.purl) |v| allocator.free(v);
    if (self.url) |v| allocator.free(v);
    if (self.references) |v| {
        for (v) |v2| allocator.free(v2);
        allocator.free(v);
    }
    if (self.license) |v| {
        allocator.free(v.id);
        if (v.ref) |ref| allocator.free(ref);
    }
    if (self.categories) |v| allocator.free(v);
    if (self.cvss) |v| allocator.free(v);
    if (self.keywords) |v| {
        for (v) |v2| allocator.free(v2);
        allocator.free(v);
    }
    if (self.aliases) |v| {
        for (v) |v2| allocator.free(v2);
        allocator.free(v);
    }
    if (self.related) |v| {
        for (v) |v2| allocator.free(v2);
        allocator.free(v);
    }
    if (self.affected) |v| {
        if (v.arch) |arch| {
            for (arch) |a| allocator.free(a);
            allocator.free(arch);
        }
        if (v.os) |os| {
            for (os) |o| allocator.free(o);
            allocator.free(os);
        }
        if (v.functions) |funcs| {
            for (funcs) |o| allocator.free(o);
            allocator.free(funcs);
        }
    }
    for (self.versions.patched) |p| allocator.free(p);
    allocator.free(self.versions.patched);
    if (self.versions.unaffected) |u| {
        for (u) |u_| allocator.free(u_);
        allocator.free(u);
    }
    allocator.free(self.description);
    allocator.free(self.detail);
    if (self.recommended) |r| allocator.free(r);
}

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

    pub fn toString(self: @This()) []const u8 {
        return switch (self) {
            .code_execution => "code-execution",
            .crypto_failure => "crypto-failure",
            .denial_of_service => "denial-of-service",
            .file_disclosure => "file-disclosure",
            .format_injection => "format-injection",
            .memory_corruption => "memory-corruption",
            .memory_exposure => "memory-exposure",
            .privilege_escalation => "privilege-escalation",
        };
    }
};

pub const Affected = struct {
    arch: ?[]const []const u8 = null,
    os: ?[]const []const u8 = null,
    functions: ?[]const []const u8 = null,
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
