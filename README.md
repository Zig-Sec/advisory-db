# Zig-Sec Advisory Database

The Zig-Sec Advisory Database is a repository of security-advisories filed against Zig packages.

The following tools make use of the given database and can be used to audit Zig packages:

- `zat`: The Zig Audit Tool (not released yet)

## Reporting Vulnerabilities

To report a new vulnerability, open a pull request using the template below. 

### Steps

1. Create a file named `ZIGSEC-0000-0000.zon` in the `packages/<fingerprint>` subdirectory of the repository. The fingerprint for a package can be found in its `build.zig.zon`. Please specify the fingerprint without `0x`, e.g. if the fingerprint is `0x1a06b10ba57a349a`, the advisory is placed in `packages/1a06b10ba57a349a/`.
2. Copy and paste the [ZON advisory template](./EXAMPLE_ADVISORY.zon) into the created file. Delete the comments and fill it out with details about the vulnerability. Make sure to describe the vulnerability in detail.
3. Open a [pull request](https://github.com/Zig-Sec/advisory-db/pulls). After being reviewed your advisory will be assigned a unique identifier `ZIGSEC-YYYY-NNNN` and be published to the database.

> The created `.zon` file can be validated using the validate application. It can be build using `zig build`.

### Criteria

The following vulnerabilities qualify for an advisory:

- Code Execution
- Memory Corruption
- Privilege Escalation
- File Disclosure or Directory Traversal
- Web Security (XSS, CSRF, etc.)
- Format Injection (SQL Injection, etc.)
- Cryptography Failure (confidentiality breakage, integrity breakage, authenticity breakage, key leakage)
- Covert Channels (Specter, Meltdown, etc.)
- Denial of Service (especially if used in a web context)

In addition to the qualifiers stated above, the package should have a certain user base, i.e. the
vulnerability actually impacts other packages and users.

## Advisory Format

Advisories are defined using the Zig Object Notation (ZON).

```zon
.{
    // Identifier for the advisory (mandatory) in the format ZIGSEC-YYYY-NNNN,
    // e.g. ZIGSEC-2025-0001 for the first published advisory in the year 2025.
    // Please use ZIGSEC-0000-0000 in pull requests.
    .id = "ZIGSEC-0000-0000", 

    // The name of the affected Zig package (mandatory).
    .package = "mypackage",
    
    // The fingerprint of the affected Zig package (mandatory).
    .fingerprint = 0xec469ac53ee70841,

    // Disclosure date of the advisory as an RFC3339 date (mandatory).
    .date = "2025-01-31",
    
    // A package-url (https://github.com/package-url/purl-spec) for the Zig package (optional).
    //
    // A purl is a URL composed of seven components:
    // ```
    // scheme:type/namespace/name@version?qualifiers#subpath
    // ```
    .purl = "pkg:github/r4gus/mypackage",

    // Whether the advisory is withdrawn (optional).
    //.withdrawn = "YYYY-MM-DD",
    
    // URL to a long-form description of this issue, e.g. a GitHub issue/PR,
    // a change log entry, or a blogpost announcing the release (optional, except
    // for advisories using a license that requires attribution).
    .url = "https://github.com/mystuff/mypackage/issues/123",
    
    // URL to additional helpful references regarding the advisory (optional). 
    .references = .{
        "https://github.com/mystuff/mypackage/discussions/1",
    },
    
    // Optional: the advisory license.
    //.license = .{
    //    // A license identifier (mandatory).
    //    .id = "CC-BY-4.0",
    //    // A reference with a description of the license (optional).
    //    .ref = "https://creativecommons.org/licenses/by/4.0/deed.en",
    //},
    
    // Optional: Indicates the type of informational security advisory 
    // - `unmaintained` for packages that are no longer maintained
    // - `notice` for other informational notices
    .informational = .unmaintained,
    
    // Optional: Categories this advisory falls under. Valid categories are:
    // code_execution, crypto_failure, denial_of_service, file_disclosure
    // format_injection, memory_corruption, memory_exposure, privilege_escalation.
    .categories = .{
        .code_execution,
    },
    
    // Optional: a Common Vulnerability Scoring System score. More information
    // can be found on the CVSS website, https://www.first.org/cvss/.
    //.cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    
    // Freeform keywords which describe this vulnerability.
    .keywords = .{
        "http", "memory"
    },
    
    // Vulnerability aliases, e.g. CVE IDs (optional but recommended)
    //.aliases = .{ "CVE-2025-XXXX" },
    
    // Related vulnerabilities (optional)
    //.related = .{ "CVE-2024-YYYY", "CVE-2018-ZZZZ" },
    
    // Optional: metadata which narrows the scope of what this advisory affects
    .affected = .{
        // CPU architectures impacted by this vulnerability (optional).
        // For a list of CPU architectures run `zig targets`.
        .arch = .{ "x86", "x86_64"},  
        
        // Operating systems impacted by this vulnerability (optional)
        // For a list of operating systems run `zig targets`.
        //.os = .{ "windows" },
    },
    
    // Versions which include fixes for this vulnerability (mandatory).
    // Those are [Semantic Versions](https://semver.org/).
    // Use `.patched = .{}` e.g. in case of unmaintained where there is no fix.
    .versions = .{
        .patched = .{">= 1.2.0"},
        
        // Versions which were never vulnerable (optional).
        //.unaffected = .{"< 1.1.0"},
    },
    
    // A short description of the issue.
    .description = "Your short description here",
    
    // A long desctiption of the issue in [Markdown](https://www.markdownguide.org/)
    // format (mandatory).
    .detail = "Your description here.",
    
    // Recommendations (optional but recommended).
    .recommended = "You should do XYZ",
}
```

## FAQ

_Q: Do I need to be the owner of a package to file an advisory?_

A: No, anyone can file an advisory against a package. Make sure the package has a certain reach and describe the vulnerability in detail. We must be able to validate the vulnerability in order to merge it.

_Q: Is this the official way to report vulnerabilities for Zig packages?_

A: There are many ways to report vulnerabilities for software including the [GitHub Advisory Database](https://github.com/advisories) and the [Open Source Vulnerabilities Database](https://osv.dev/). This is just another way inspired by [RustSEC](https://rustsec.org/) and dedicated specifically to Zig packages.

## License

All content in this repository is published in the public domain, except otherwise specified.

Advisories published under a different domain contain a license field specifying the license.
