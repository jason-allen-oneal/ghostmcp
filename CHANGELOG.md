# Changelog

## 0.2.0

Security-boundary release.

### Added

- Versioned tool manifest with risk, capability, target, routing, availability,
  and sensitive-output metadata.
- Mode-`0600`, expiring per-engagement execution-policy files and audit scope
  digests.
- Central effective-argument validation for hosts, domains, URLs, CIDRs,
  ranges, filesystem paths, resources, and raw argv.
- Transport-level bearer authentication and TLS requirements for non-loopback
  remote use.
- Dashboard authentication, cross-origin write protection, and response
  security headers.
- Distribution-content verification and aligned GitHub/Forgejo release gates.

### Changed

- Raw tools are disabled by default and require explicit raw capability plus a
  policy-backed intrusive engagement.
- Intrusive tools fail closed without a versioned engagement policy.
- Proxy wrappers fail closed instead of silently executing directly.
- Dangerous structured wrappers use conservative intrusive risk levels.
- Credential, database, and audit files use restrictive permissions.
- Subprocess environments are minimized; commands, output, targets, and
  persisted scan data are redacted.
- Remote unauthenticated transport is no longer supported.

### Fixed

- Raw-argv destination bypasses.
- Domain-key bypasses of address policy.
- Placeholder masscan range validation.
- Redirect scope validation for native HTTP requests.
- SQLite queries returning cursors after their connection closed.
- Concurrent audit writes and incompatible audit hash verification.
- Missing parser, template, and static files in built distributions.
- Root-running container image that contradicted runtime policy.
