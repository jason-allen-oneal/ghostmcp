# Changelog

## 0.2.0 — 2026-07-25

- Added a versioned tool manifest with risk, capability, target-field, routing, availability, and sensitive-output metadata.
- Added expiring per-engagement policy files with target narrowing and approval provenance.
- Reclassified credential access, remote execution, and broad enumeration tools as intrusive.
- Enforced effective targets from tool arguments, filesystem roots, resource allowlists, capability allowlists, target cardinality, and dashboard execution scope.
- Made Tor and proxy routing fail closed when the requested wrapper is unavailable.
- Bounded subprocess output while processes run and isolated child process groups.
- Required TLS for non-loopback bearer-token transport and explicit trusted-TLS-proxy acknowledgement for non-loopback dashboards.
- Added machine-readable health checks, scope/approval audit fields, and regression coverage for the hardened policy paths.
- Raised dependency floors and regenerated hash locks to exclude known-vulnerable MCP and IDNA releases.
