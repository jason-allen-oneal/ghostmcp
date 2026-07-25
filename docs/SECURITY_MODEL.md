# GhostMCP execution security model

GhostMCP enforces its own execution boundary even when the calling client is
trusted. A higher-level orchestrator may narrow this boundary but cannot
replace it.

## Tool manifest

`tool_manifest_tool` returns schema version `1.0` with, for every tool:

- risk: `passive`, `active`, or `intrusive`;
- capabilities such as `discovery`, `collection`, `credential_access`,
  `remote_execution`, and `raw_execution`;
- effective target fields;
- routing support;
- availability and raw-tool status;
- sensitive-output classification.

Clients must reject unsupported manifest schema versions. Tool-name substring
inference is not an authorization mechanism.

## Engagement policy

Set `GHOSTMCP_ENGAGEMENT_POLICY_FILE` to a JSON file owned by the GhostMCP
service user and mode `0600`. The file uses this shape:

```json
{
  "schema_version": "1.0",
  "engagements": {
    "engagement-identifier": {
      "expires_at": "2027-01-01T00:00:00Z",
      "max_tool_level": "active",
      "allowed_capabilities": ["discovery"],
      "allowed_cidrs": ["192.0.2.0/28"],
      "allowed_domains": ["authorized.example"],
      "allowed_paths": ["/srv/authorized-evidence"],
      "forbidden_paths": ["/srv/authorized-evidence/private"],
      "allowed_resources": ["authorized-bucket"],
      "require_routed_execution": false,
      "authorization": {
        "approval_id": "approval-identifier",
        "approved_by": "operator-identifier",
        "approved_at": "2026-01-01T00:00:00Z",
        "reason": "Authorized assessment plan"
      }
    }
  }
}
```

Each scope is canonicalized and hashed. Its digest is included in audit
events. Engagement policy may narrow global server policy but cannot broaden
it. Missing target classes fail closed.

Policies granting intrusive risk, collection, credential access, raw
execution, or remote execution must include authorization provenance. The
approval identifier and approver identifier are copied into the audit chain.

Intrusive tools require a policy-backed `engagement_id` by default.
`GHOSTMCP_ALLOW_UNSCOPED_INTRUSIVE=true` exists only for controlled migration
and should not be used in production.

## Raw tools

Raw wrappers are disabled by default. Enabling them requires all of:

1. `GHOSTMCP_ALLOW_RAW_TOOLS=true`;
2. `raw_execution` in allowed capabilities;
3. an intrusive engagement policy;
4. a recognizable effective network target or an explicitly allowed path;
5. argument count, length, character, and option-policy validation.

Prefer structured wrappers. Raw syntax that cannot be interpreted is rejected.

## Routing

Proxy modes fail closed when their enforcement wrapper is missing. `tor` uses
`torsocks` or `proxychains`; environment proxy variables alone are not treated
as proof that an external security tool is routed.

When `GHOSTMCP_REQUIRE_ROUTED_EXECUTION=true`, tools marked `direct_only` are
denied. This is preferable to quietly leaking traffic into the ordinary
network.

## Remote transport and dashboard

- Remote MCP transport never supports unauthenticated mode.
- Bearer authentication is enforced at the HTTP transport, not exposed as a
  model tool argument.
- Non-loopback bearer transport requires TLS certificate and key files.
- mTLS remains the recommended remote deployment.
- The dashboard stays locked until Basic or bearer credentials are configured.
- Non-loopback dashboard binding requires a trusted TLS reverse proxy.

## Stored material

Credential stores are encrypted by default. SQLite databases and audit sinks
are created with mode `0600`. Commands, outputs, errors, targets, and database
payloads receive conservative secret redaction before persistence or exposure.

Redaction reduces accidental disclosure; it is not a substitute for host
filesystem permissions, retention controls, or encrypted storage volumes.
