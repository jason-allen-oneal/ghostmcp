# Security operations

This guide describes how to operate GhostMCP safely. It does not replace written authorization, rules of engagement, legal review, or organizational security policy.

## Threat model

GhostMCP sits between an MCP client and security-sensitive capabilities. Relevant threats include:

- A compromised or misdirected model requesting out-of-scope actions
- An unauthorized network client reaching the remote gateway or dashboard
- DNS answers or redirects that move a request outside approved scope
- Dangerous raw-tool arguments or unexpected installed binaries
- Malicious or compromised plugins
- Credential leakage through command lines, logs, errors, or return values
- Audit-log modification
- Dashboard cross-site request forgery or stored script injection
- Filesystem traversal through file-backed tools
- Duplicate scheduled execution
- Excessive privilege in the service account or container

The hardened runtime reduces these risks through layered controls. No single control should be treated as sufficient.

## Authorization boundary

Before an engagement, record:

- Engagement owner
- Written authorization source
- Start and end dates
- Permitted CIDRs and domains
- Permitted ports and protocols
- Maximum tool level
- Approved credentials
- Approved scanners and plugins
- Data handling and retention requirements
- Emergency contact and stop conditions

GhostMCP stores technical scope and status. Keep the signed authorization package in the organization's normal records system.

## Scope controls

Recommended baseline:

```bash
GHOSTMCP_ALLOW_PRIVATE_ONLY=true
GHOSTMCP_ALLOWED_CIDRS=10.40.0.0/16
GHOSTMCP_ALLOWED_DOMAINS=lab.example.internal
GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT=true
GHOSTMCP_MAX_TOOL_LEVEL=active
GHOSTMCP_ALLOW_UNSCOPED_INTRUSIVE=false
```

Scope validation applies to literal addresses, DNS results, URLs, masscan expressions, CIDRs, and explicit address ranges. A hostname with any prohibited resolved address is rejected.

Avoid broad scopes such as `10.0.0.0/8` when a smaller subnet is known. Do not use public targets unless private-only mode has been deliberately disabled and an explicit CIDR or domain allowlist is configured.

## Tool levels

- `passive`: intended to avoid direct intrusive interaction
- `active`: direct probing or bounded scanning
- `intrusive`: behavior with greater operational or authentication impact

The global ceiling and engagement ceiling both apply. The `engagement_mode` tool argument is a requested ceiling, not authorization. Intrusive and sensitive calls require a policy-backed scope with approval provenance unless the explicit unsafe compatibility override is enabled.

Use [`engagement-policy.example.json`](../engagement-policy.example.json) as a schema example. Keep the real file mode `0600`, replace the example timestamps and identifiers, and grant only the capabilities and targets required by the engagement.

## Raw wrappers

Raw wrappers expose the largest extension surface and are disabled by default.

Enable only reviewed binaries:

```bash
GHOSTMCP_ENABLE_RAW_TOOLS=true
GHOSTMCP_RAW_TOOL_ALLOWLIST=nmap,testssl.sh
```

Review:

- Every accepted flag and argument pattern
- Whether the tool can write files or execute helpers
- Whether it reads environment credentials or home-directory configuration
- Network and authentication side effects
- Timeout and output behavior
- How secrets appear in process listings and logs

Do not expose shells, package managers, interpreters, remote administration clients, or general-purpose file utilities as raw wrappers.

## Plugins

Plugins execute in process. A plugin compromise is a GhostMCP compromise.

- Keep plugins disabled unless required.
- Allowlist exact entry-point names.
- Pin distributions and hashes.
- Review source and dependencies.
- Test policy, file-root, timeout, redaction, and collision behavior.
- Rebuild the environment after adding or removing a plugin.

See [Plugin development](PLUGINS.md).

## Remote transport

Local stdio is preferred when the MCP client and server can run on the same host.

For remote mode:

- Use mTLS when possible.
- Otherwise use a long random bearer token.
- Bind to loopback or an internal interface.
- Restrict the port with a firewall or private overlay.
- Terminate HTTPS at a trusted proxy only with a loopback backend, or configure direct TLS.
- Preserve and validate the `Authorization` header.
- Do not enable unauthenticated remote mode.

Token authentication is enforced before MCP dispatch. Tokens are not tool arguments.

## Dashboard security

- Use a distinct dashboard token.
- Bind to loopback by default.
- Enable secure cookies only behind HTTPS.
- Preserve original host and scheme through reverse proxies.
- Keep same-origin mutation checks enabled.
- Restrict file-backed tools with `GHOSTMCP_ALLOWED_PATHS`.
- Run one dashboard instance for the beta release.

The dashboard renders escaped report values and sends security headers, but operators should still avoid placing untrusted HTML or secrets into engagement descriptions and findings.

## Credential handling

Credential storage is disabled by default.

Preferred order:

1. External secret manager with short-lived service identity
2. Encrypted local store with a file-mounted key
3. Encrypted local store with a password supplied through a protected service environment
4. Plaintext only in isolated disposable testing

Protect:

- Credential store
- Salt file
- Key file
- Provider tokens
- Service identity files
- Backups

Do not pass credentials in target URLs. Avoid tools that require secrets directly in command-line arguments when a safer mechanism is available. GhostMCP redacts recognized credential arguments from results, but operating-system process inspection may still expose arguments while a child process is running.

## Audit integrity

For production:

```bash
GHOSTMCP_AUDIT_SINK_PATH=/var/log/ghostmcp/audit.jsonl
GHOSTMCP_AUDIT_HMAC_KEY_FILE=/etc/ghostmcp/audit-hmac.key
GHOSTMCP_AUDIT_FSYNC=true
```

Operational controls:

- Store the HMAC key separately from the log.
- Restrict file permissions.
- Forward audit output to centralized or append-only storage.
- Verify the chain regularly and after incidents.
- Alert on verification failure.
- Preserve the original JSON event order.
- Rotate logs without truncating an active event or losing chain state.

A hash chain without an independently protected HMAC key detects accidental corruption and many edits, but it does not prevent an attacker with full write access from rebuilding the chain.

## Filesystem controls

Use absolute paths for database, audit, credential, and file-root settings. Separate directories by purpose:

```text
/etc/ghostmcp       root-owned configuration and keys
/var/lib/ghostmcp   database and durable state
/var/log/ghostmcp   audit and service logs
/srv/assessments    approved input and output files
```

Run with a read-only system or container filesystem where possible. Grant write access only to the state, log, and approved assessment directories.

## Process privileges

Run as a dedicated non-root user. Keep `GHOSTMCP_ALLOW_RUN_AS_ROOT=false`.

If a scanner needs raw sockets or another elevated capability:

- Grant the narrow Linux capability to that binary.
- Use a dedicated helper service.
- Restrict the helper with its own policy and authentication.
- Do not elevate the entire GhostMCP process.

Drop container capabilities and enable `no-new-privileges`.

## Network egress

Limit egress to authorized target networks, DNS resolvers, secret-manager endpoints, and required update sources. Application scope checks are not a replacement for network enforcement.

Proxy and Tor modes change routing, not authorization. Configured routing fails closed when its wrapper is unavailable. `GHOSTMCP_REQUIRE_ROUTED_EXECUTION=true` also denies direct-only tools. Routing must not be used to conceal unauthorized activity or bypass network controls.

## Dependency and image security

- Install from committed hash-locked requirements.
- Run dependency auditing in CI.
- Rebuild images regularly to receive base-image fixes.
- Scan the final image, not only source dependencies.
- Keep GitHub Actions pinned by commit SHA.
- Review SBOM and provenance artifacts for releases.

The CI policy rejects high and critical fixed vulnerabilities found by Trivy.

## Scheduling risk

Scheduled execution can outlive the human context in which it was created.

Before enabling a schedule:

- Confirm engagement dates include every future run.
- Confirm scope and credentials remain valid.
- Use UTC explicitly.
- Set a review or removal date outside GhostMCP.
- Monitor failed and duplicate claims.

SQLite leases prevent duplicate claims across cooperating instances, but the in-process queue is not crash durable.

## Incident containment

If unauthorized execution or credential exposure is suspected:

1. Stop the gateway and dashboard.
2. Block network access.
3. Preserve database, audit, logs, configuration, and process evidence.
4. Revoke transport and dashboard tokens.
5. Revoke secret-manager identities and stored credentials.
6. Disable raw wrappers and plugins.
7. Verify the audit chain from the last trusted checkpoint.
8. Rebuild from a trusted commit and lock set.
9. Rotate all keys before restoring service.
10. Notify target owners and follow the engagement incident process.

See the [Operations runbook](RUNBOOK.md) for detailed recovery and upgrade steps.

## Security review checklist

Before production use:

- [ ] Written authorization is current.
- [ ] CIDRs and domains are narrowly scoped.
- [ ] Global maximum tool level is appropriate.
- [ ] Intrusive/sensitive engagements have unexpired policy records and approval provenance.
- [ ] Capability, filesystem, resource, and target-address ceilings are narrow.
- [ ] Remote and dashboard authentication are tested.
- [ ] Public binding is avoided or protected.
- [ ] Raw-wrapper allowlist is reviewed.
- [ ] Plugin allowlist is reviewed.
- [ ] Credential backend is explicitly selected.
- [ ] Database and audit paths are absolute and protected.
- [ ] Audit HMAC key is separate from the log.
- [ ] File roots exclude code, configuration, keys, and system paths.
- [ ] Service runs as non-root.
- [ ] Egress controls match engagement scope.
- [ ] Dependency, CodeQL, and container scans are green.
- [ ] Backup and restore have been tested.
- [ ] Stop conditions and incident contacts are documented.
