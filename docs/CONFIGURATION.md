# Configuration reference

GhostMCP is configured through environment variables prefixed with `GHOSTMCP_`. Start from [`.env.example`](../.env.example), then keep production secrets in an environment file readable only by the service account or in an external secret manager.

Boolean settings accept `true`, `false`, `1`, `0`, `yes`, `no`, `on`, and `off`. Invalid values fail startup rather than silently falling back.

## Logging and rate limits

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_LOG_LEVEL` | `INFO` | Runtime logging level |
| `GHOSTMCP_LOG_FORMAT` | `json` | Structured log format |
| `GHOSTMCP_RATE_LIMIT_CALLS` | `120` | Maximum calls per rate-limit window |
| `GHOSTMCP_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window length |

## Scope policy

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_ALLOW_PRIVATE_ONLY` | `true` | Reject targets outside private, loopback, link-local, and unique-local networks |
| `GHOSTMCP_ALLOWED_CIDRS` | empty | Optional comma-separated CIDR allowlist applied in addition to private-only policy |
| `GHOSTMCP_ALLOWED_DOMAINS` | empty | Optional comma-separated domain and subdomain allowlist |
| `GHOSTMCP_BLOCKED_PORTS` | `22,2375,2376,3389` | Ports denied even when the target is otherwise in scope |
| `GHOSTMCP_MAX_PORTS_PER_SCAN` | `256` | Maximum unique ports in a guarded scan |
| `GHOSTMCP_CONNECT_TIMEOUT_MS` | `1500` | Per-connection timeout |
| `GHOSTMCP_MAX_CONCURRENT_CONNECTS` | `64` | Maximum concurrent connection attempts |
| `GHOSTMCP_MAX_TARGET_ADDRESSES` | `4096` | Maximum combined addresses in a network/range target expression |
| `GHOSTMCP_USER_AGENT` | `GhostMCP/0.2` | User agent for internal HTTP requests |

All resolved addresses must pass policy. A hostname that resolves to a mix of permitted and prohibited addresses is rejected. Literal IP URLs and masscan CIDRs or ranges are validated through the same policy model.

Example restricted lab scope:

```bash
export GHOSTMCP_ALLOW_PRIVATE_ONLY=true
export GHOSTMCP_ALLOWED_CIDRS=10.40.0.0/16
export GHOSTMCP_ALLOWED_DOMAINS=lab.example.internal
export GHOSTMCP_BLOCKED_PORTS=22,2375,2376,3389
```

## Engagement and execution levels

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT` | `true` | Require `engagement_id` on guarded tool calls |
| `GHOSTMCP_MAX_TOOL_LEVEL` | `active` | Global ceiling: `passive`, `active`, or `intrusive` |
| `GHOSTMCP_ALLOWED_CAPABILITIES` | all known capabilities | Comma-separated capability ceiling |
| `GHOSTMCP_ENGAGEMENT_POLICY_FILE` | empty | Mode-`0600` JSON policy file used to authorize and narrow engagements |
| `GHOSTMCP_ALLOW_UNSCOPED_INTRUSIVE` | `false` | Unsafe compatibility override for intrusive calls without policy provenance |
| `GHOSTMCP_MAX_PASSIVE_PARALLEL` | implementation default | Parallel limit for passive tools |
| `GHOSTMCP_MAX_ACTIVE_PARALLEL` | implementation default | Parallel limit for active tools |
| `GHOSTMCP_MAX_INTRUSIVE_PARALLEL` | implementation default | Parallel limit for intrusive tools |

A tool call must pass the global ceiling, capability ceiling, effective-target checks, and engagement-specific ceiling. Keep the global ceiling at `active` unless an authorized engagement explicitly requires intrusive behavior.

An intrusive or sensitive policy entry requires:

- an unexpired `expires_at`
- `max_tool_level` and `allowed_capabilities`
- at least one explicit CIDR, domain, filesystem path, or resource
- `authorization.approval_id`, `approved_by`, `approved_at`, and `reason`

The policy file must be owned by the GhostMCP service user and have mode `0600`. Start from [`engagement-policy.example.json`](../engagement-policy.example.json). Empty engagement capability lists deny every tool; they do not mean unlimited access.

## Filesystem and resource scope

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_ALLOWED_PATHS` | empty | Platform-path-separated roots permitted for file-backed tools |
| `GHOSTMCP_FORBIDDEN_PATHS` | empty | Platform-path-separated deny roots applied after allowlisting |
| `GHOSTMCP_ALLOWED_RESOURCES` | empty | Comma-separated non-filesystem resources such as approved bucket names |

`GHOSTMCP_ALLOWED_FILE_ROOTS` remains a compatibility alias for `GHOSTMCP_ALLOWED_PATHS`. If neither is set, filesystem-backed tools fail closed.

## Routed execution

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_REQUIRE_ROUTED_EXECUTION` | `false` | Deny tools that cannot honor the selected routing policy |
| `GHOSTMCP_PROXY_MODE` | `none` | `none`, `tor`, `proxychains`, or `torsocks` |
| `GHOSTMCP_TOR_HOST` | `127.0.0.1` | Tor SOCKS host used for proxy-aware HTTP clients |
| `GHOSTMCP_TOR_PORT` | `9050` | Tor SOCKS port |

Requested routing never silently falls back to direct execution. Startup fails if required wrappers are missing, and direct-only tools are denied when routed execution is mandatory.

## Raw wrappers

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_ENABLE_RAW_TOOLS` | `false` | Enables the raw-wrapper registration path |
| `GHOSTMCP_RAW_TOOL_ALLOWLIST` | empty | Comma-separated binary names that may be exposed |
| `GHOSTMCP_MAX_RAW_ARG_COUNT` | `24` | Maximum raw argument count |
| `GHOSTMCP_MAX_RAW_ARG_LENGTH` | `256` | Maximum length of one raw argument |
| `GHOSTMCP_MAX_RAW_RUNTIME_SECONDS` | `180` | Maximum process runtime |
| `GHOSTMCP_MAX_RAW_STDOUT_BYTES` | `20000` | Captured stdout limit |
| `GHOSTMCP_MAX_RAW_STDERR_BYTES` | `8000` | Captured stderr limit |

Both enablement and allowlisting are required:

```bash
export GHOSTMCP_ENABLE_RAW_TOOLS=true
export GHOSTMCP_RAW_TOOL_ALLOWLIST=nmap,testssl.sh
```

Do not use broad or generated allowlists. Review each binary's flags, side effects, credential handling, and filesystem behavior before exposure.

## Plugins

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_ENABLE_PLUGINS` | `false` | Enables external entry-point loading |
| `GHOSTMCP_PLUGIN_GROUP` | `ghostmcp.plugins` | Python entry-point group |
| `GHOSTMCP_PLUGIN_ALLOWLIST` | empty | Comma-separated entry-point names allowed to load |

Plugin packages execute inside the GhostMCP process. Treat them as trusted code and pin their distributions and hashes.

## Transport

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_TRANSPORT_MODE` | `stdio` | `stdio` or `remote_gateway` |
| `GHOSTMCP_AUTH_MODE` | `none` | `none`, `token`, or `mtls` |
| `GHOSTMCP_AUTH_TOKEN` | empty | Bearer token required by token mode |
| `GHOSTMCP_ALLOW_INSECURE_REMOTE_NO_AUTH` | `false` | Explicit unsafe override for unauthenticated remote mode |
| `GHOSTMCP_HTTP_HOST` | `127.0.0.1` | Remote HTTP bind address |
| `GHOSTMCP_HTTP_PORT` | `8000` | Remote HTTP port |
| `GHOSTMCP_UVICORN_LOG_LEVEL` | `info` | Uvicorn log level |
| `GHOSTMCP_MTLS_CA_CERT_PATH` | empty | Trusted client CA path |
| `GHOSTMCP_MTLS_CERT_PATH` | empty | Server certificate path |
| `GHOSTMCP_MTLS_KEY_PATH` | empty | Server private-key path |
| `GHOSTMCP_TLS_CERT_PATH` | empty | TLS certificate for non-loopback bearer-token transport |
| `GHOSTMCP_TLS_KEY_PATH` | empty | TLS private key for non-loopback bearer-token transport |

Token-mode clients send `Authorization: Bearer <token>`. Authentication is enforced at the HTTP transport before MCP dispatch. A non-loopback token listener requires a TLS certificate and key.

Do not set `GHOSTMCP_ALLOW_INSECURE_REMOTE_NO_AUTH=true` outside isolated development. Prefer mTLS for network-accessible deployments.

## Dashboard and scheduler

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_DASHBOARD_HOST` | `127.0.0.1` | Dashboard bind address |
| `GHOSTMCP_DASHBOARD_PORT` | `8080` | Dashboard port |
| `GHOSTMCP_DASHBOARD_TOKEN` | empty | Required dashboard bearer or login token |
| `GHOSTMCP_DASHBOARD_SECURE_COOKIE` | `false` | Marks the dashboard cookie Secure; enable behind HTTPS |
| `GHOSTMCP_DASHBOARD_ALLOW_UNAUTHENTICATED` | `false` | Explicit unsafe testing override |
| `GHOSTMCP_DASHBOARD_TRUSTED_TLS_PROXY` | `false` | Required acknowledgement before binding the dashboard beyond loopback |
| `GHOSTMCP_SCHEDULER_POLL_SECONDS` | `30` | Scheduler polling interval |
| `GHOSTMCP_ALLOWED_FILE_ROOTS` | empty | Compatibility alias for `GHOSTMCP_ALLOWED_PATHS` |

Example Linux file-root policy:

```bash
export GHOSTMCP_ALLOWED_PATHS=/srv/assessments:/var/lib/ghostmcp/uploads
```

The dashboard queue is in process. SQLite stores scan and schedule state, but an item already placed in memory is not restored after a process crash.

## Database

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_DB_TYPE` | `sqlite` | Persistence backend selector |
| `GHOSTMCP_DB_PATH` | `ghostmcp.db` | SQLite database path |
| `GHOSTMCP_DB_DSN` | empty | Reserved for a future PostgreSQL backend |

The current implementation supports SQLite. PostgreSQL selection fails explicitly because that backend is not implemented.

Use an absolute database path in services and containers:

```bash
export GHOSTMCP_DB_PATH=/var/lib/ghostmcp/ghostmcp.db
```

## Credentials

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_CREDENTIAL_BACKEND` | `disabled` | `disabled`, `encrypted`, `vault`, `aws`, `gcp`, or `plaintext` |
| `GHOSTMCP_CREDENTIAL_STORE` | `credentials.bin` | Local credential-store path |
| `GHOSTMCP_CRED_PASSWORD` | empty | Password used to derive an encrypted-store key |
| `GHOSTMCP_CRED_KEY_FILE` | empty | File containing a Fernet key |
| `GHOSTMCP_ALLOW_PLAINTEXT_CREDENTIALS` | `false` | Required additional opt-in for plaintext storage |

Encrypted storage requires exactly one of `GHOSTMCP_CRED_PASSWORD` or `GHOSTMCP_CRED_KEY_FILE`. A key file is usually safer for unattended services because it avoids placing a password in the process environment.

External backends also use their provider variables:

- Vault: `VAULT_ADDR`, `VAULT_TOKEN`
- AWS: `AWS_REGION` and normal AWS credential resolution
- GCP: `GCP_PROJECT_ID` and normal Google application credentials

## Audit chain

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_AUDIT_SINK_PATH` | empty | JSONL audit destination |
| `GHOSTMCP_AUDIT_HMAC_KEY` | empty | Direct HMAC secret; file-based configuration is preferred |
| `GHOSTMCP_AUDIT_HMAC_KEY_FILE` | empty | File containing the audit HMAC secret |
| `GHOSTMCP_AUDIT_FSYNC` | `false` | Flush each event to stable storage |

For production:

```bash
export GHOSTMCP_AUDIT_SINK_PATH=/var/log/ghostmcp/audit.jsonl
export GHOSTMCP_AUDIT_HMAC_KEY_FILE=/etc/ghostmcp/audit-hmac.key
export GHOSTMCP_AUDIT_FSYNC=true
```

Protect the signing key separately from the audit log. Copy or stream the log to append-only storage so an attacker who compromises the service account cannot silently replace both local files.

## Process privileges

| Setting | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_ALLOW_RUN_AS_ROOT` | `false` | Allows execution as root when explicitly enabled |

Run GhostMCP as a dedicated non-root account. If a scanner requires elevated privileges, grant the narrow capability to that binary or use a separate controlled execution service instead of running the entire MCP process as root.
