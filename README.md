<p align="center">
  <img src="docs/images/banner.png" alt="GhostMCP banner" />
</p>

# GhostMCP

[![CI](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/ci.yml/badge.svg)](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/codeql.yml/badge.svg)](https://github.com/jason-allen-oneal/GhostMCP/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/jason-allen-oneal/GhostMCP/badge)](https://securityscorecards.dev/viewer/?uri=github.com/jason-allen-oneal/GhostMCP)
[![License](https://img.shields.io/github/license/jason-allen-oneal/GhostMCP)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)

GhostMCP is a security-focused MCP server for authorized assessment workflows. It combines policy-guarded native tools, curated external scanners, normalized workflows, a local dashboard, scheduling, credential backends, and auditable execution.

GhostMCP is currently a beta release. It defaults to a restricted posture and should be deployed only in environments where the operator controls the target scope, credentials, network path, and installed security tools.

## Safety and authorization

Use GhostMCP only against systems you own or are explicitly authorized to assess. The runtime provides scope controls and execution ceilings, but those controls do not replace written authorization, rules of engagement, or operator review.

Secure defaults include:

- Private-address targeting by default
- Engagement context required by default
- Maximum tool level set to `active`
- Raw binary wrappers disabled by default
- External plugins disabled by default
- Credential storage disabled until a backend is selected
- Remote transport without authentication blocked by default
- Dashboard authentication required by default

## Capabilities

- Core MCP tools for DNS, WHOIS, HTTP, TLS, TCP exposure checks, IOC extraction, URL risk scoring, recon generation, metrics, and health checks
- Normalized assessment workflows for web surface, TLS posture, and host exposure reviews
- Curated wrappers for common security tools when their binaries are installed
- Optional raw Kali wrappers with explicit global enablement and per-binary allowlisting
- CIDR, domain, port, engagement, and tool-level policy controls
- Versioned tool capability/target manifest and policy-backed approval provenance
- Fail-closed routed execution and bounded in-memory subprocess output
- Streamable HTTP transport with bearer-token or mTLS authentication
- SQLite engagement, scan, schedule, and finding persistence
- Authenticated web dashboard with a guarded execution registry
- Five-field UTC cron scheduling with SQLite leases and duplicate-submit protection
- Disabled-by-default entry-point plugin system with explicit allowlisting
- Encrypted local credentials or Vault, AWS Secrets Manager, and GCP Secret Manager backends
- Persistent canonical audit hash chain with optional HMAC signatures

## Documentation

- [Documentation index](docs/README.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Dashboard and scheduling](docs/DASHBOARD.md)
- [Operations runbook](docs/RUNBOOK.md)
- [Plugin development](docs/PLUGINS.md)
- [Security operations](docs/SECURITY-OPERATIONS.md)
- [Vulnerability reporting policy](SECURITY.md)

## Requirements

- Python 3.11 or newer
- The `mcp` package, installed as a project dependency
- Optional security binaries on `PATH` for curated or raw wrappers
- Optional dashboard, credential, or secret-manager extras as needed

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Common optional installations:

```bash
# Dashboard and encrypted local credentials
python -m pip install -e ".[dashboard,credentials]"

# Development and tests
python -m pip install -e ".[dev,dashboard,credentials]"

# One external secret-manager backend
python -m pip install -e ".[vault]"
python -m pip install -e ".[aws]"
python -m pip install -e ".[gcp]"
```

## Local MCP server

The default transport is local stdio:

```bash
export GHOSTMCP_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
export GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT=true
export GHOSTMCP_MAX_TOOL_LEVEL=active
ghostmcp
```

Configure your MCP client to start the `ghostmcp` command. Keep the environment explicit instead of relying on shell-wide defaults.

## Remote gateway

Remote mode fails closed unless authentication is configured or the explicit insecure override is enabled.

Bearer-token example:

```bash
export GHOSTMCP_TRANSPORT_MODE=remote_gateway
export GHOSTMCP_AUTH_MODE=token
export GHOSTMCP_AUTH_TOKEN="replace-with-a-long-random-token"
export GHOSTMCP_HTTP_HOST=127.0.0.1
export GHOSTMCP_HTTP_PORT=8000
ghostmcp
```

Clients authenticate at the HTTP transport with:

```text
Authorization: Bearer <token>
```

The token is not exposed as an MCP tool argument. Non-loopback token binding requires `GHOSTMCP_TLS_CERT_PATH` and `GHOSTMCP_TLS_KEY_PATH`; otherwise startup fails. For network-accessible deployments, prefer mTLS, bind to an internal interface, and restrict the port with a firewall or private overlay network.

See [Deployment](docs/DEPLOYMENT.md) and [Security operations](docs/SECURITY-OPERATIONS.md).

## Dashboard

```bash
python -m pip install -e ".[dashboard]"
export GHOSTMCP_DASHBOARD_TOKEN="replace-with-a-long-random-token"
export GHOSTMCP_DB_PATH="$PWD/ghostmcp.db"
ghostmcp-dashboard
```

The dashboard binds to `127.0.0.1:8080` by default. It contains one in-process worker and one scheduler. Schedule claims are durable and leased in SQLite, but work that is already queued in memory is not restored after a process crash.

Run one dashboard instance unless all instances share the same database and compatible file-root policy. See [Dashboard and scheduling](docs/DASHBOARD.md).

## Normalized assessment workflows

- `web_surface_assessment_tool` validates scope, checks HTTP posture, and optionally runs WhatWeb and WAF detection when available.
- `tls_posture_assessment_tool` validates the host and port, checks certificate state and expiry, and optionally runs `sslscan`.
- `host_exposure_assessment_tool` performs a policy-bounded TCP exposure check over an explicit port list.

These workflows provide stable, typed entry points without requiring an agent to assemble many low-level calls.

## Curated external tools

Curated wrappers register only when their binaries are available. Examples include nmap, WhatWeb, Nikto, Amass, Gobuster, Nuclei, ffuf, Feroxbuster, Subfinder, dnsx, sqlmap, sslscan, sslyze, TruffleHog, Gitleaks, SMB utilities, and metadata-analysis tools.

Availability is environment-dependent. Use `toolchain_status_tool` to inspect installed, missing, enabled, and disabled integrations.

## Raw binary wrappers

Raw wrappers are disabled by default. Enabling the feature does not enable every discovered binary. Each binary must also appear in the allowlist.

```bash
export GHOSTMCP_ENABLE_RAW_TOOLS=true
export GHOSTMCP_RAW_TOOL_ALLOWLIST=nmap,testssl.sh
```

Raw wrappers remain subject to engagement context, capability and target validation, tool-level ceilings, argument limits, runtime limits, output limits, and audit logging. They should be enabled sparingly.

## Policy-backed intrusive execution

Intrusive and sensitive capabilities fail closed unless the engagement is present in a mode-`0600` policy file with an expiration, narrow target scope, capability list, and approval provenance:

```bash
export GHOSTMCP_ENGAGEMENT_POLICY_FILE=/etc/ghostmcp/engagement-policy.json
export GHOSTMCP_MAX_TOOL_LEVEL=intrusive
```

Start from [`engagement-policy.example.json`](engagement-policy.example.json). The runtime hashes the effective scope and records the scope digest, approval ID, and approver in audit events. The tool-provided `engagement_mode` can only narrow policy; it cannot grant authority.

## Plugins

Plugins are disabled by default and loaded by entry-point name only when allowlisted.

```bash
export GHOSTMCP_ENABLE_PLUGINS=true
export GHOSTMCP_PLUGIN_GROUP=ghostmcp.plugins
export GHOSTMCP_PLUGIN_ALLOWLIST=my-approved-plugin
```

See [Plugin development](docs/PLUGINS.md) for the entry-point contract and deployment checklist.

## Credential storage

Credential storage defaults to `disabled`. Select a backend explicitly:

```bash
# Encrypted local file
export GHOSTMCP_CREDENTIAL_BACKEND=encrypted
export GHOSTMCP_CREDENTIAL_STORE="$HOME/.local/state/ghostmcp/credentials.bin"
export GHOSTMCP_CRED_KEY_FILE="$HOME/.config/ghostmcp/credential.key"
```

Supported backend names are `disabled`, `encrypted`, `vault`, `aws`, `gcp`, and `plaintext`. Plaintext storage additionally requires `GHOSTMCP_ALLOW_PLAINTEXT_CREDENTIALS=true` and should be limited to isolated testing.

Use file-mounted secrets or a secret manager in production. Do not commit tokens, passwords, key files, credential stores, or audit HMAC keys.

## Audit chain

Set an audit sink to persist JSONL events:

```bash
export GHOSTMCP_AUDIT_SINK_PATH=/var/log/ghostmcp/audit.jsonl
export GHOSTMCP_AUDIT_HMAC_KEY_FILE=/etc/ghostmcp/audit-hmac.key
export GHOSTMCP_AUDIT_FSYNC=true
```

Events use canonical JSON, `prev_hash`, and `event_hash`. When an HMAC key is configured, each event is also signed. Protect the audit file and key separately and ship audit output to append-only or centralized storage when possible.

## Configuration baseline

Copy `.env.example` and review every value before deployment. Important defaults:

| Setting | Default | Meaning |
| --- | --- | --- |
| `GHOSTMCP_ALLOW_PRIVATE_ONLY` | `true` | Reject public target addresses |
| `GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT` | `true` | Require an engagement ID for guarded calls |
| `GHOSTMCP_MAX_TOOL_LEVEL` | `active` | Global execution ceiling |
| `GHOSTMCP_ENGAGEMENT_POLICY_FILE` | empty | Protected policy input for scoped intrusive/sensitive authorization |
| `GHOSTMCP_ALLOW_UNSCOPED_INTRUSIVE` | `false` | Unsafe compatibility override |
| `GHOSTMCP_ENABLE_RAW_TOOLS` | `false` | Disable generated raw wrappers |
| `GHOSTMCP_ENABLE_PLUGINS` | `false` | Disable external plugins |
| `GHOSTMCP_CREDENTIAL_BACKEND` | `disabled` | Do not load or store credentials |
| `GHOSTMCP_AUTH_MODE` | `none` | Valid for stdio; remote mode blocks it |
| `GHOSTMCP_DASHBOARD_ALLOW_UNAUTHENTICATED` | `false` | Require dashboard authentication |

See [Configuration reference](docs/CONFIGURATION.md) for all supported groups and production guidance.

## Development

```bash
python -m pip install -e ".[dev,dashboard,credentials]"
ruff check .
mypy ghostmcp
bandit -q -r ghostmcp
pip-audit -r requirements-dev.lock.txt
python -m unittest discover -s tests -v
python -m build
```

CI validates Python 3.11 and 3.12, dependency locks, linting, typing, Bandit, dependency advisories, tests, package builds, clean-wheel installation, container construction, Trivy policy, and CodeQL.

## Release status

The package version is `0.2.0`. The runtime is beta-quality: policy enforcement is fail-closed, but operators must still layer network egress controls, least privilege, protected secrets, and written authorization around it.

## License

GhostMCP is licensed under the GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).
