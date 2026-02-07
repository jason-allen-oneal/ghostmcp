# GhostMCP
[![CI](https://github.com/jason-allen-oneal/ghostmcp/actions/workflows/ci.yml/badge.svg)](https://github.com/jason-allen-oneal/ghostmcp/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jason-allen-oneal/ghostmcp/actions/workflows/codeql.yml/badge.svg)](https://github.com/jason-allen-oneal/ghostmcp/actions/workflows/codeql.yml)
[![Dependabot Updates](https://github.com/jason-allen-oneal/ghostmcp/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/jason-allen-oneal/ghostmcp/actions/workflows/dependabot/dependabot-updates)

GhostMCP is a production-oriented MCP server for authorized red-team and security operations.

It provides:
- Core built-in reconnaissance and analysis tools
- Binary-backed Kali tool wrappers discovered at startup
- Engagement context support (`engagement_id`, `engagement_mode`)
- Lightweight policy controls and audit chaining
- Transport/auth policy for non-local gateway mode
- Runtime metrics, health probes, and SIEM audit export

## How It Works
GhostMCP has a single binary tool system:
- At startup, it scans a Kali-common binary list.
- Only binaries found on `PATH` are enabled as MCP tools.
- Missing binaries are not registered, so the LLM cannot call them.

Trusted transport patterns:
- `stdio` for local/sidecar deployments (default)
- `remote_gateway` served by in-process `streamable-http` transport

You will see startup status including:
- `Tools enabled: <enabled>/<total>`
- `Binary tools enabled: <enabled>/<total>`
- `Enabled binaries: ...`

## Tool Types

### 1) Core tools (always available)
- `dns_lookup_tool`
- `reverse_dns_tool`
- `whois_tool`
- `http_probe_tool`
- `tls_certificate_tool`
- `tls_certificate_expiry_tool`
- `tcp_port_scan_tool`
- `security_txt_tool`
- `ioc_extract_tool`
- `url_risk_score_tool`
- `subdomain_candidates_tool`
- `common_web_paths_tool`
- `toolchain_status_tool`
- `metrics_tool`
- `runtime_probe_tool`
- `server_health_tool`

### 2) Curated binary-backed tools (enabled only when installed)
- `nmap_service_scan_tool`
- `whatweb_tool`
- `nikto_tool`
- `amass_passive_tool`
- `gobuster_dir_tool`
- `sslscan_tool`
- `wafw00f_tool`

### 3) Generated raw binary tools (enabled only when installed)
- Pattern: `<binary>_raw_tool`
- Non-alphanumeric characters become `_`
- Example: `testssl.sh` -> `testssl_sh_raw_tool`

## Requirements
- Python 3.11+
- `mcp` package (installed via this project)
- Optional: Kali tools on `PATH` for binary-backed tools

## Install
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Configuration
Use `.env.example` as a baseline.

Primary env vars:
- `GHOSTMCP_LOG_LEVEL` (default: `INFO`)
- `GHOSTMCP_LOG_FORMAT` (default: `json`)
- `GHOSTMCP_RATE_LIMIT_CALLS` (default: `120`)
- `GHOSTMCP_RATE_LIMIT_WINDOW_SECONDS` (default: `60`)
- `GHOSTMCP_MAX_PORTS_PER_SCAN` (default: `256`)
- `GHOSTMCP_CONNECT_TIMEOUT_MS` (default: `1500`)
- `GHOSTMCP_MAX_CONCURRENT_CONNECTS` (default: `64`)
- `GHOSTMCP_ALLOW_PRIVATE_ONLY` (default: `true`)
- `GHOSTMCP_ALLOWED_CIDRS` (optional)
- `GHOSTMCP_ALLOWED_DOMAINS` (optional)
- `GHOSTMCP_BLOCKED_PORTS` (default includes `22,2375,2376,3389`)
- `GHOSTMCP_USER_AGENT` (default: `GhostMCP/0.1`)
- `GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT` (default: `false`)
- `GHOSTMCP_MAX_TOOL_LEVEL` (`passive|active|intrusive`, default: `intrusive`)
- `GHOSTMCP_TRANSPORT_MODE` (`stdio|remote_gateway`, default: `stdio`)
- `GHOSTMCP_AUTH_MODE` (`none|token|mtls`, default: `none`)
- `GHOSTMCP_AUTH_TOKEN` (required for token mode)
- `GHOSTMCP_ALLOW_INSECURE_REMOTE_NO_AUTH` (default: `false`; unsafe override)
- `GHOSTMCP_MTLS_CA_CERT_PATH`, `GHOSTMCP_MTLS_CERT_PATH`, `GHOSTMCP_MTLS_KEY_PATH`
- `GHOSTMCP_HTTP_HOST`, `GHOSTMCP_HTTP_PORT` (remote gateway bind settings)
- `GHOSTMCP_UVICORN_LOG_LEVEL` (default: `info`)
- `GHOSTMCP_MAX_PASSIVE_PARALLEL`, `GHOSTMCP_MAX_ACTIVE_PARALLEL`, `GHOSTMCP_MAX_INTRUSIVE_PARALLEL`
- `GHOSTMCP_MAX_RAW_ARG_COUNT`, `GHOSTMCP_MAX_RAW_ARG_LENGTH`, `GHOSTMCP_MAX_RAW_RUNTIME_SECONDS`
- `GHOSTMCP_MAX_RAW_STDOUT_BYTES`, `GHOSTMCP_MAX_RAW_STDERR_BYTES`
- `GHOSTMCP_AUDIT_SINK_PATH` (JSONL sink for SIEM shipping)
- `GHOSTMCP_ALLOW_RUN_AS_ROOT` (default: `false`)

## Run
```bash
ghostmcp
```

This runs in the foreground over stdio (blocks the terminal). Use `Ctrl+C` to stop.

## MCP Client Example (Claude Desktop)
```json
{
  "mcpServers": {
    "ghostmcp": {
      "command": "ghostmcp",
      "env": {
        "GHOSTMCP_ALLOW_PRIVATE_ONLY": "true",
        "GHOSTMCP_ALLOWED_CIDRS": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
        "GHOSTMCP_ALLOWED_DOMAINS": "example.com"
      }
    }
  }
}
```

## Engagement Model
Most tools accept:
- `engagement_id` (optional unless required by policy)
- `engagement_mode` (`passive`, `active`, `intrusive`)
- `auth_token` (required for `remote_gateway` + `token` auth mode)

Authorization checks enforce:
- Global max tool level (`GHOSTMCP_MAX_TOOL_LEVEL`)
- Per-call engagement mode ceiling
- Auth policy for remote mode (`auth_token` for token mode; TLS client cert for mTLS mode)
- Hard block on `remote_gateway + AUTH_MODE=none` unless unsafe override is explicitly enabled

## Audit & Safety
GhostMCP emits:
- Structured logs
- Per-call audit entries with hash chaining (`prev_hash`, `event_hash`)
- Optional JSONL audit sink export (`GHOSTMCP_AUDIT_SINK_PATH`)
- Per-tool runtime metrics (`metrics_tool`)
- Runtime orchestration probe (`runtime_probe_tool`)

Scope controls:
- Target/private network validation
- Optional domain allowlist
- Optional CIDR allowlist
- Port policy enforcement
- Raw-tool argument policy (allowlisted tokens/flags, length/count limits)
- Runtime/output caps and forced subprocess termination on timeout
- Per-tool-class concurrency controls (passive/active/intrusive semaphores)

## Inspect Runtime Availability
Use:
- `toolchain_status_tool` for installed/missing binaries and enabled binary MCP tools
- `server_health_tool` for policy/config snapshot plus toolchain summary
- `metrics_tool` for call/failure/timeout/deny statistics
- `runtime_probe_tool` for readiness/liveness-style runtime state

## Development
Run tests:
```bash
python -m unittest discover -s tests
```

E2E smoke test (opt-in):
```bash
GHOSTMCP_E2E=1 python -m unittest tests/test_e2e_mcp.py
```

## CI/CD
GitHub workflows included:
- `.github/workflows/ci.yml`:
  - lint (`ruff`)
  - type checks (`mypy`)
  - tests (`unittest`)
  - static security scan (`bandit`)
  - dependency audit (`pip-audit`)
  - package build
  - container vulnerability scan (`trivy`)
- `.github/workflows/codeql.yml`: scheduled and PR/push CodeQL analysis
- `.github/workflows/release.yml`:
  - tag-triggered build (`v*`)
  - Twine artifact verification
  - SBOM generation (SPDX)
  - build provenance attestation
  - GitHub Release publishing
  - optional PyPI publish when `PYPI_API_TOKEN` secret is present

## Deployment
- `deploy/systemd/ghostmcp.service` for systemd-managed process lifecycle
- `deploy/container/Dockerfile` for non-root container runtime
- `deploy/apparmor/ghostmcp.apparmor` for optional AppArmor confinement

## Runtime Security
- Non-root enforcement by default (`GHOSTMCP_ALLOW_RUN_AS_ROOT=false`)
- Minimal write footprint recommended (logs/audit sink only)
- Optional AppArmor profile included for stricter binary confinement

## Legal
Use GhostMCP only on systems and networks you are explicitly authorized to assess.
