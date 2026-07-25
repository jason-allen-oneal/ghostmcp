# Deployment guide

GhostMCP should run as a dedicated non-root service with an explicit environment, restricted network exposure, writable state paths, and protected secrets.

## Deployment checklist

Before starting the service:

1. Confirm written authorization and define target CIDRs, domains, ports, and tool-level ceilings.
2. Create a dedicated service account.
3. Choose local stdio or an authenticated remote transport.
4. Set an absolute SQLite path and audit path.
5. Configure dashboard authentication if the dashboard is enabled.
6. Leave raw wrappers and plugins disabled unless each extension has been reviewed.
7. Store tokens and key files outside the repository.
8. Restrict inbound and outbound network paths with host or network firewalls.
9. Verify `toolchain_status_tool` after deployment.
10. Back up the database and audit output before upgrades.

## Local stdio deployment

Local stdio is the smallest attack surface. The MCP client starts GhostMCP as a child process and communicates over standard input and output.

Example environment:

```bash
GHOSTMCP_TRANSPORT_MODE=stdio
GHOSTMCP_ALLOW_PRIVATE_ONLY=true
GHOSTMCP_ALLOWED_CIDRS=10.40.0.0/16
GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT=true
GHOSTMCP_MAX_TOOL_LEVEL=active
GHOSTMCP_ENABLE_RAW_TOOLS=false
GHOSTMCP_ENABLE_PLUGINS=false
GHOSTMCP_CREDENTIAL_BACKEND=disabled
```

Keep the MCP client's environment block explicit. Avoid inheriting unrelated credentials from an interactive shell.

## Remote gateway

Remote mode uses streamable HTTP. Bind to loopback or an internal interface and require token or mTLS authentication. Bearer-token mode on a non-loopback listener also requires direct TLS certificate and key paths.

Token example:

```bash
export GHOSTMCP_TRANSPORT_MODE=remote_gateway
export GHOSTMCP_AUTH_MODE=token
export GHOSTMCP_AUTH_TOKEN="replace-with-a-long-random-token"
export GHOSTMCP_HTTP_HOST=127.0.0.1
export GHOSTMCP_HTTP_PORT=8000
ghostmcp
```

A reverse proxy may provide TLS termination, but it must preserve the `Authorization` header and restrict direct access to the backend listener. When possible, use mTLS directly and avoid exposing the service to the public internet.

Never use `GHOSTMCP_ALLOW_INSECURE_REMOTE_NO_AUTH=true` outside isolated development.

## systemd

The repository includes `deploy/systemd/ghostmcp.service`. The unit is intended for a dedicated `ghostmcp` user and uses systemd hardening directives.

Create the account and directories:

```bash
sudo useradd --system --home /opt/ghostmcp --shell /usr/sbin/nologin ghostmcp
sudo install -d -o ghostmcp -g ghostmcp -m 0750 /opt/ghostmcp
sudo install -d -o ghostmcp -g ghostmcp -m 0750 /var/lib/ghostmcp
sudo install -d -o ghostmcp -g ghostmcp -m 0750 /var/log/ghostmcp
sudo install -d -o root -g ghostmcp -m 0750 /etc/ghostmcp
```

Install the project into `/opt/ghostmcp/.venv`, then create `/etc/ghostmcp/ghostmcp.env`:

```bash
GHOSTMCP_TRANSPORT_MODE=remote_gateway
GHOSTMCP_AUTH_MODE=token
GHOSTMCP_AUTH_TOKEN=replace-with-a-long-random-token
GHOSTMCP_HTTP_HOST=127.0.0.1
GHOSTMCP_HTTP_PORT=8000
GHOSTMCP_ALLOW_PRIVATE_ONLY=true
GHOSTMCP_ALLOWED_CIDRS=10.40.0.0/16
GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT=true
GHOSTMCP_MAX_TOOL_LEVEL=active
GHOSTMCP_DB_PATH=/var/lib/ghostmcp/ghostmcp.db
GHOSTMCP_AUDIT_SINK_PATH=/var/log/ghostmcp/audit.jsonl
GHOSTMCP_AUDIT_HMAC_KEY_FILE=/etc/ghostmcp/audit-hmac.key
GHOSTMCP_AUDIT_FSYNC=true
GHOSTMCP_ENABLE_RAW_TOOLS=false
GHOSTMCP_ENABLE_PLUGINS=false
GHOSTMCP_CREDENTIAL_BACKEND=disabled
```

Protect the environment and key files:

```bash
sudo chown root:ghostmcp /etc/ghostmcp/ghostmcp.env /etc/ghostmcp/audit-hmac.key
sudo chmod 0640 /etc/ghostmcp/ghostmcp.env /etc/ghostmcp/audit-hmac.key
```

Install and start the unit:

```bash
sudo cp deploy/systemd/ghostmcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ghostmcp
sudo systemctl status ghostmcp
sudo journalctl -u ghostmcp -f
```

The shipped unit provides writable state and log directories while keeping the rest of the filesystem read-only.

## Container

Build the image:

```bash
docker build -f deploy/container/Dockerfile -t ghostmcp:local .
```

Run an authenticated remote gateway with persistent state:

```bash
docker run --rm \
  --name ghostmcp \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 127.0.0.1:8000:8000 \
  -v ghostmcp-state:/var/lib/ghostmcp \
  -v ghostmcp-audit:/var/log/ghostmcp \
  -e GHOSTMCP_TRANSPORT_MODE=remote_gateway \
  -e GHOSTMCP_AUTH_MODE=token \
  -e GHOSTMCP_AUTH_TOKEN="replace-with-a-long-random-token" \
  -e GHOSTMCP_TLS_CERT_PATH=/run/ghostmcp/tls.crt \
  -e GHOSTMCP_TLS_KEY_PATH=/run/ghostmcp/tls.key \
  -v /etc/ghostmcp/tls.crt:/run/ghostmcp/tls.crt:ro \
  -v /etc/ghostmcp/tls.key:/run/ghostmcp/tls.key:ro \
  -e GHOSTMCP_HTTP_HOST=0.0.0.0 \
  -e GHOSTMCP_HTTP_PORT=8000 \
  -e GHOSTMCP_DB_PATH=/var/lib/ghostmcp/ghostmcp.db \
  -e GHOSTMCP_AUDIT_SINK_PATH=/var/log/ghostmcp/audit.jsonl \
  -e GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT=true \
  -e GHOSTMCP_MAX_TOOL_LEVEL=active \
  ghostmcp:local
```

Use Docker secrets, Kubernetes Secrets, or mounted files for production tokens and keys instead of command-line environment values.

The base image contains the Python runtime and GhostMCP source. External scanner binaries must be provided by a derived image or a separate controlled execution environment. Installing a full security distribution into the control-plane image substantially increases attack surface and patching requirements.

## Dashboard deployment

Run the dashboard separately from the MCP gateway unless a single-process local installation is intentional.

```bash
export GHOSTMCP_DASHBOARD_HOST=127.0.0.1
export GHOSTMCP_DASHBOARD_PORT=8080
export GHOSTMCP_DASHBOARD_TOKEN="replace-with-a-long-random-token"
export GHOSTMCP_DB_PATH=/var/lib/ghostmcp/ghostmcp.db
export GHOSTMCP_ALLOWED_PATHS=/srv/assessments
ghostmcp-dashboard
```

Put HTTPS in front of the dashboard before enabling `GHOSTMCP_DASHBOARD_SECURE_COOKIE=true`. Non-loopback binding additionally requires `GHOSTMCP_DASHBOARD_TRUSTED_TLS_PROXY=true`; this is an explicit operator acknowledgement, not a TLS implementation. The dashboard token should be different from the MCP transport token.

## Upgrades

Before upgrading:

1. Stop the service and dashboard.
2. Back up the SQLite database and audit chain.
3. Record the current package version and lock-file commit.
4. Review changes to `.env.example` and the documentation.
5. Rebuild the virtual environment or image from locked dependencies.
6. Run the test and health checks.
7. Start one instance and verify migrations, tool registration, and audit continuity.

Do not copy old environment files forward without reviewing new defaults.

Machine-readable readiness:

```bash
ghostmcp --healthcheck
```
