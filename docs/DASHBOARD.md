# Dashboard and scheduling

The optional GhostMCP dashboard provides engagement, scan, schedule, and finding views over the SQLite database. It also hosts one guarded in-process worker and one cron scheduler.

## Install and start

```bash
python -m pip install -e ".[dashboard]"
export GHOSTMCP_DASHBOARD_TOKEN="replace-with-a-long-random-token"
export GHOSTMCP_DB_PATH="$PWD/ghostmcp.db"
ghostmcp-dashboard
```

Defaults:

- Bind address: `127.0.0.1`
- Port: `8080`
- Authentication required
- Secure cookie disabled until HTTPS is configured
- Scheduler poll interval: 30 seconds

Open `http://127.0.0.1:8080` and authenticate with the dashboard token.

## Authentication

The dashboard accepts a bearer token, `X-GhostMCP-Token`, or a login cookie. Cookie-authenticated state-changing requests must be same-origin.

Production guidance:

- Use a token that is different from the MCP transport token.
- Put HTTPS in front of the dashboard before setting `GHOSTMCP_DASHBOARD_SECURE_COOKIE=true`.
- Keep the backend listener on loopback or an internal interface.
- Do not enable `GHOSTMCP_DASHBOARD_ALLOW_UNAUTHENTICATED` outside isolated testing.
- Rotate the token after suspected exposure.

## Engagements

An engagement stores:

- ID and name
- Description
- CIDR scope
- Domain scope
- Maximum tool level
- Status

The dashboard is not a substitute for a signed statement of work or rules of engagement. Store only the technical scope needed by the runtime and retain legal authorization elsewhere.

## Scan execution

Dashboard-created scans are dispatched through a guarded executor registry. The dashboard does not accept arbitrary command strings.

A scan moves through states such as:

- `pending`
- `queued`
- `running`
- `completed`
- `failed`

The worker validates the registered executor and persists completion or failure information. Exceptions are contained so one failed scan does not terminate the worker thread.

Optional external tools still depend on installed binaries and policy. A scheduled scan can fail safely if its executor is unavailable or the current policy rejects its target.

## File-backed tools

File-backed operations are restricted to roots in `GHOSTMCP_ALLOWED_PATHS`.

Linux example:

```bash
export GHOSTMCP_ALLOWED_PATHS=/srv/assessments:/var/lib/ghostmcp/uploads
```

The separator is the platform path separator. Keep writable upload locations separate from code, configuration, key files, and audit storage.

## Scheduling

Schedules use standard five-field cron expressions in UTC:

```text
minute hour day-of-month month day-of-week
```

Examples:

```text
0 2 * * *       every day at 02:00 UTC
*/15 * * * *    every 15 minutes
0 6 * * 1       every Monday at 06:00 UTC
30 1 1 * *      first day of each month at 01:30 UTC
```

Validate schedules against the intended UTC time. The runtime does not infer a local timezone.

## Lease behavior

The scheduler uses atomic SQLite leases so multiple dashboard processes sharing one database do not claim the same due schedule simultaneously.

This does not make the in-memory work queue durable:

- Schedule definitions and leases are stored in SQLite.
- Scan records and results are stored in SQLite.
- Work already placed into the process queue is lost if that process exits before execution.
- A process restart does not reconstruct queued work automatically.

For the current beta release, run one dashboard instance. A durable external queue is required for multi-node or crash-resumable execution.

## Backup and recovery

Back up the database before upgrades and before large scheduled campaigns.

Safe sequence:

1. Stop the dashboard.
2. Confirm no scan is running.
3. Copy the SQLite database and its WAL and SHM files, or use SQLite's backup command.
4. Back up the audit log separately.
5. Restart the dashboard and verify engagement and schedule views.

Do not restore a database while another process is writing to it.

## Troubleshooting

### The dashboard refuses to start

Confirm `GHOSTMCP_DASHBOARD_TOKEN` is set. The runtime intentionally fails closed unless `GHOSTMCP_DASHBOARD_ALLOW_UNAUTHENTICATED=true` is explicitly set.

### Login succeeds but mutations fail

When using a cookie, verify the request origin and host match. If the dashboard is behind a reverse proxy, preserve the original host and scheme correctly.

### A scan remains pending

Check:

- The dashboard process is still running.
- The tool name exists in the executor registry.
- The target remains inside engagement and global scope.
- Required external binaries are installed.
- The scan was not rejected by the global or engagement tool ceiling.

### A schedule does not fire

Check:

- The cron expression has exactly five fields.
- The expected time was converted to UTC.
- The schedule is enabled.
- The scheduler poll interval has elapsed.
- Another process does not hold an unexpired lease.
- The database is writable.

### A queued scan disappeared after restart

That is a known beta limitation. The queue is in process. Resubmit the scan after verifying that the previous process did not complete it.
