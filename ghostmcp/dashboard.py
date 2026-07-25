"""Web dashboard for GhostMCP - FastAPI + HTMX."""

import base64
import hmac
import html
import json
import os
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .database import get_database

app = FastAPI(title="GhostMCP Dashboard", version="1.0.0")


def _dashboard_credentials() -> tuple[str, str, str]:
    return (
        os.getenv("GHOSTMCP_DASHBOARD_AUTH_USERNAME", "ghostmcp"),
        os.getenv("GHOSTMCP_DASHBOARD_AUTH_PASSWORD", ""),
        os.getenv("GHOSTMCP_DASHBOARD_AUTH_TOKEN", ""),
    )


def _authorized_request(request: Request) -> tuple[bool, str | None]:
    username, password, token = _dashboard_credentials()
    auth = request.headers.get("authorization", "")
    if token and auth.startswith("Bearer "):
        supplied = auth.removeprefix("Bearer ").strip()
        return hmac.compare_digest(supplied, token), "bearer"
    if password and auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(
                auth.removeprefix("Basic ").strip(),
                validate=True,
            ).decode("utf-8")
            supplied_user, supplied_password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return False, None
        return (
            hmac.compare_digest(supplied_user, username)
            and hmac.compare_digest(supplied_password, password),
            "basic",
        )
    return False, None


@app.middleware("http")
async def secure_dashboard(request: Request, call_next) -> Response:
    _username, password, token = _dashboard_credentials()
    if not password and not token:
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "Dashboard is locked. Configure dashboard authentication."
                )
            },
        )
    authorized, auth_type = _authorized_request(request)
    if not authorized:
        return JSONResponse(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="GhostMCP"'},
            content={"detail": "Authentication required"},
        )
    if request.method not in {"GET", "HEAD", "OPTIONS"} and auth_type == "basic":
        origin = request.headers.get("origin")
        if not origin or urlsplit(origin).netloc != request.headers.get("host"):
            return JSONResponse(
                status_code=403,
                content={"detail": "Cross-origin write request denied"},
            )
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# Templates
template_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))

# Database
_db = None


def get_db():
    global _db
    if _db is None:
        _db = get_database()
    return _db


# Helper functions
def _generate_id() -> str:
    return uuid.uuid4().hex[:12]


# ===== Engagement Endpoints =====

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page."""
    db = get_db()
    engagements = db.list_engagements()
    stats = {
        "total_engagements": len(engagements),
        "active_engagements": len([e for e in engagements if e.status == "active"]),
        "total_scans": sum(db.get_engagement_stats(e.id)["total_scans"] for e in engagements),
    }
    return templates.TemplateResponse(request, "dashboard.html", {"request": request, "engagements": engagements, "stats": stats})


@app.get("/engagements", response_class=HTMLResponse)
async def list_engagements(request: Request):
    """List all engagements."""
    db = get_db()
    engagements = db.list_engagements()
    return templates.TemplateResponse(request, "engagements/list.html", {"request": request, "engagements": engagements})


@app.get("/engagements/new", response_class=HTMLResponse)
async def new_engagement_form(request: Request):
    """Show new engagement form."""
    return templates.TemplateResponse(request, "engagements/new.html", {"request": request})


@app.post("/engagements", response_class=HTMLResponse)
async def create_engagement(
    request: Request,
    name: str = Form(...),
    description: str = Form(default=""),
    scope_cidrs: str = Form(default=""),
    scope_domains: str = Form(default=""),
    max_tool_level: str = Form(default="intrusive"),
):
    """Create a new engagement."""
    db = get_db()
    engagement_id = _generate_id()

    engagement = db.create_engagement(
        engagement_id=engagement_id,
        name=name,
        description=description or None,
        scope_cidrs=[c.strip() for c in scope_cidrs.split(",") if c.strip()],
        scope_domains=[d.strip() for d in scope_domains.split(",") if d.strip()],
        max_tool_level=max_tool_level,
    )

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request, "engagements/row.html", {"request": request, "engagement": engagement}
        )
    return templates.TemplateResponse(request, "engagements/list.html", {"request": request, "engagements": db.list_engagements()})


@app.get("/engagements/{engagement_id}", response_class=HTMLResponse)
async def view_engagement(request: Request, engagement_id: str):
    """View engagement details."""
    db = get_db()
    engagement = db.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    scans = db.list_scans(engagement_id=engagement_id)
    stats = db.get_engagement_stats(engagement_id)

    return templates.TemplateResponse(
        request, "engagements/detail.html",
        {"request": request, "engagement": engagement, "scans": scans, "stats": stats},
    )


@app.post("/engagements/{engagement_id}/update", response_class=HTMLResponse)
async def update_engagement(
    request: Request,
    engagement_id: str,
    name: str = Form(...),
    description: str = Form(default=""),
    status: str = Form(default="active"),
):
    """Update engagement."""
    db = get_db()
    engagement = db.update_engagement(
        engagement_id,
        name=name,
        description=description or None,
        status=status,
    )
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    return templates.TemplateResponse(request, "engagements/detail.html#summary", {"request": request, "engagement": engagement})


@app.delete("/engagements/{engagement_id}")
async def delete_engagement(engagement_id: str):
    """Delete engagement."""
    db = get_db()
    success = db.delete_engagement(engagement_id)
    if not success:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {"status": "ok"}


# ===== Scan Endpoints =====

@app.post("/engagements/{engagement_id}/scans", response_class=HTMLResponse)
async def create_scan(
    request: Request,
    engagement_id: str,
    tool_name: str = Form(...),
    target: str = Form(...),
    parameters: str = Form(default="{}"),
):
    """Create a new scan."""
    db = get_db()
    engagement = db.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    scan_id = _generate_id()
    try:
        params = json.loads(parameters) if parameters else {}
    except json.JSONDecodeError:
        params = {}

    scan = db.create_scan(
        scan_id=scan_id,
        engagement_id=engagement_id,
        tool_name=tool_name,
        target=target,
        parameters=params,
    )

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "scans/row.html", {"request": request, "scan": scan})

    scans = db.list_scans(engagement_id=engagement_id)
    return templates.TemplateResponse(request, "scans/list.html", {"request": request, "scans": scans, "engagement_id": engagement_id})


@app.post("/scans/{scan_id}/start")
async def start_scan(scan_id: str):
    """Start a scan (async - in real implementation would queue to worker)."""
    db = get_db()
    scan = db.start_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "started", "scan": scan.id}


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def view_scan(request: Request, scan_id: str):
    """View scan details."""
    db = get_db()
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.get_findings(scan_id)
    engagement = db.get_engagement(scan.engagement_id)

    return templates.TemplateResponse(
        request, "scans/detail.html",
        {"request": request, "scan": scan, "findings": findings, "engagement": engagement},
    )


@app.get("/scans/{scan_id}/results.json")
async def get_scan_results(scan_id: str):
    """Get scan results as JSON."""
    db = get_db()
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan": {
            "id": scan.id,
            "tool": scan.tool_name,
            "target": scan.target,
            "status": scan.status,
            "result": scan.result,
            "error": scan.error,
        },
        "findings": [
            {
                "id": f.id,
                "type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
            }
            for f in db.get_findings(scan_id)
        ],
    }


# ===== API Endpoints =====

@app.get("/api/engagements", response_class=HTMLResponse)
async def api_list_engagements():
    """List engagements API."""
    db = get_db()
    engagements = db.list_engagements()
    return [
        {
            "id": e.id,
            "name": e.name,
            "status": e.status,
            "created_at": e.created_at,
        }
        for e in engagements
    ]


@app.get("/api/engagements/{engagement_id}/stats")
async def api_engagement_stats(engagement_id: str):
    """Get engagement statistics."""
    db = get_db()
    stats = db.get_engagement_stats(engagement_id)
    return stats


# ===== Scheduled Scans =====

@app.get("/engagements/{engagement_id}/schedule", response_class=HTMLResponse)
async def schedule_form(request: Request, engagement_id: str):
    """Show scan scheduling form."""
    db = get_db()
    engagement = db.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # Get available tools
    tools = [
        "nmap_service_scan_tool",
        "whatweb_tool",
        "nikto_tool",
        "amass_passive_tool",
        "gobuster_dir_tool",
        "sslscan_tool",
        "wafw00f_tool",
        "nuclei_tool",
        "ffuf_tool",
        "feroxbuster_tool",
        "wfuzz_tool",
        "subfinder_tool",
        "assetfinder_tool",
        "dnsx_tool",
        "gowitness_tool",
        "jaeles_tool",
        "trufflehog_tool",
        "gitleaks_tool",
    ]

    return templates.TemplateResponse(
        request, "schedule/new.html",
        {"request": request, "engagement": engagement, "tools": tools},
    )


@app.post("/engagements/{engagement_id}/schedule", response_class=HTMLResponse)
async def create_schedule(
    request: Request,
    engagement_id: str,
    tool_name: str = Form(...),
    target: str = Form(...),
    cron_expression: str = Form(...),
    parameters: str = Form(default="{}"),
):
    """Create a scheduled scan (stored in database for now)."""
    db = get_db()
    engagement = db.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # In a real implementation, this would use a cron scheduler
    # For now, just show success
    try:
        params = json.loads(parameters) if parameters else {}
    except json.JSONDecodeError:
        params = {}

    # Store in database as a special scan with cron_expression in parameters
    schedule_id = _generate_id()
    scan = db.create_scan(
        scan_id=schedule_id,
        engagement_id=engagement_id,
        tool_name=tool_name,
        target=target,
        parameters={**params, "cron": cron_expression, "scheduled": True},
    )

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "schedule/row.html", {"request": request, "scan": scan})

    return templates.TemplateResponse(request, "schedule/list.html", {"request": request, "engagement": engagement})


# ===== Reports =====

@app.get("/engagements/{engagement_id}/report", response_class=HTMLResponse)
async def view_report(request: Request, engagement_id: str):
    """View engagement report."""
    db = get_db()
    engagement = db.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    scans = db.list_scans(engagement_id=engagement_id)
    stats = db.get_engagement_stats(engagement_id)
    all_findings = db.get_findings_by_severity(engagement_id)

    return templates.TemplateResponse(
        request, "reports/view.html",
        {
            "request": request,
            "engagement": engagement,
            "scans": scans,
            "stats": stats,
            "findings": all_findings,
        },
    )


@app.get("/engagements/{engagement_id}/report.{format}")
async def export_report(engagement_id: str, format: str):
    """Export report in various formats."""
    db = get_db()
    engagement = db.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    scans = db.list_scans(engagement_id=engagement_id)
    stats = db.get_engagement_stats(engagement_id)
    all_findings = db.get_findings_by_severity(engagement_id)

    report_data = {
        "engagement": {
            "id": engagement.id,
            "name": engagement.name,
            "description": engagement.description,
            "scope_cidrs": engagement.scope_cidrs,
            "scope_domains": engagement.scope_domains,
            "max_tool_level": engagement.max_tool_level,
            "status": engagement.status,
            "created_at": engagement.created_at,
        },
        "stats": stats,
        "scans": [
            {
                "id": s.id,
                "tool": s.tool_name,
                "target": s.target,
                "status": s.status,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "result": s.result,
            }
            for s in scans
        ],
        "findings": [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "target": f.target,
            }
            for f in all_findings
        ],
    }

    if format == "json":
        from fastapi.responses import JSONResponse
        return JSONResponse(content=report_data)

    elif format == "md":
        from fastapi.responses import PlainTextResponse
        md = generate_markdown_report(report_data)
        return PlainTextResponse(content=md, media_type="text/markdown")

    elif format == "html":
        from fastapi.responses import HTMLResponse
        html = generate_html_report(report_data)
        return HTMLResponse(content=html)

    raise HTTPException(status_code=400, detail="Unsupported format")


def generate_markdown_report(data: dict) -> str:
    """Generate Markdown report."""
    lines = [
        f"# {data['engagement']['name']} - Security Assessment Report",
        "",
        f"**Engagement ID**: {data['engagement']['id']}",
        f"**Status**: {data['engagement']['status']}",
        f"**Created**: {data['engagement']['created_at']}",
        f"**Max Tool Level**: {data['engagement']['max_tool_level']}",
        "",
        "## Scope",
        f"- **CIDRs**: {', '.join(data['engagement']['scope_cidrs']) or 'None'}",
        f"- **Domains**: {', '.join(data['engagement']['scope_domains']) or 'None'}",
        "",
        "## Summary",
        f"- **Total Scans**: {data['stats']['total_scans']}",
        f"- **Completed**: {data['stats']['scans_by_status']['completed']}",
        f"- **Failed**: {data['stats']['scans_by_status']['failed']}",
        f"- **Total Findings**: {data['stats']['total_findings']}",
        "",
        "## Findings by Severity",
    ]
    for sev, count in data["stats"]["findings_by_severity"].items():
        if count > 0:
            lines.append(f"- **{sev.capitalize()}**: {count}")

    lines.extend(["", "## Scan Details", ""])
    for scan in data["scans"]:
        lines.extend([
            f"### {scan['tool']} - {scan['target']}",
            f"- **Status**: {scan['status']}",
            f"- **Started**: {scan['started_at']}",
            f"- **Completed**: {scan['completed_at']}",
            "",
        ])

    if data["findings"]:
        lines.extend(["", "## Detailed Findings", ""])
        for finding in data["findings"]:
            lines.extend([
                f"### {finding['severity'].upper()}: {finding['title']}",
                f"- **Type**: {finding['type']}",
                f"- **Target**: {finding['target']}",
                f"- **Description**: {finding['description']}",
                "",
            ])

    return "\n".join(lines)


def generate_html_report(data: dict) -> str:
    """Generate HTML report."""
    md = generate_markdown_report(data)
    escaped = html.escape(md)
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>GhostMCP Security Assessment Report</title>
    <style>
        body {{ font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 1rem; }}
        h1, h2, h3 {{ color: #333; }}
        .critical {{ color: #dc2626; }}
        .high {{ color: #ea580c; }}
        .medium {{ color: #ca8a04; }}
        .low {{ color: #16a34a; }}
        .info {{ color: #2563eb; }}
    </style>
</head>
<body>
<pre>{escaped}</pre>
</body>
</html>"""


# ===== Static files =====

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
