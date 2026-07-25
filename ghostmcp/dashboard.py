"""Web dashboard for GhostMCP - FastAPI + HTMX."""

import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .database import get_database
from .execution import ScanScheduler, ScanWorker, available_dashboard_tools
from .scheduling import CronExpression

_db = None
_worker: ScanWorker | None = None
_scheduler: ScanScheduler | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _worker, _scheduler
    database = get_db()
    _worker = ScanWorker(database)
    _scheduler = ScanScheduler(
        database,
        _worker,
        poll_seconds=float(os.getenv("GHOSTMCP_SCHEDULER_POLL_SECONDS", "30")),
    )
    _worker.start()
    _scheduler.start()
    try:
        yield
    finally:
        _scheduler.stop()
        _worker.stop()
        _scheduler = None
        _worker = None


app = FastAPI(title="GhostMCP Dashboard", version="0.2.0", lifespan=lifespan)

# Templates
template_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))

# Database
def get_db():
    global _db
    if _db is None:
        _db = get_database()
    return _db


# Helper functions
def _generate_id() -> str:
    return uuid.uuid4().hex[:12]


def _parse_parameters(parameters: str) -> dict:
    try:
        value = json.loads(parameters) if parameters else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Parameters must be valid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="Parameters must be a JSON object")
    return value


def _scan_worker() -> ScanWorker:
    if _worker is None:
        raise HTTPException(status_code=503, detail="Scan worker is not running")
    return _worker


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
    max_tool_level: str = Form(default="active"),
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

    if tool_name not in available_dashboard_tools():
        raise HTTPException(status_code=400, detail="Unsupported dashboard tool")
    scan_id = _generate_id()
    params = _parse_parameters(parameters)

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
    """Queue a pending scan for worker-backed execution."""
    scan = get_db().get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    queued = get_db().queue_scan(scan_id)
    if queued is None:
        raise HTTPException(status_code=409, detail="Scan is not queueable")
    try:
        _scan_worker().submit(scan_id)
    except Exception as exc:
        get_db().complete_scan(scan_id, error=str(exc))
        raise HTTPException(status_code=503, detail="Scan worker is unavailable") from exc
    return {"status": "queued", "scan": queued.id}


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

    tools = available_dashboard_tools()

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
    """Create an executable recurring scan schedule."""
    db = get_db()
    engagement = db.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if tool_name not in available_dashboard_tools():
        raise HTTPException(status_code=400, detail="Unsupported dashboard tool")
    params = _parse_parameters(parameters)
    try:
        cron = CronExpression.parse(cron_expression)
        next_run = cron.next_after(datetime.now(UTC))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    schedule = db.create_schedule(
        schedule_id=_generate_id(),
        engagement_id=engagement_id,
        tool_name=tool_name,
        target=target,
        parameters=params,
        cron_expression=cron_expression,
        next_run_at=next_run.isoformat(),
    )
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(
            request,
            "schedule/row.html",
            {"request": request, "schedule": schedule},
        )
    schedules = db.list_schedules(engagement_id)
    return templates.TemplateResponse(
        request,
        "schedule/list.html",
        {
            "request": request,
            "engagement": engagement,
            "schedules": schedules,
        },
    )


@app.post("/schedules/{schedule_id}/enabled")
async def set_schedule_enabled(
    schedule_id: str, enabled: bool = Form(...),
):
    schedule = get_db().set_schedule_enabled(schedule_id, enabled)
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "ok", "enabled": schedule.enabled}


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
    # Simple markdown to HTML conversion
    html = md.replace("\n", "<br>")
    html = html.replace("# ", "<h1>").replace("## ", "<h2>").replace("### ", "<h3>")
    html = html.replace("**", "<strong>").replace("* ", "<li>")
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>{data['engagement']['name']} - Report</title>
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
{html}
</body>
</html>"""


# ===== Static files =====

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
