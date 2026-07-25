"""Database layer for GhostMCP - scan history and engagement tracking."""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .redaction import redact_text, redact_url, redact_value


@dataclass
class Engagement:
    id: str
    name: str
    description: str | None
    scope_cidrs: list[str]
    scope_domains: list[str]
    max_tool_level: str
    created_at: str
    updated_at: str
    status: str  # active, completed, archived


@dataclass
class Scan:
    id: str
    engagement_id: str
    tool_name: str
    target: str
    parameters: dict[str, Any]
    status: str  # pending, running, completed, failed
    result: dict[str, Any] | None
    started_at: str | None
    completed_at: str | None
    error: str | None


@dataclass
class ScanFinding:
    id: str
    scan_id: str
    finding_type: str
    severity: str
    title: str
    description: str
    target: str
    raw_data: dict[str, Any]
    created_at: str


@dataclass
class QueryResult:
    rows: list[sqlite3.Row]
    rowcount: int

    def fetchone(self) -> sqlite3.Row | None:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> list[sqlite3.Row]:
        return list(self.rows)


class Database:
    """SQLite database for GhostMCP."""

    def __init__(self, db_path: str = "ghostmcp.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        if db_path != ":memory:":
            path = Path(db_path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.db_path = str(path)
        self._init_db()
        if self.db_path != ":memory:":
            os.chmod(self.db_path, 0o600)

    def _init_db(self):
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS engagements (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    scope_cidrs TEXT NOT NULL DEFAULT '[]',
                    scope_domains TEXT NOT NULL DEFAULT '[]',
                    max_tool_level TEXT NOT NULL DEFAULT 'intrusive',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    parameters TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    result TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    FOREIGN KEY (engagement_id) REFERENCES engagements (id)
                );

                CREATE TABLE IF NOT EXISTS scan_findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    target TEXT,
                    raw_data TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                );

                CREATE INDEX IF NOT EXISTS idx_scans_engagement ON scans (engagement_id);
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);
                CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings (scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON scan_findings (severity);
            """)
            conn.commit()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        try:
            yield conn
        finally:
            conn.close()

    def _execute(self, query: str, params: tuple = ()) -> QueryResult:
        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(query, params)
                rows = cursor.fetchall() if cursor.description else []
                rowcount = cursor.rowcount
                conn.commit()
                return QueryResult(rows=rows, rowcount=rowcount)

    # Engagement methods
    def create_engagement(
        self,
        engagement_id: str,
        name: str,
        description: str | None = None,
        scope_cidrs: list[str] | None = None,
        scope_domains: list[str] | None = None,
        max_tool_level: str = "intrusive",
    ) -> Engagement:
        now = datetime.now(UTC).isoformat()
        engagement = Engagement(
            id=engagement_id,
            name=name,
            description=redact_text(description) if description else None,
            scope_cidrs=scope_cidrs or [],
            scope_domains=scope_domains or [],
            max_tool_level=max_tool_level,
            created_at=now,
            updated_at=now,
            status="active",
        )
        self._execute(
            """INSERT INTO engagements (id, name, description, scope_cidrs, scope_domains,
               max_tool_level, created_at, updated_at, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement.id,
                engagement.name,
                engagement.description,
                json.dumps(engagement.scope_cidrs),
                json.dumps(engagement.scope_domains),
                engagement.max_tool_level,
                engagement.created_at,
                engagement.updated_at,
                engagement.status,
            ),
        )  # nosec B608
        return engagement

    def get_engagement(self, engagement_id: str) -> Engagement | None:
        cursor = self._execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,))  # nosec B608
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_engagement(row)

    def list_engagements(self, status: str | None = None) -> list[Engagement]:
        query = "SELECT * FROM engagements"
        params: tuple = ()
        if status:
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY created_at DESC"
        cursor = self._execute(query, params)  # nosec B608
        return [self._row_to_engagement(row) for row in cursor.fetchall()]

    def update_engagement(self, engagement_id: str, **kwargs) -> Engagement | None:
        engagement = self.get_engagement(engagement_id)
        if not engagement:
            return None

        allowed = {"name", "description", "scope_cidrs", "scope_domains", "max_tool_level", "status"}
        updates = []
        params = []
        for key, value in kwargs.items():
            if key in allowed:
                if key in ("scope_cidrs", "scope_domains"):
                    value = json.dumps(value)
                elif key == "description" and isinstance(value, str):
                    value = redact_text(value)
                updates.append(f"{key} = ?")
                params.append(value)

        if not updates:
            return engagement

        params.append(datetime.now(UTC).isoformat())
        params.append(engagement_id)

        query = f"UPDATE engagements SET {', '.join(updates)}, updated_at = ? WHERE id = ?"  # nosec B608
        self._execute(query, tuple(params))
        return self.get_engagement(engagement_id)

    def delete_engagement(self, engagement_id: str) -> bool:
        cursor = self._execute("DELETE FROM engagements WHERE id = ?", (engagement_id,))
        return cursor.rowcount > 0

    def _row_to_engagement(self, row: sqlite3.Row) -> Engagement:
        return Engagement(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            scope_cidrs=json.loads(row["scope_cidrs"]),
            scope_domains=json.loads(row["scope_domains"]),
            max_tool_level=row["max_tool_level"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            status=row["status"],
        )

    # Scan methods
    def create_scan(
        self,
        scan_id: str,
        engagement_id: str,
        tool_name: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> Scan:
        scan = Scan(
            id=scan_id,
            engagement_id=engagement_id,
            tool_name=tool_name,
            target=redact_url(target),
            parameters=redact_value(parameters or {}),
            status="pending",
            result=None,
            started_at=None,
            completed_at=None,
            error=None,
        )
        self._execute(
            """INSERT INTO scans (id, engagement_id, tool_name, target, parameters, status,
               started_at, completed_at, error, result)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan.id,
                scan.engagement_id,
                scan.tool_name,
                scan.target,
                json.dumps(scan.parameters),
                scan.status,
                scan.started_at,
                scan.completed_at,
                scan.error,
                json.dumps(scan.result) if scan.result else None,
            ),
        )  # nosec B608
        return scan

    def start_scan(self, scan_id: str) -> Scan | None:
        now = datetime.now(UTC).isoformat()
        self._execute(
            "UPDATE scans SET status = ?, started_at = ? WHERE id = ?",  # nosec B608
            ("running", now, scan_id),
        )
        return self.get_scan(scan_id)

    def complete_scan(self, scan_id: str, result: dict[str, Any] | None = None, error: str | None = None) -> Scan | None:
        now = datetime.now(UTC).isoformat()
        status = "failed" if error else "completed"
        self._execute(
            "UPDATE scans SET status = ?, completed_at = ?, result = ?, error = ? WHERE id = ?",  # nosec B608
            (
                status,
                now,
                json.dumps(redact_value(result)) if result else None,
                redact_text(error) if error else None,
                scan_id,
            ),
        )
        return self.get_scan(scan_id)

    def get_scan(self, scan_id: str) -> Scan | None:
        cursor = self._execute("SELECT * FROM scans WHERE id = ?", (scan_id,))  # nosec B608
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_scan(row)

    def list_scans(self, engagement_id: str | None = None, status: str | None = None) -> list[Scan]:
        query = "SELECT * FROM scans"
        conditions = []
        params = []
        if engagement_id:
            conditions.append("engagement_id = ?")
            params.append(engagement_id)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY started_at DESC"
        cursor = self._execute(query, tuple(params))  # nosec B608 - column names validated against allowed set
        return [self._row_to_scan(row) for row in cursor.fetchall()]

    def _row_to_scan(self, row: sqlite3.Row) -> Scan:
        return Scan(
            id=row["id"],
            engagement_id=row["engagement_id"],
            tool_name=row["tool_name"],
            target=row["target"],
            parameters=json.loads(row["parameters"]),
            status=row["status"],
            result=json.loads(row["result"]) if row["result"] else None,
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            error=row["error"],
        )

    # Finding methods
    def add_finding(
        self,
        finding_id: str,
        scan_id: str,
        finding_type: str,
        severity: str,
        title: str,
        description: str,
        target: str = "",
        raw_data: dict[str, Any] | None = None,
    ) -> ScanFinding:
        now = datetime.now(UTC).isoformat()
        finding = ScanFinding(
            id=finding_id,
            scan_id=scan_id,
            finding_type=finding_type,
            severity=severity,
            title=title,
            description=redact_text(description),
            target=redact_url(target),
            raw_data=redact_value(raw_data or {}),
            created_at=now,
        )
        self._execute(
            """INSERT INTO scan_findings (id, scan_id, finding_type, severity, title,
               description, target, raw_data, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.id,
                finding.scan_id,
                finding.finding_type,
                finding.severity,
                finding.title,
                finding.description,
                finding.target,
                json.dumps(finding.raw_data),
                finding.created_at,
            ),
        )  # nosec B608
        return finding

    def get_findings(self, scan_id: str) -> list[ScanFinding]:
        cursor = self._execute("SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY created_at DESC", (scan_id,))  # nosec B608
        return [self._row_to_finding(row) for row in cursor.fetchall()]

    def get_findings_by_severity(self, engagement_id: str, severity: str | None = None) -> list[ScanFinding]:
        query = """
            SELECT f.* FROM scan_findings f
            JOIN scans s ON f.scan_id = s.id
            WHERE s.engagement_id = ?
        """
        params = [engagement_id]
        if severity:
            query += " AND f.severity = ?"
            params.append(severity)
        query += " ORDER BY f.created_at DESC"
        cursor = self._execute(query, tuple(params))  # nosec B608 - column names validated against allowed set
        return [self._row_to_finding(row) for row in cursor.fetchall()]

    def _row_to_finding(self, row: sqlite3.Row) -> ScanFinding:
        return ScanFinding(
            id=row["id"],
            scan_id=row["scan_id"],
            finding_type=row["finding_type"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            target=row["target"],
            raw_data=json.loads(row["raw_data"]),
            created_at=row["created_at"],
        )

    # Utility
    def get_engagement_stats(self, engagement_id: str) -> dict[str, Any]:
        """Get statistics for an engagement."""
        scans = self.list_scans(engagement_id=engagement_id)
        findings = self.get_findings_by_severity(engagement_id)

        return {
            "engagement_id": engagement_id,
            "total_scans": len(scans),
            "scans_by_status": {
                "pending": len([s for s in scans if s.status == "pending"]),
                "running": len([s for s in scans if s.status == "running"]),
                "completed": len([s for s in scans if s.status == "completed"]),
                "failed": len([s for s in scans if s.status == "failed"]),
            },
            "total_findings": len(findings),
            "findings_by_severity": {
                "critical": len([f for f in findings if f.severity == "critical"]),
                "high": len([f for f in findings if f.severity == "high"]),
                "medium": len([f for f in findings if f.severity == "medium"]),
                "low": len([f for f in findings if f.severity == "low"]),
                "info": len([f for f in findings if f.severity == "info"]),
            },
        }


def get_database() -> Database:
    """Get database instance from environment."""
    db_type = os.getenv("GHOSTMCP_DB_TYPE", "sqlite").lower()
    if db_type == "postgres":
        dsn = os.getenv("GHOSTMCP_DB_DSN")
        if not dsn:
            raise RuntimeError("GHOSTMCP_DB_DSN required for PostgreSQL")
        # Return a stub that raises NotImplementedError for now
        raise NotImplementedError("PostgreSQL backend not fully implemented yet")
    else:
        db_path = os.getenv("GHOSTMCP_DB_PATH", "ghostmcp.db")
        return Database(db_path)
