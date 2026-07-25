"""Worker-backed execution for dashboard scans and schedules."""

from __future__ import annotations

import ipaddress
import logging
import queue
import shutil
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import load_config
from .database import Database, Engagement, Scan
from .scanners import (
    amass_passive_enum,
    assetfinder_scan,
    cloudflair_scan,
    dirsearch_scan,
    dnsrecon_scan,
    dnsx_scan,
    feroxbuster_scan,
    ffuf_scan,
    gitleaks_scan,
    gobuster_dir_scan,
    gowitness_scan,
    jaeles_scan,
    nikto_scan,
    nmap_service_scan,
    nuclei_scan,
    sslscan_target,
    subfinder_scan,
    trufflehog_scan,
    wafw00f_scan,
    wfuzz_scan,
    whatweb_scan,
    wpscan_scan,
)
from .scheduling import CronExpression
from .security import SecurityPolicy

TOOL_LEVELS = {"passive": 1, "active": 2, "intrusive": 3}
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExecutorDefinition:
    level: str
    binary: str | None
    run: Callable[[SecurityPolicy, str, dict[str, Any]], dict[str, Any]]


def _reject_unknown_params(
    params: dict[str, Any], allowed: set[str]
) -> None:
    unknown = set(params) - allowed
    if unknown:
        raise ValueError(f"Unsupported scan parameters: {sorted(unknown)}")


def _url_runner(function: Callable[[str], dict[str, Any]]):
    def run(
        policy: SecurityPolicy, target: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        _reject_unknown_params(params, set())
        policy.validate_url(target)
        return function(target)

    return run


def _domain_runner(function: Callable[[str], dict[str, Any]]):
    def run(
        policy: SecurityPolicy, target: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        _reject_unknown_params(params, set())
        domain = policy.validate_domain(target)
        return function(domain)

    return run


def _wordlist_url_runner(function: Callable[..., dict[str, Any]]):
    def run(
        policy: SecurityPolicy, target: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        _reject_unknown_params(params, {"wordlist"})
        policy.validate_url(target)
        if "wordlist" not in params:
            return function(target)
        return function(
            target,
            wordlist=str(_local_path(policy, str(params["wordlist"]))),
        )

    return run


def _gobuster_runner(
    policy: SecurityPolicy, target: str, params: dict[str, Any]
) -> dict[str, Any]:
    _reject_unknown_params(params, {"wordlist", "threads"})
    policy.validate_url(target)
    kwargs: dict[str, Any] = {}
    if "wordlist" in params:
        kwargs["wordlist"] = str(
            _local_path(policy, str(params["wordlist"]))
        )
    if "threads" in params:
        threads = int(params["threads"])
        if threads < 1 or threads > 64:
            raise ValueError("threads must be between 1 and 64")
        kwargs["threads"] = threads
    return gobuster_dir_scan(target, **kwargs)


def _nuclei_runner(
    policy: SecurityPolicy, target: str, params: dict[str, Any]
) -> dict[str, Any]:
    _reject_unknown_params(params, {"templates"})
    policy.validate_url(target)
    templates = params.get("templates")
    if templates is None:
        return nuclei_scan(target)
    return nuclei_scan(
        target, templates=str(_local_path(policy, str(templates)))
    )


def _dnsrecon_runner(
    policy: SecurityPolicy, target: str, params: dict[str, Any]
) -> dict[str, Any]:
    _reject_unknown_params(params, {"scan_type"})
    domain = policy.validate_domain(target)
    scan_type = str(params.get("scan_type", "std"))
    if scan_type not in {"std", "brt", "srv", "axfr"}:
        raise ValueError("Unsupported dnsrecon scan_type")
    return dnsrecon_scan(domain, scan_type=scan_type)


def _nmap_runner(
    policy: SecurityPolicy, target: str, params: dict[str, Any]
) -> dict[str, Any]:
    _reject_unknown_params(params, {"top_ports"})
    validated = policy.validate_target(target)
    top_ports = int(params.get("top_ports", 100))
    if top_ports < 1 or top_ports > policy.config.max_ports_per_scan:
        raise ValueError("top_ports exceeds engagement policy")
    return nmap_service_scan(validated.host, top_ports=top_ports)


def _sslscan_runner(
    policy: SecurityPolicy, target: str, params: dict[str, Any]
) -> dict[str, Any]:
    _reject_unknown_params(params, {"port"})
    validated = policy.validate_target(target)
    port = policy.parse_ports([int(params.get("port", 443))])[0]
    return sslscan_target(validated.host, port=port)


def _local_path(policy: SecurityPolicy, target: str) -> Path:
    candidate = Path(target).expanduser().resolve(strict=True)
    policy.validate_path(str(candidate))
    return candidate


def _file_runner(function: Callable[..., dict[str, Any]]):
    def run(
        policy: SecurityPolicy, target: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        _reject_unknown_params(params, set())
        return function(str(_local_path(policy, target)))

    return run


EXECUTORS: dict[str, ExecutorDefinition] = {
    "nmap_service_scan_tool": ExecutorDefinition("intrusive", "nmap", _nmap_runner),
    "whatweb_tool": ExecutorDefinition("active", "whatweb", _url_runner(whatweb_scan)),
    "nikto_tool": ExecutorDefinition("intrusive", "nikto", _url_runner(nikto_scan)),
    "amass_passive_tool": ExecutorDefinition(
        "passive", "amass", _domain_runner(amass_passive_enum)
    ),
    "gobuster_dir_tool": ExecutorDefinition(
        "intrusive", "gobuster", _gobuster_runner
    ),
    "sslscan_tool": ExecutorDefinition("active", "sslscan", _sslscan_runner),
    "wafw00f_tool": ExecutorDefinition("active", "wafw00f", _url_runner(wafw00f_scan)),
    "nuclei_tool": ExecutorDefinition("intrusive", "nuclei", _nuclei_runner),
    "ffuf_tool": ExecutorDefinition(
        "intrusive", "ffuf", _wordlist_url_runner(ffuf_scan)
    ),
    "feroxbuster_tool": ExecutorDefinition(
        "intrusive", "feroxbuster", _wordlist_url_runner(feroxbuster_scan)
    ),
    "wfuzz_tool": ExecutorDefinition(
        "intrusive", "wfuzz", _wordlist_url_runner(wfuzz_scan)
    ),
    "subfinder_tool": ExecutorDefinition(
        "passive", "subfinder", _domain_runner(subfinder_scan)
    ),
    "assetfinder_tool": ExecutorDefinition(
        "passive", "assetfinder", _domain_runner(assetfinder_scan)
    ),
    "dnsx_tool": ExecutorDefinition("passive", "dnsx", _domain_runner(dnsx_scan)),
    "gowitness_tool": ExecutorDefinition(
        "active", "gowitness", _url_runner(gowitness_scan)
    ),
    "jaeles_tool": ExecutorDefinition("intrusive", "jaeles", _url_runner(jaeles_scan)),
    "cloudflair_tool": ExecutorDefinition(
        "active", "cloudflair", _domain_runner(cloudflair_scan)
    ),
    "dnsrecon_tool": ExecutorDefinition(
        "active", "dnsrecon", _dnsrecon_runner
    ),
    "wpscan_tool": ExecutorDefinition("intrusive", "wpscan", _url_runner(wpscan_scan)),
    "dirsearch_tool": ExecutorDefinition(
        "intrusive", "dirsearch", _url_runner(dirsearch_scan)
    ),
    "trufflehog_tool": ExecutorDefinition(
        "passive", "trufflehog", _file_runner(trufflehog_scan)
    ),
    "gitleaks_tool": ExecutorDefinition(
        "passive", "gitleaks", _file_runner(gitleaks_scan)
    ),
}


def available_dashboard_tools() -> list[str]:
    return sorted(EXECUTORS)


def _engagement_policy(engagement: Engagement) -> SecurityPolicy:
    base = load_config()
    base_policy = SecurityPolicy(base)
    if base.engagement_policy_file is not None:
        scoped = base_policy.for_engagement(engagement.id)
        if (
            TOOL_LEVELS[engagement.max_tool_level]
            > TOOL_LEVELS[scoped.config.max_tool_level]
        ):
            raise PermissionError(
                "Dashboard engagement exceeds policy-backed tool ceiling"
            )
        return scoped
    if (
        engagement.max_tool_level == "intrusive"
        and not base.allow_unscoped_intrusive
    ):
        raise PermissionError(
            "Intrusive dashboard execution requires a policy-backed engagement"
        )
    if TOOL_LEVELS[engagement.max_tool_level] > TOOL_LEVELS[base.max_tool_level]:
        raise PermissionError(
            "Dashboard engagement exceeds the server tool ceiling"
        )
    cidrs = tuple(
        ipaddress.ip_network(value, strict=False) for value in engagement.scope_cidrs
    )
    if not cidrs and not engagement.scope_domains:
        raise PermissionError(
            "Dashboard engagement requires an explicit CIDR or domain scope"
        )
    return base_policy.narrow(
        {
            "allowed_cidrs": [
                str(item) for item in (cidrs or base.allowed_cidrs)
            ],
            "allowed_domains": (
                list(engagement.scope_domains)
                or list(base.allowed_domains)
            ),
            "allowed_paths": [str(item) for item in base.allowed_paths],
            "forbidden_paths": [str(item) for item in base.forbidden_paths],
            "allowed_resources": list(base.allowed_resources),
            "allowed_capabilities": list(base.allowed_capabilities),
            "max_tool_level": engagement.max_tool_level,
        }
    )


class ScanExecutor:
    def __init__(self, database: Database):
        self.database = database

    def execute(self, scan_id: str) -> Scan:
        scan = self.database.get_scan(scan_id)
        if scan is None:
            raise ValueError(f"Unknown scan: {scan_id}")
        try:
            engagement = self.database.get_engagement(scan.engagement_id)
            if engagement is None:
                raise ValueError(f"Unknown engagement: {scan.engagement_id}")
            definition = EXECUTORS.get(scan.tool_name)
            if definition is None:
                raise ValueError(f"Unsupported dashboard tool: {scan.tool_name}")
            if TOOL_LEVELS[definition.level] > TOOL_LEVELS[engagement.max_tool_level]:
                raise PermissionError(
                    f"Tool level {definition.level} exceeds engagement max "
                    f"{engagement.max_tool_level}"
                )
            if definition.binary and shutil.which(definition.binary) is None:
                raise RuntimeError(
                    f"Required binary is not installed: {definition.binary}"
                )
            if self.database.start_scan(scan_id) is None:
                raise RuntimeError("Scan is not in an executable state")
            result = definition.run(
                _engagement_policy(engagement), scan.target, scan.parameters
            )
        except Exception as exc:
            completed = self.database.complete_scan(scan_id, error=str(exc))
            if completed is None:
                raise RuntimeError("Unable to persist failed scan") from exc
            return completed
        completed = self.database.complete_scan(scan_id, result=result)
        if completed is None:
            raise RuntimeError("Unable to persist completed scan")
        return completed


class ScanWorker:
    def __init__(self, database: Database):
        self.database = database
        self.executor = ScanExecutor(database)
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run, name="ghostmcp-scan-worker", daemon=True
        )
        self._thread.start()

    def submit(self, scan_id: str) -> None:
        if self._thread is None or not self._thread.is_alive():
            raise RuntimeError("Scan worker is not running")
        self._queue.put(scan_id)

    def stop(self, timeout: float = 5.0) -> None:
        if self._thread is None:
            return
        self._queue.put(None)
        self._thread.join(timeout=timeout)
        self._thread = None

    def _run(self) -> None:
        while True:
            scan_id = self._queue.get()
            try:
                if scan_id is None:
                    return
                try:
                    self.executor.execute(scan_id)
                except Exception as exc:
                    logger.exception("Unhandled scan worker failure for %s", scan_id)
                    if self.database.get_scan(scan_id) is not None:
                        self.database.complete_scan(scan_id, error=str(exc))
            finally:
                self._queue.task_done()


class ScanScheduler:
    def __init__(
        self, database: Database, worker: ScanWorker, poll_seconds: float = 30.0
    ):
        self.database = database
        self.worker = worker
        self.poll_seconds = max(1.0, poll_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="ghostmcp-scan-scheduler", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def run_due_once(self, now: datetime | None = None) -> int:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        lease_until = current.timestamp() + max(60.0, self.poll_seconds * 3)
        claimed_until = datetime.fromtimestamp(lease_until, tz=UTC).isoformat()
        schedules = self.database.claim_due_schedules(
            current.isoformat(), claimed_until
        )
        submitted = 0
        for schedule in schedules:
            try:
                scan_id = uuid.uuid4().hex[:12]
                self.database.create_scan(
                    scan_id,
                    schedule.engagement_id,
                    schedule.tool_name,
                    schedule.target,
                    schedule.parameters,
                )
                if self.database.queue_scan(scan_id) is None:
                    raise RuntimeError("Unable to queue scheduled scan")
                self.worker.submit(scan_id)
                cron = CronExpression.parse(schedule.cron_expression)
                self.database.mark_schedule_run(
                    schedule.id,
                    last_run_at=current.isoformat(),
                    next_run_at=cron.next_after(current).isoformat(),
                )
                submitted += 1
            except Exception:
                self.database.release_schedule_claim(schedule.id)
                logger.exception("Unable to execute schedule %s", schedule.id)
        return submitted

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_due_once()
            except Exception:
                logger.exception("Unhandled scan scheduler failure")
            self._stop.wait(self.poll_seconds)
