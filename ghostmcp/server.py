from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import shutil
import signal
import ssl
import sys
import threading
import time
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Literal, get_type_hints
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from .config import load_config
from .logging_utils import configure_logging
from .rate_limit import SlidingWindowRateLimiter
from .scanners import (
    ScannerError,
    ScannerTimeoutError,
    amass_passive_enum,
    dns_lookup,
    extract_iocs,
    fetch_security_txt,
    generate_common_web_paths,
    generate_subdomain_candidates,
    gobuster_dir_scan,
    http_probe,
    nikto_scan,
    nmap_service_scan,
    port_scan,
    reverse_dns,
    run_external_binary,
    sslscan_target,
    terminate_active_processes,
    tls_certificate,
    tls_certificate_expiry,
    url_risk_score,
    wafw00f_scan,
    whatweb_scan,
    whois_query,
)
from .security import SecurityPolicy

configure_logging()
logger = logging.getLogger(__name__)


def _env(name: str, default: str) -> str:
    return os.getenv(f"GHOSTMCP_{name}", default)


cfg = load_config()
policy = SecurityPolicy(cfg)
rate_limiter = SlidingWindowRateLimiter(
    max_calls=int(_env("RATE_LIMIT_CALLS", "120")),
    window_seconds=int(_env("RATE_LIMIT_WINDOW_SECONDS", "60")),
)
STARTED_AT = datetime.now(UTC)

mcp = FastMCP(
    "ghostmcp-tooling",
    instructions=(
        "GhostMCP cybersecurity tooling server. Passive recon, TLS inspection, DNS "
        "lookup, WHOIS, and policy-guarded TCP port checks for authorized targets."
    ),
)

TOOL_LEVELS = {"passive": 1, "active": 2, "intrusive": 3}
_audit_lock = threading.Lock()
_last_audit_hash = "0" * 64
_metrics_lock = threading.Lock()
_shutdown_event = threading.Event()
AUDIT_SINK_PATH = _env("AUDIT_SINK_PATH", "").strip()

TRANSPORT_MODE = _env("TRANSPORT_MODE", "stdio").strip().lower()
AUTH_MODE = _env("AUTH_MODE", "none").strip().lower()
AUTH_TOKEN = _env("AUTH_TOKEN", "").strip()
MTLS_CA_CERT = _env("MTLS_CA_CERT_PATH", "").strip()
MTLS_CERT = _env("MTLS_CERT_PATH", "").strip()
MTLS_KEY = _env("MTLS_KEY_PATH", "").strip()
HTTP_HOST = _env("HTTP_HOST", "127.0.0.1").strip()
HTTP_PORT = int(_env("HTTP_PORT", "8000"))
ALLOW_INSECURE_REMOTE_NO_AUTH = _env("ALLOW_INSECURE_REMOTE_NO_AUTH", "false").strip().lower() in {
    "1",
    "true",
    "yes",
}
ALLOW_RUN_AS_ROOT = _env("ALLOW_RUN_AS_ROOT", "false").strip().lower() in {
    "1",
    "true",
    "yes",
}

TOOL_CLASS_LIMITS = {
    "passive": threading.Semaphore(int(_env("MAX_PASSIVE_PARALLEL", "64"))),
    "active": threading.Semaphore(int(_env("MAX_ACTIVE_PARALLEL", "16"))),
    "intrusive": threading.Semaphore(int(_env("MAX_INTRUSIVE_PARALLEL", "4"))),
}

METRICS = {
    "calls_total": 0,
    "success_total": 0,
    "failures_total": 0,
    "timeouts_total": 0,
    "denied_total": 0,
    "duration_ms_total": 0,
    "per_tool": {},
}

KALI_COMMON_TOOL_BINARIES = [
    "nmap",
    "masscan",
    "amass",
    "subfinder",
    "assetfinder",
    "dnsx",
    "dnsrecon",
    "dnsenum",
    "fierce",
    "theharvester",
    "recon-ng",
    "whatweb",
    "wafw00f",
    "nikto",
    "gobuster",
    "ffuf",
    "dirsearch",
    "feroxbuster",
    "wfuzz",
    "sqlmap",
    "xsser",
    "commix",
    "wpscan",
    "joomscan",
    "sslyze",
    "sslscan",
    "testssl.sh",
    "hydra",
    "medusa",
    "patator",
    "crackmapexec",
    "netexec",
    "enum4linux",
    "enum4linux-ng",
    "smbclient",
    "smbmap",
    "rpcclient",
    "kerbrute",
    "impacket-secretsdump",
    "impacket-psexec",
    "impacket-wmiexec",
    "responder",
    "mitm6",
    "ettercap",
    "bettercap",
    "tcpdump",
    "wireshark",
    "tshark",
    "ngrep",
    "hping3",
    "netcat",
    "nc",
    "socat",
    "aircrack-ng",
    "hashcat",
    "john",
    "cewl",
    "hash-identifier",
    "binwalk",
    "exiftool",
    "radare2",
    "ghidra",
    "gdb",
    "pwndbg",
    "msfconsole",
    "searchsploit",
    "exploitdb",
    "evil-winrm",
    "bloodhound-python",
    "neo4j",
]

SUPPORTED_EXTERNAL_TOOL_BINARIES = {
    "nmap_service_scan_tool": "nmap",
    "whatweb_tool": "whatweb",
    "nikto_tool": "nikto",
    "amass_passive_tool": "amass",
    "gobuster_dir_tool": "gobuster",
    "sslscan_tool": "sslscan",
    "wafw00f_tool": "wafw00f",
}


def _binary_to_tool_name(binary: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in binary).strip("_")
    return f"{safe}_raw_tool"


DYNAMIC_KALI_RAW_TOOL_BINARIES = {
    _binary_to_tool_name(binary): binary for binary in KALI_COMMON_TOOL_BINARIES
}


def _discover_toolchain() -> dict[str, dict[str, str | bool | None]]:
    snapshot: dict[str, dict[str, str | bool | None]] = {}
    for binary in KALI_COMMON_TOOL_BINARIES:
        path = shutil.which(binary)
        snapshot[binary] = {"installed": bool(path), "path": path}
    return snapshot


KALI_TOOLCHAIN_SNAPSHOT = _discover_toolchain()
BINARY_MCP_TOOL_BINARIES = {
    **SUPPORTED_EXTERNAL_TOOL_BINARIES,
    **DYNAMIC_KALI_RAW_TOOL_BINARIES,
}
ENABLED_BINARY_MCP_TOOLS = sorted(
    tool_name
    for tool_name, binary in BINARY_MCP_TOOL_BINARIES.items()
    if KALI_TOOLCHAIN_SNAPSHOT.get(binary, {}).get("installed")
)


def _validate_runtime_security() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not ALLOW_RUN_AS_ROOT:
        raise RuntimeError(
            "Refusing to run as root. Set GHOSTMCP_ALLOW_RUN_AS_ROOT=true to override."
        )


def _validate_transport_auth_configuration() -> None:
    if TRANSPORT_MODE not in {"stdio", "remote_gateway"}:
        raise RuntimeError("GHOSTMCP_TRANSPORT_MODE must be 'stdio' or 'remote_gateway'")
    if AUTH_MODE not in {"none", "token", "mtls"}:
        raise RuntimeError("GHOSTMCP_AUTH_MODE must be 'none', 'token', or 'mtls'")
    if TRANSPORT_MODE == "remote_gateway" and AUTH_MODE == "none":
        if not ALLOW_INSECURE_REMOTE_NO_AUTH:
            raise RuntimeError(
                "remote_gateway mode with AUTH_MODE=none is blocked. "
                "Set GHOSTMCP_ALLOW_INSECURE_REMOTE_NO_AUTH=true to override (unsafe)."
            )
        logger.warning(
            "Running remote_gateway mode without auth due to explicit unsafe override."
        )
    if AUTH_MODE == "token" and not AUTH_TOKEN:
        raise RuntimeError("token auth mode requires GHOSTMCP_AUTH_TOKEN")
    if AUTH_MODE == "mtls":
        for required in (MTLS_CA_CERT, MTLS_CERT, MTLS_KEY):
            if not required:
                raise RuntimeError(
                    "mtls auth mode requires GHOSTMCP_MTLS_CA_CERT_PATH, "
                    "GHOSTMCP_MTLS_CERT_PATH, and GHOSTMCP_MTLS_KEY_PATH"
                )
            if not Path(required).exists():
                raise RuntimeError(f"mTLS file not found: {required}")


def _setdefault_tool_metrics(tool_name: str) -> dict:
    per_tool = METRICS["per_tool"]
    if tool_name not in per_tool:
        per_tool[tool_name] = {
            "calls": 0,
            "success": 0,
            "failures": 0,
            "timeouts": 0,
            "denied": 0,
            "duration_ms_total": 0,
        }
    return per_tool[tool_name]


def _record_call_start(tool_name: str) -> None:
    with _metrics_lock:
        METRICS["calls_total"] += 1
        tool_metrics = _setdefault_tool_metrics(tool_name)
        tool_metrics["calls"] += 1


def _record_call_denied(tool_name: str) -> None:
    with _metrics_lock:
        METRICS["denied_total"] += 1
        tool_metrics = _setdefault_tool_metrics(tool_name)
        tool_metrics["denied"] += 1


def _record_call_result(
    tool_name: str,
    success: bool,
    duration_ms: int,
    timed_out: bool = False,
) -> None:
    with _metrics_lock:
        METRICS["duration_ms_total"] += duration_ms
        tool_metrics = _setdefault_tool_metrics(tool_name)
        tool_metrics["duration_ms_total"] += duration_ms
        if success:
            METRICS["success_total"] += 1
            tool_metrics["success"] += 1
            return
        METRICS["failures_total"] += 1
        tool_metrics["failures"] += 1
        if timed_out:
            METRICS["timeouts_total"] += 1
            tool_metrics["timeouts"] += 1


def _instrument_tool(tool_name: str, tool_level: Literal["passive", "active", "intrusive"]):
    def decorator(fn):
        fn_signature = inspect.signature(fn)
        resolved_hints = get_type_hints(fn, globalns=fn.__globals__, include_extras=True)

        @wraps(fn)
        def wrapped(*args, **kwargs):
            _record_call_start(tool_name)
            started = time.monotonic()
            try:
                with TOOL_CLASS_LIMITS[tool_level]:
                    result = fn(*args, **kwargs)
            except ScannerTimeoutError:
                duration_ms = int((time.monotonic() - started) * 1000)
                _record_call_result(tool_name, success=False, duration_ms=duration_ms, timed_out=True)
                raise
            except Exception:
                duration_ms = int((time.monotonic() - started) * 1000)
                _record_call_result(tool_name, success=False, duration_ms=duration_ms)
                raise
            duration_ms = int((time.monotonic() - started) * 1000)
            _record_call_result(tool_name, success=True, duration_ms=duration_ms)
            return result

        # FastMCP inspects function signatures for tool schemas; preserve original params.
        resolved_params = []
        for name, param in fn_signature.parameters.items():
            annotation = resolved_hints.get(name, param.annotation)
            resolved_params.append(param.replace(annotation=annotation))
        resolved_return = resolved_hints.get("return", fn_signature.return_annotation)
        wrapped.__signature__ = fn_signature.replace(  # type: ignore[attr-defined]
            parameters=resolved_params,
            return_annotation=resolved_return,
        )
        wrapped.__annotations__ = {
            **{k: v for k, v in resolved_hints.items() if k != "return"},
            "return": resolved_return,
        }
        return wrapped

    return decorator


ARG_TOKEN_RE = r"^[A-Za-z0-9._:/=,+-]+$"
RAW_TOOL_ARG_ALLOW_PREFIX = {
    "nmap": ["-s", "-p", "-Pn", "-T", "--top-ports", "--script"],
    "gobuster": ["dir", "-u", "-w", "-t", "--no-error", "-x", "-k"],
    "nikto": ["-host", "-Format", "-ssl", "-port"],
}
MAX_RAW_ARG_COUNT = int(_env("MAX_RAW_ARG_COUNT", "24"))
MAX_RAW_ARG_LENGTH = int(_env("MAX_RAW_ARG_LENGTH", "256"))
MAX_RAW_RUNTIME_SECONDS = int(_env("MAX_RAW_RUNTIME_SECONDS", "180"))
MAX_RAW_STDOUT_BYTES = int(_env("MAX_RAW_STDOUT_BYTES", "20000"))
MAX_RAW_STDERR_BYTES = int(_env("MAX_RAW_STDERR_BYTES", "8000"))


def _validate_raw_tool_args(binary: str, args: list[str] | None) -> list[str]:
    import re

    if not args:
        return []
    if len(args) > MAX_RAW_ARG_COUNT:
        raise ValueError("Too many args for raw binary tool invocation")
    for arg in args:
        if len(arg) > MAX_RAW_ARG_LENGTH:
            raise ValueError("Arg exceeds max length")
        if not re.match(ARG_TOKEN_RE, arg):
            raise ValueError("Arg contains disallowed characters")
        if any(token in arg for token in ["..", ";", "|", "&", "$(", "`", "\n", "\r"]):
            raise ValueError("Arg contains unsafe shell token")
    prefixes = RAW_TOOL_ARG_ALLOW_PREFIX.get(binary)
    if prefixes and not all(any(arg.startswith(p) for p in prefixes) for arg in args if arg.startswith("-") or arg in {"dir"}):
        raise ValueError(f"Args not allowed by policy for {binary}")
    return args


def _optional_binary_tool(tool_name: str):
    binary = BINARY_MCP_TOOL_BINARIES[tool_name]
    if KALI_TOOLCHAIN_SNAPSHOT.get(binary, {}).get("installed"):
        return mcp.tool()

    logger.warning(
        "Skipping MCP registration for %s; missing binary: %s",
        tool_name,
        binary,
    )

    def passthrough(fn):
        return fn

    return passthrough


def _register_dynamic_kali_raw_tools() -> None:
    for tool_name, binary in DYNAMIC_KALI_RAW_TOOL_BINARIES.items():
        if not KALI_TOOLCHAIN_SNAPSHOT.get(binary, {}).get("installed"):
            continue

        def _factory(name: str, bin_name: str):
            def _tool(
                args: list[str] | None = None,
                timeout_s: float = 120.0,
                engagement_id: str | None = None,
                engagement_mode: Literal["passive", "active", "intrusive"] = "intrusive",
                auth_token: str | None = None,
            ) -> dict:
                context = _authorize(
                    name,
                    "intrusive",
                    engagement_id,
                    engagement_mode,
                    auth_token=auth_token,
                )
                _audit_tool_call(name, context, target=bin_name)
                safe_args = _validate_raw_tool_args(bin_name, args)
                result = run_external_binary(
                    binary=bin_name,
                    args=safe_args,
                    timeout_s=min(timeout_s, MAX_RAW_RUNTIME_SECONDS),
                    max_stdout_bytes=MAX_RAW_STDOUT_BYTES,
                    max_stderr_bytes=MAX_RAW_STDERR_BYTES,
                )
                result["generated_tool"] = name
                return result

            _tool.__name__ = name
            _tool.__doc__ = (
                f"Run raw Kali tool '{bin_name}' with optional args."
            )
            return _instrument_tool(name, "intrusive")(_tool)

        mcp.tool()(_factory(tool_name, binary))


def _install_signal_handlers() -> None:
    def _handle_shutdown(signum: int, _frame: object) -> None:
        name = signal.Signals(signum).name
        _shutdown_event.set()
        print(
            f"\n[GhostMCP] Received {name}. Shutting down now.",
            file=sys.stderr,
            flush=True,
        )
        terminated = terminate_active_processes()
        if terminated:
            print(
                f"[GhostMCP] Terminated {terminated} active subprocess(es).",
                file=sys.stderr,
                flush=True,
            )
        # FastMCP/transport loops may swallow SystemExit; force process teardown.
        os._exit(130 if signum == signal.SIGINT else 143)

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)


def _enforce_budget() -> None:
    if not rate_limiter.allow():
        raise RuntimeError("Rate limit exceeded. Retry later.")


def _authorize(
    tool_name: str,
    tool_level: Literal["passive", "active", "intrusive"],
    engagement_id: str | None,
    engagement_mode: Literal["passive", "active", "intrusive"],
    auth_token: str | None = None,
) -> dict:
    _enforce_budget()

    if cfg.require_engagement_context and not engagement_id:
        _record_call_denied(tool_name)
        raise ValueError("engagement_id is required by policy")
    if TRANSPORT_MODE == "remote_gateway":
        if AUTH_MODE == "token" and auth_token != AUTH_TOKEN:
            _record_call_denied(tool_name)
            raise PermissionError("Invalid auth token")

    configured_max = cfg.max_tool_level
    if configured_max not in TOOL_LEVELS:
        configured_max = "intrusive"
    if TOOL_LEVELS[tool_level] > TOOL_LEVELS[configured_max]:
        _record_call_denied(tool_name)
        raise ValueError(
            f"Tool level '{tool_level}' exceeds configured max '{configured_max}'"
        )
    if TOOL_LEVELS[tool_level] > TOOL_LEVELS[engagement_mode]:
        _record_call_denied(tool_name)
        raise ValueError(
            f"Tool level '{tool_level}' exceeds engagement mode '{engagement_mode}'"
        )

    return {
        "engagement_id": engagement_id or "unspecified",
        "engagement_mode": engagement_mode,
        "tool_level": tool_level,
    }


def _audit_tool_call(
    tool_name: str,
    context: dict,
    target: str | None = None,
) -> None:
    global _last_audit_hash
    now = datetime.now(UTC).isoformat()
    with _audit_lock:
        payload = {
            "ts": now,
            "tool": tool_name,
            "engagement_id": context["engagement_id"],
            "engagement_mode": context["engagement_mode"],
            "tool_level": context["tool_level"],
            "target": target,
            "prev_hash": _last_audit_hash,
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        new_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        payload["event_hash"] = new_hash
        _last_audit_hash = new_hash
    logger.info("audit %s", json.dumps(payload, separators=(",", ":")))
    if AUDIT_SINK_PATH:
        try:
            with open(AUDIT_SINK_PATH, "a", encoding="utf-8") as sink:
                sink.write(json.dumps(payload, separators=(",", ":")) + "\n")
        except Exception:
            logger.exception("failed to write audit sink: %s", AUDIT_SINK_PATH)


def _enforce_url_scope(url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("URL host is required")
    try:
        # Host is an IP; scope is enforced by host-based tools.
        from ipaddress import ip_address

        ip_address(host)
        return
    except ValueError:
        policy.enforce_domain_scope(host.lower())


@mcp.tool()
@_instrument_tool("dns_lookup_tool", "passive")
def dns_lookup_tool(
    domain: str,
    record_type: Literal["A"] = "A",
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Resolve DNS records for a domain (currently supports A records only)."""
    context = _authorize(
        "dns_lookup_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    domain = policy.validate_domain(domain)
    _audit_tool_call("dns_lookup_tool", context, target=domain)
    records = dns_lookup(domain, record_type=record_type)
    logger.info("dns_lookup domain=%s count=%d", domain, len(records))
    return {"domain": domain, "record_type": record_type, "records": records}


@mcp.tool()
@_instrument_tool("reverse_dns_tool", "passive")
def reverse_dns_tool(
    ip: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Perform reverse DNS lookup for an IPv4 or IPv6 address."""
    context = _authorize(
        "reverse_dns_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    _audit_tool_call("reverse_dns_tool", context, target=ip)
    result = reverse_dns(ip)
    logger.info("reverse_dns ip=%s host=%s", ip, result)
    return {"ip": ip, "hostname": result}


@mcp.tool()
@_instrument_tool("whois_tool", "passive")
def whois_tool(
    target: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Query WHOIS information for a domain or IP."""
    context = _authorize("whois_tool", "passive", engagement_id, engagement_mode, auth_token)
    if not target.strip():
        raise ValueError("Target is required")
    if any(ch.isalpha() for ch in target):
        try:
            policy.validate_domain(target.strip())
        except ValueError:
            pass
    _audit_tool_call("whois_tool", context, target=target.strip())
    payload = whois_query(target.strip())
    logger.info("whois target=%s bytes=%d", target, len(payload))
    return {"target": target, "raw": payload}


@mcp.tool()
@_instrument_tool("http_probe_tool", "active")
def http_probe_tool(
    url: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "active",
    auth_token: str | None = None,
) -> dict:
    """Probe HTTP(S) endpoint and return status, latency, and key security headers."""
    context = _authorize(
        "http_probe_tool", "active", engagement_id, engagement_mode, auth_token
    )
    _enforce_url_scope(url)
    _audit_tool_call("http_probe_tool", context, target=url)
    result = http_probe(url=url, user_agent=cfg.user_agent)
    logger.info("http_probe url=%s status=%s", url, result.get("status"))
    return result


@mcp.tool()
@_instrument_tool("tls_certificate_tool", "active")
def tls_certificate_tool(
    host: str,
    port: int = 443,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "active",
    auth_token: str | None = None,
) -> dict:
    """Fetch and summarize the peer TLS certificate for host:port."""
    context = _authorize(
        "tls_certificate_tool", "active", engagement_id, engagement_mode, auth_token
    )
    validated = policy.validate_target(host)
    _audit_tool_call("tls_certificate_tool", context, target=f"{host}:{port}")
    result = tls_certificate(host=validated.host, port=port)
    logger.info("tls_certificate host=%s port=%d", host, port)
    return result


@mcp.tool()
@_instrument_tool("tls_certificate_expiry_tool", "active")
def tls_certificate_expiry_tool(
    host: str,
    port: int = 443,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "active",
    auth_token: str | None = None,
) -> dict:
    """Return TLS certificate expiration status and days remaining."""
    context = _authorize(
        "tls_certificate_expiry_tool",
        "active",
        engagement_id,
        engagement_mode,
        auth_token,
    )
    validated = policy.validate_target(host)
    _audit_tool_call("tls_certificate_expiry_tool", context, target=f"{host}:{port}")
    result = tls_certificate_expiry(host=validated.host, port=port)
    logger.info(
        "tls_certificate_expiry host=%s port=%d days_remaining=%d",
        host,
        port,
        result["days_remaining"],
    )
    return result


@mcp.tool()
@_instrument_tool("tcp_port_scan_tool", "intrusive")
def tcp_port_scan_tool(
    host: str,
    ports: list[int],
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Scan selected TCP ports with policy controls and connection timeouts."""
    context = _authorize(
        "tcp_port_scan_tool", "intrusive", engagement_id, engagement_mode, auth_token
    )
    validated = policy.validate_target(host)
    validated_ports = policy.parse_ports(ports)
    _audit_tool_call("tcp_port_scan_tool", context, target=f"{host}:{validated_ports}")
    result = port_scan(
        host=validated.host,
        ports=validated_ports,
        connect_timeout_ms=cfg.connect_timeout_ms,
        max_workers=cfg.max_concurrent_connects,
    )
    logger.info(
        "port_scan host=%s ports=%d open=%d",
        host,
        len(validated_ports),
        result["summary"]["open"],
    )
    return result


@mcp.tool()
@_instrument_tool("security_txt_tool", "passive")
def security_txt_tool(
    domain: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Fetch and parse /.well-known/security.txt for a domain."""
    context = _authorize(
        "security_txt_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    validated_domain = policy.validate_domain(domain)
    _audit_tool_call("security_txt_tool", context, target=validated_domain)
    result = fetch_security_txt(validated_domain, user_agent=cfg.user_agent)
    logger.info("security_txt domain=%s found=%s", validated_domain, result["found"])
    return result


@mcp.tool()
@_instrument_tool("ioc_extract_tool", "passive")
def ioc_extract_tool(
    text: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Extract URLs, domains, IPs, and common hash IOCs from free text."""
    context = _authorize(
        "ioc_extract_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    _audit_tool_call("ioc_extract_tool", context)
    result = extract_iocs(text)
    logger.info(
        "ioc_extract urls=%d domains=%d ips=%d",
        len(result["urls"]),
        len(result["domains"]),
        len(result["ips"]),
    )
    return result


@mcp.tool()
@_instrument_tool("url_risk_score_tool", "passive")
def url_risk_score_tool(
    url: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Return a heuristic risk score for a URL."""
    context = _authorize(
        "url_risk_score_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    _enforce_url_scope(url)
    _audit_tool_call("url_risk_score_tool", context, target=url)
    result = url_risk_score(url)
    logger.info("url_risk_score url=%s score=%d", url, result["score"])
    return result


@mcp.tool()
@_instrument_tool("subdomain_candidates_tool", "passive")
def subdomain_candidates_tool(
    domain: str,
    words: list[str] | None = None,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Generate likely subdomain candidates for recon planning."""
    context = _authorize(
        "subdomain_candidates_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    validated_domain = policy.validate_domain(domain)
    _audit_tool_call("subdomain_candidates_tool", context, target=validated_domain)
    candidates = generate_subdomain_candidates(validated_domain, words=words)
    return {"domain": validated_domain, "count": len(candidates), "candidates": candidates}


@mcp.tool()
@_instrument_tool("common_web_paths_tool", "passive")
def common_web_paths_tool(
    base_url: str,
    profile: Literal["light", "standard"] = "light",
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Generate common web paths/endpoints for authorized recon planning."""
    context = _authorize(
        "common_web_paths_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    _enforce_url_scope(base_url)
    _audit_tool_call("common_web_paths_tool", context, target=base_url)
    urls = generate_common_web_paths(base_url, profile=profile)
    return {"base_url": base_url, "profile": profile, "count": len(urls), "urls": urls}


@_optional_binary_tool("nmap_service_scan_tool")
@_instrument_tool("nmap_service_scan_tool", "intrusive")
def nmap_service_scan_tool(
    host: str,
    ports: list[int] | None = None,
    top_ports: int = 100,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run nmap -sV service scan using explicit ports or top ports."""
    context = _authorize(
        "nmap_service_scan_tool", "intrusive", engagement_id, engagement_mode, auth_token
    )
    validated = policy.validate_target(host)
    validated_ports = policy.parse_ports(ports) if ports else None
    _audit_tool_call("nmap_service_scan_tool", context, target=validated.host)
    return nmap_service_scan(
        host=validated.host,
        ports=validated_ports,
        top_ports=top_ports,
    )


@_optional_binary_tool("whatweb_tool")
@_instrument_tool("whatweb_tool", "active")
def whatweb_tool(
    url: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "active",
    auth_token: str | None = None,
) -> dict:
    """Run whatweb against a target URL."""
    context = _authorize("whatweb_tool", "active", engagement_id, engagement_mode, auth_token)
    _enforce_url_scope(url)
    _audit_tool_call("whatweb_tool", context, target=url)
    return whatweb_scan(url)


@_optional_binary_tool("nikto_tool")
@_instrument_tool("nikto_tool", "intrusive")
def nikto_tool(
    url: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run nikto web scan against a target URL."""
    context = _authorize("nikto_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    _enforce_url_scope(url)
    _audit_tool_call("nikto_tool", context, target=url)
    return nikto_scan(url)


@_optional_binary_tool("amass_passive_tool")
@_instrument_tool("amass_passive_tool", "passive")
def amass_passive_tool(
    domain: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Run passive subdomain enumeration with amass."""
    context = _authorize(
        "amass_passive_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    validated_domain = policy.validate_domain(domain)
    _audit_tool_call("amass_passive_tool", context, target=validated_domain)
    return amass_passive_enum(validated_domain)


@_optional_binary_tool("gobuster_dir_tool")
@_instrument_tool("gobuster_dir_tool", "intrusive")
def gobuster_dir_tool(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    threads: int = 20,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run gobuster directory enumeration for a target URL."""
    context = _authorize(
        "gobuster_dir_tool", "intrusive", engagement_id, engagement_mode, auth_token
    )
    _enforce_url_scope(url)
    _audit_tool_call("gobuster_dir_tool", context, target=url)
    return gobuster_dir_scan(url=url, wordlist=wordlist, threads=threads)


@_optional_binary_tool("sslscan_tool")
@_instrument_tool("sslscan_tool", "active")
def sslscan_tool(
    host: str,
    port: int = 443,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "active",
    auth_token: str | None = None,
) -> dict:
    """Run sslscan against host:port."""
    context = _authorize("sslscan_tool", "active", engagement_id, engagement_mode, auth_token)
    validated = policy.validate_target(host)
    _audit_tool_call("sslscan_tool", context, target=f"{validated.host}:{port}")
    return sslscan_target(validated.host, port=port)


@_optional_binary_tool("wafw00f_tool")
@_instrument_tool("wafw00f_tool", "active")
def wafw00f_tool(
    url: str,
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "active",
    auth_token: str | None = None,
) -> dict:
    """Run wafw00f to detect WAF technologies on a target URL."""
    context = _authorize("wafw00f_tool", "active", engagement_id, engagement_mode, auth_token)
    _enforce_url_scope(url)
    _audit_tool_call("wafw00f_tool", context, target=url)
    return wafw00f_scan(url)


@mcp.tool()
@_instrument_tool("toolchain_status_tool", "passive")
def toolchain_status_tool(
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Return Kali toolchain availability and enabled binary MCP tools."""
    context = _authorize(
        "toolchain_status_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    _audit_tool_call("toolchain_status_tool", context)
    installed = [
        binary
        for binary, info in KALI_TOOLCHAIN_SNAPSHOT.items()
        if info.get("installed")
    ]
    missing = [
        binary
        for binary, info in KALI_TOOLCHAIN_SNAPSHOT.items()
        if not info.get("installed")
    ]
    return {
        "installed_count": len(installed),
        "missing_count": len(missing),
        "installed": installed,
        "missing": missing,
        "binary_mcp_tools": {
            tool_name: {
                "binary": binary,
                "enabled": tool_name in ENABLED_BINARY_MCP_TOOLS,
                "path": KALI_TOOLCHAIN_SNAPSHOT.get(binary, {}).get("path"),
            }
            for tool_name, binary in BINARY_MCP_TOOL_BINARIES.items()
        },
        "enabled_binary_mcp_tools": ENABLED_BINARY_MCP_TOOLS,
    }


@mcp.tool()
@_instrument_tool("metrics_tool", "passive")
def metrics_tool(
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Return runtime metrics for tool calls."""
    context = _authorize("metrics_tool", "passive", engagement_id, engagement_mode, auth_token)
    _audit_tool_call("metrics_tool", context)
    with _metrics_lock:
        snapshot = json.loads(json.dumps(METRICS))
    calls = snapshot["calls_total"] or 1
    snapshot["failure_rate"] = snapshot["failures_total"] / calls
    snapshot["timeout_rate"] = snapshot["timeouts_total"] / calls
    snapshot["denied_rate"] = snapshot["denied_total"] / calls
    snapshot["avg_duration_ms"] = snapshot["duration_ms_total"] / calls
    return snapshot


@mcp.tool()
@_instrument_tool("runtime_probe_tool", "passive")
def runtime_probe_tool(
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Runtime health probe for orchestration and readiness checks."""
    context = _authorize(
        "runtime_probe_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    _audit_tool_call("runtime_probe_tool", context)
    return {
        "status": "ready" if not _shutdown_event.is_set() else "stopping",
        "started_at": STARTED_AT.isoformat(),
        "uptime_seconds": int((datetime.now(UTC) - STARTED_AT).total_seconds()),
        "transport_mode": TRANSPORT_MODE,
        "auth_mode": AUTH_MODE,
        "tool_count_enabled": len(ENABLED_BINARY_MCP_TOOLS) + 16,
    }


@mcp.tool()
@_instrument_tool("server_health_tool", "passive")
def server_health_tool(
    engagement_id: str | None = None,
    engagement_mode: Literal["passive", "active", "intrusive"] = "passive",
    auth_token: str | None = None,
) -> dict:
    """Return server health and policy configuration snapshot."""
    context = _authorize("server_health_tool", "passive", engagement_id, engagement_mode, auth_token)
    _audit_tool_call("server_health_tool", context)
    return {
        "status": "ok",
        "config": {
            "max_ports_per_scan": cfg.max_ports_per_scan,
            "connect_timeout_ms": cfg.connect_timeout_ms,
            "max_concurrent_connects": cfg.max_concurrent_connects,
            "allow_private_only": cfg.allow_private_only,
            "allowed_cidrs": [str(cidr) for cidr in cfg.allowed_cidrs],
            "allowed_domains": list(cfg.allowed_domains),
            "blocked_ports": list(cfg.blocked_ports),
            "require_engagement_context": cfg.require_engagement_context,
            "max_tool_level": cfg.max_tool_level,
            "transport_mode": TRANSPORT_MODE,
            "auth_mode": AUTH_MODE,
            "audit_sink_path": AUDIT_SINK_PATH or None,
        },
        "toolchain": {
            "enabled_binary_mcp_tools": ENABLED_BINARY_MCP_TOOLS,
            "binary_mcp_tool_count": len(BINARY_MCP_TOOL_BINARIES),
            "installed_common_kali_tool_count": sum(
                1
                for info in KALI_TOOLCHAIN_SNAPSHOT.values()
                if info.get("installed")
            ),
            "common_kali_tool_count": len(KALI_TOOLCHAIN_SNAPSHOT),
        },
        "runtime": {
            "started_at": STARTED_AT.isoformat(),
            "uptime_seconds": int((datetime.now(UTC) - STARTED_AT).total_seconds()),
            "shutting_down": _shutdown_event.is_set(),
        },
    }


_register_dynamic_kali_raw_tools()


def main() -> None:
    _validate_runtime_security()
    _validate_transport_auth_configuration()
    _install_signal_handlers()
    enabled_bins = sorted(
        {
            BINARY_MCP_TOOL_BINARIES[name]
            for name in ENABLED_BINARY_MCP_TOOLS
        }
    )
    enabled_display = ", ".join(enabled_bins) if enabled_bins else "none"
    core_tool_count = 16
    total_enabled_tools = (
        core_tool_count
        + len(ENABLED_BINARY_MCP_TOOLS)
    )
    total_tool_count = (
        core_tool_count
        + len(BINARY_MCP_TOOL_BINARIES)
    )
    banner = [
        " ▗▄▄▖▐▌    ▄▄▄   ▄▄▄  ■  ▗▖  ▗▖ ▗▄▄▖▗▄▄▖ ",
        "▐▌   ▐▌   █   █ ▀▄▄▗▄▟▙▄▖▐▛▚▞▜▌▐▌   ▐▌ ▐▌",
        "▐▌▝▜▌▐▛▀▚▖▀▄▄▄▀ ▄▄▄▀ ▐▌  ▐▌  ▐▌▐▌   ▐▛▀▘ ",
        "▝▚▄▞▘▐▌ ▐▌           ▐▌  ▐▌  ▐▌▝▚▄▄▖▐▌   ",
        "                     ▐▌                  ",
        "=========================================",
        " Server Started",
        " Server ID: ghostmcp-tooling",
        f" Transport: {'stdio' if TRANSPORT_MODE == 'stdio' else 'streamable-http'}",
        f" PID: {os.getpid()}",
        f" Tools enabled: {total_enabled_tools}/{total_tool_count}",
        (
            " Binary tools enabled: "
            f"{len(ENABLED_BINARY_MCP_TOOLS)}/{len(BINARY_MCP_TOOL_BINARIES)}"
        ),
        f" Enabled binaries: {enabled_display}",
        " Status: ready",
        "=========================================",
    ]
    print("\n".join(banner), file=sys.stderr, flush=True)
    try:
        if TRANSPORT_MODE == "stdio":
            mcp.run(transport="stdio")
        else:
            import uvicorn

            app = mcp.streamable_http_app()
            uvicorn_kwargs = {
                "host": HTTP_HOST,
                "port": HTTP_PORT,
                "log_level": _env("UVICORN_LOG_LEVEL", "info"),
            }
            if AUTH_MODE == "mtls":
                uvicorn_kwargs.update(
                    {
                        "ssl_keyfile": MTLS_KEY,
                        "ssl_certfile": MTLS_CERT,
                        "ssl_ca_certs": MTLS_CA_CERT,
                        "ssl_cert_reqs": ssl.CERT_REQUIRED,
                    }
                )
            config = uvicorn.Config(app, **uvicorn_kwargs)
            uvicorn.Server(config).run()
    except ScannerError as exc:
        logger.exception("scanner_error: %s", exc)
        raise
    finally:
        _shutdown_event.set()
        terminate_active_processes()


if __name__ == "__main__":
    main()
