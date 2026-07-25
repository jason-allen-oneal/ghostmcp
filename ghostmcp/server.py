from __future__ import annotations

import inspect
import ipaddress
import json
import logging
import os
import shutil
import signal
import ssl
import sys
import threading
import time
from contextvars import ContextVar
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, Literal, cast, get_type_hints

from mcp.server.fastmcp import FastMCP

from . import __version__
from .audit import AuditChain, load_hmac_key, verify_audit_log
from .config import load_config
from .logging_utils import configure_logging
from .plugins import get_plugin_manager, load_all_plugins, register_plugin_tools
from .rate_limit import SlidingWindowRateLimiter
from .scanners import (
    ScannerError,
    ScannerTimeoutError,
    amass_passive_enum,
    assetfinder_scan,
    binwalk_scan,
    cloudflair_scan,
    crackmapexec_scan,
    dirsearch_scan,
    dns_lookup,
    dnsrecon_scan,
    dnsx_scan,
    enum4linux_ng_scan,
    exiftool_scan,
    extract_iocs,
    feroxbuster_scan,
    fetch_security_txt,
    ffuf_scan,
    generate_common_web_paths,
    generate_subdomain_candidates,
    gitleaks_scan,
    gobuster_dir_scan,
    gowitness_scan,
    http_probe,
    hydra_scan,
    jaeles_scan,
    masscan_scan,
    nikto_scan,
    nmap_service_scan,
    nuclei_scan,
    port_scan,
    reverse_dns,
    rpcclient_query,
    run_external_binary,
    s3scanner_scan,
    searchsploit_query,
    smbclient_list,
    smbmap_scan,
    sqlmap_scan,
    sslscan_target,
    sslyze_scan,
    subfinder_scan,
    terminate_active_processes,
    theharvester_scan,
    tls_certificate,
    tls_certificate_expiry,
    trufflehog_scan,
    url_risk_score,
    wafw00f_scan,
    wfuzz_scan,
    whatweb_scan,
    whois_query,
    wpscan_scan,
)
from .security import SecurityPolicy
from .tool_policy import (
    TOOL_MANIFEST,
    descriptor_for_curated,
    descriptor_for_raw,
    enforce_capabilities,
    validate_effective_arguments,
)
from .transport_security import TransportAuthMiddleware, get_transport_principal
from .workflows import (
    host_exposure_assessment,
    tls_posture_assessment,
    web_surface_assessment,
)

configure_logging()
logger = logging.getLogger(__name__)


def _env(name: str, default: str) -> str:
    return os.getenv(f"GHOSTMCP_{name}", default)


def _env_bool(name: str, default: bool = False) -> bool:
    value = _env(name, "true" if default else "false").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"Invalid boolean value for GHOSTMCP_{name}: {value}")


def _env_csv(name: str) -> set[str]:
    return {
        value.strip()
        for value in _env(name, "").split(",")
        if value.strip()
    }


cfg = load_config()
_base_policy = SecurityPolicy(cfg)
_current_policy: ContextVar[SecurityPolicy] = ContextVar(
    "ghostmcp_current_policy",
    default=_base_policy,
)


class _PolicyProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(_current_policy.get(), name)


policy = _PolicyProxy()
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

ToolLevel = Literal["passive", "active", "intrusive"]
EngagementMode = Literal["default", "passive", "active", "intrusive"]
TOOL_LEVELS = {"passive": 1, "active": 2, "intrusive": 3}
CORE_TOOL_COUNT = 21
_metrics_lock = threading.Lock()
_shutdown_event = threading.Event()
AUDIT_SINK_PATH = _env("AUDIT_SINK_PATH", "").strip()
AUDIT_HMAC_KEY = load_hmac_key(
    key_value=_env("AUDIT_HMAC_KEY", "").strip(),
    key_file=_env("AUDIT_HMAC_KEY_FILE", "").strip(),
)
AUDIT_CHAIN = AuditChain(
    AUDIT_SINK_PATH,
    hmac_key=AUDIT_HMAC_KEY,
    fsync=_env_bool("AUDIT_FSYNC", False),
)

TRANSPORT_MODE = _env("TRANSPORT_MODE", "stdio").strip().lower()
AUTH_MODE = _env("AUTH_MODE", "none").strip().lower()
AUTH_TOKEN = _env("AUTH_TOKEN", "").strip()
MTLS_CA_CERT = _env("MTLS_CA_CERT_PATH", "").strip()
MTLS_CERT = _env("MTLS_CERT_PATH", "").strip()
MTLS_KEY = _env("MTLS_KEY_PATH", "").strip()
TLS_CERT = _env("TLS_CERT_PATH", "").strip()
TLS_KEY = _env("TLS_KEY_PATH", "").strip()
HTTP_HOST = _env("HTTP_HOST", "127.0.0.1").strip()
HTTP_PORT = int(_env("HTTP_PORT", "8000"))
if HTTP_PORT < 1 or HTTP_PORT > 65535:
    raise RuntimeError("GHOSTMCP_HTTP_PORT must be between 1 and 65535")
ALLOW_INSECURE_REMOTE_NO_AUTH = _env("ALLOW_INSECURE_REMOTE_NO_AUTH", "false").strip().lower() in {
    "1",
    "true",
    "yes",
}
ALLOW_RUN_AS_ROOT = _env_bool("ALLOW_RUN_AS_ROOT", False)
ENABLE_RAW_TOOLS = _env_bool("ENABLE_RAW_TOOLS", False)
RAW_TOOL_ALLOWLIST = _env_csv("RAW_TOOL_ALLOWLIST")
ENABLE_PLUGINS = _env_bool("ENABLE_PLUGINS", False)
PLUGIN_ALLOWLIST = _env_csv("PLUGIN_ALLOWLIST")
PLUGIN_GROUP = _env("PLUGIN_GROUP", "ghostmcp.plugins").strip()
PLUGIN_REGISTRATION: dict[str, list[str]] = {}

TOOL_CLASS_LIMITS = {
    "passive": threading.Semaphore(int(_env("MAX_PASSIVE_PARALLEL", "64"))),
    "active": threading.Semaphore(int(_env("MAX_ACTIVE_PARALLEL", "16"))),
    "intrusive": threading.Semaphore(int(_env("MAX_INTRUSIVE_PARALLEL", "4"))),
}

METRICS: dict[str, Any] = {
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
    "gowitness",
    "jaeles",
    "cloudflair",
    "s3scanner",
    "trufflehog",
    "gitleaks",
]

SUPPORTED_EXTERNAL_TOOL_BINARIES = {
    "nmap_service_scan_tool": "nmap",
    "whatweb_tool": "whatweb",
    "nikto_tool": "nikto",
    "amass_passive_tool": "amass",
    "gobuster_dir_tool": "gobuster",
    "sslscan_tool": "sslscan",
    "wafw00f_tool": "wafw00f",
    "sqlmap_tool": "sqlmap",
    "hydra_tool": "hydra",
    "enum4linux_ng_tool": "enum4linux-ng",
    "crackmapexec_tool": "crackmapexec",
    "theharvester_tool": "theHarvester",
    "masscan_tool": "masscan",
    "dnsrecon_tool": "dnsrecon",
    "wpscan_tool": "wpscan",
    "dirsearch_tool": "dirsearch",
    "sslyze_tool": "sslyze",
    "smbmap_tool": "smbmap",
    "smbclient_tool": "smbclient",
    "rpcclient_tool": "rpcclient",
    "searchsploit_tool": "searchsploit",
    "nuclei_tool": "nuclei",
    "exiftool_tool": "exiftool",
    "binwalk_tool": "binwalk",
    "ffuf_tool": "ffuf",
    "feroxbuster_tool": "feroxbuster",
    "wfuzz_tool": "wfuzz",
    "subfinder_tool": "subfinder",
    "assetfinder_tool": "assetfinder",
    "dnsx_tool": "dnsx",
    "gowitness_tool": "gowitness",
    "jaeles_tool": "jaeles",
    "cloudflair_tool": "cloudflair",
    "s3scanner_tool": "s3scanner",
    "trufflehog_tool": "trufflehog",
    "gitleaks_tool": "gitleaks",
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
ENABLED_CURATED_MCP_TOOLS = sorted(
    tool_name
    for tool_name, binary in SUPPORTED_EXTERNAL_TOOL_BINARIES.items()
    if KALI_TOOLCHAIN_SNAPSHOT.get(binary, {}).get("installed")
)
ENABLED_RAW_MCP_TOOLS = sorted(
    tool_name
    for tool_name, binary in DYNAMIC_KALI_RAW_TOOL_BINARIES.items()
    if ENABLE_RAW_TOOLS
    and binary in RAW_TOOL_ALLOWLIST
    and KALI_TOOLCHAIN_SNAPSHOT.get(binary, {}).get("installed")
)
ENABLED_BINARY_MCP_TOOLS = sorted(
    {*ENABLED_CURATED_MCP_TOOLS, *ENABLED_RAW_MCP_TOOLS}
)
for _raw_tool_name, _raw_binary in DYNAMIC_KALI_RAW_TOOL_BINARIES.items():
    TOOL_MANIFEST.register(
        descriptor_for_raw(
            _raw_tool_name,
            _raw_binary,
            available=_raw_tool_name in ENABLED_RAW_MCP_TOOLS,
        )
    )


def _validate_runtime_security() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not ALLOW_RUN_AS_ROOT:
        raise RuntimeError(
            "Refusing to run as root. Set GHOSTMCP_ALLOW_RUN_AS_ROOT=true to override."
        )
    unknown_raw_tools = RAW_TOOL_ALLOWLIST - set(KALI_COMMON_TOOL_BINARIES)
    if unknown_raw_tools:
        raise RuntimeError(
            f"Unknown raw-tool allowlist entries: {sorted(unknown_raw_tools)}"
        )
    if ENABLE_RAW_TOOLS and not RAW_TOOL_ALLOWLIST:
        raise RuntimeError(
            "Raw tools were enabled without GHOSTMCP_RAW_TOOL_ALLOWLIST"
        )
    if ENABLE_PLUGINS and not PLUGIN_ALLOWLIST:
        raise RuntimeError(
            "Plugins were enabled without GHOSTMCP_PLUGIN_ALLOWLIST"
        )
    from .proxy import validate_proxy_configuration

    validate_proxy_configuration(required=cfg.require_routed_execution)


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
    try:
        http_is_loopback = ipaddress.ip_address(HTTP_HOST).is_loopback
    except ValueError:
        http_is_loopback = HTTP_HOST.lower() == "localhost"
    if (
        TRANSPORT_MODE == "remote_gateway"
        and AUTH_MODE == "token"
        and not http_is_loopback
    ):
        if not TLS_CERT or not TLS_KEY:
            raise RuntimeError(
                "Non-loopback token transport requires "
                "GHOSTMCP_TLS_CERT_PATH and GHOSTMCP_TLS_KEY_PATH"
            )
        for required in (TLS_CERT, TLS_KEY):
            if not Path(required).exists():
                raise RuntimeError(f"TLS file not found: {required}")
    if AUTH_MODE == "mtls":
        for required in (MTLS_CA_CERT, MTLS_CERT, MTLS_KEY):
            if not required:
                raise RuntimeError(
                    "mtls auth mode requires GHOSTMCP_MTLS_CA_CERT_PATH, "
                    "GHOSTMCP_MTLS_CERT_PATH, and GHOSTMCP_MTLS_KEY_PATH"
                )
            if not Path(required).exists():
                raise RuntimeError(f"mTLS file not found: {required}")


def _setdefault_tool_metrics(tool_name: str) -> dict[str, int]:
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


def _instrument_tool(tool_name: str, tool_level: ToolLevel):
    def decorator(fn):
        fn_signature = inspect.signature(fn)
        resolved_hints = get_type_hints(fn, globalns=fn.__globals__, include_extras=True)
        try:
            descriptor = TOOL_MANIFEST.get(tool_name)
        except ValueError:
            descriptor = TOOL_MANIFEST.register(
                descriptor_for_curated(
                    tool_name,
                    tool_level,
                    available=(
                        tool_name not in SUPPORTED_EXTERNAL_TOOL_BINARIES
                        or tool_name in ENABLED_CURATED_MCP_TOOLS
                    ),
                )
            )

        @wraps(fn)
        def wrapped(*args, **kwargs):
            _record_call_start(tool_name)
            started = time.monotonic()
            policy_token = None
            try:
                bound = fn_signature.bind(*args, **kwargs)
                bound.apply_defaults()
                engagement_id = bound.arguments.get("engagement_id")
                base_policy = (
                    _base_policy
                    if _base_policy.config is cfg
                    else SecurityPolicy(cfg, credentials=_base_policy.credentials)
                )
                scoped_policy = base_policy.for_engagement(
                    str(engagement_id) if engagement_id else None
                )
                policy_token = _current_policy.set(scoped_policy)
                enforce_capabilities(
                    descriptor,
                    scoped_policy.config.allowed_capabilities,
                )
                if (
                    descriptor.raw
                    and "raw_execution"
                    not in scoped_policy.config.allowed_capabilities
                ):
                    raise PermissionError(
                        "Raw tools require the raw_execution capability"
                    )
                if (
                    scoped_policy.config.require_routed_execution
                    and descriptor.route_support == "direct_only"
                ):
                    raise PermissionError(
                        f"Tool cannot satisfy routed-execution policy: {tool_name}"
                    )
                validate_effective_arguments(
                    descriptor,
                    dict(bound.arguments),
                    policy,
                )
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
            finally:
                if policy_token is not None:
                    _current_policy.reset(policy_token)
            duration_ms = int((time.monotonic() - started) * 1000)
            _record_call_result(tool_name, success=True, duration_ms=duration_ms)
            return result

        # FastMCP inspects function signatures for tool schemas; preserve original params.
        resolved_params = []
        for name, param in fn_signature.parameters.items():
            if name == "auth_token":
                continue
            annotation = resolved_hints.get(name, param.annotation)
            resolved_params.append(param.replace(annotation=annotation))
        resolved_return = resolved_hints.get("return", fn_signature.return_annotation)
        wrapped.__signature__ = fn_signature.replace(  # type: ignore[attr-defined]
            parameters=resolved_params,
            return_annotation=resolved_return,
        )
        wrapped.__annotations__ = {
            **{
                k: v
                for k, v in resolved_hints.items()
                if k not in {"auth_token", "return"}
            },
            "return": resolved_return,
        }
        return wrapped

    return decorator


ARG_TOKEN_RE = r"^[A-Za-z0-9._:/=,+-]+$"  # nosec B105
RAW_TOOL_ARG_ALLOW_PREFIX = {
    "nmap": ["-s", "-p", "-Pn", "-T", "--top-ports", "--script"],
    "gobuster": ["dir", "-u", "-w", "-t", "--no-error", "-x", "-k"],
    "nikto": ["-host", "-Format", "-ssl", "-port"],
    "ffuf": ["-u", "-w", "-json", "-t", "-rate", "-H", "-mc", "-fc", "-fs", "-fl", "-fw"],
    "feroxbuster": ["-u", "-w", "--json", "-t", "--rate-limit", "-x", "-k", "-H"],
    "wfuzz": ["-w", "-u", "--json", "-t", "--rate", "-H", "-c", "-f"],
    "subfinder": ["-d", "-json", "-o", "-t"],
    "assetfinder": ["-subs-only"],
    "dnsx": ["-d", "-json", "-t", "-retry"],
    "gowitness": ["scan", "single", "--json", "--udp", "--screenshot-path"],
    "jaeles": ["scan", "-u", "-o", "-c", "-t"],
    "cloudflair": ["--target", "--json", "--output"],
    "s3scanner": ["--bucket", "--json", "--threads"],
    "trufflehog": ["filesystem", "--json", "--include-paths", "--exclude-paths"],
    "gitleaks": ["detect", "--source", "--report-format", "--config", "--verbose"],
    "sqlmap": [
        "--level",
        "--risk",
        "--technique",
        "--threads",
        "--timeout",
        "--retries",
        "--batch",
        "--random-agent",
    ],
    "wpscan": [
        "--enumerate",
        "--plugins-detection",
        "--themes-detection",
        "--random-user-agent",
        "--request-timeout",
        "--connect-timeout",
    ],
    "dirsearch": [
        "--threads",
        "--timeout",
        "--retries",
        "--exclude-status",
        "--include-status",
        "--random-agent",
        "--recursive",
    ],
    "crackmapexec": [
        "--shares",
        "--sessions",
        "--users",
        "--groups",
        "--pass-pol",
        "--loggedon-users",
    ],
    "smbmap": ["-u", "-p", "-d", "--no-banner"],
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
    if not ENABLE_RAW_TOOLS:
        logger.info("Raw Kali tool registration is disabled")
        return
    for tool_name, binary in DYNAMIC_KALI_RAW_TOOL_BINARIES.items():
        if binary not in RAW_TOOL_ALLOWLIST:
            continue
        if not KALI_TOOLCHAIN_SNAPSHOT.get(binary, {}).get("installed"):
            continue

        def _factory(name: str, bin_name: str):
            def _tool(
                args: list[str] | None = None,
                timeout_s: float = 120.0,
                engagement_id: str | None = None,
                engagement_mode: EngagementMode = "intrusive",
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


def _normalize_tool_level(level: str) -> ToolLevel:
    normalized = level.strip().lower()
    if not normalized or normalized == "default":
        return "passive"
    if normalized not in TOOL_LEVELS:
        raise ValueError(f"Unsupported engagement mode/tool level: {level}")
    return cast(ToolLevel, normalized)


def _authorize(
    tool_name: str,
    tool_level: ToolLevel,
    engagement_id: str | None,
    engagement_mode: EngagementMode,
    auth_token: str | None = None,
) -> dict:
    _enforce_budget()

    normalized_tool_level = _normalize_tool_level(tool_level)
    normalized_engagement_mode = _normalize_tool_level(engagement_mode)

    active_policy = _current_policy.get()
    if active_policy.config.require_engagement_context and not engagement_id:
        _record_call_denied(tool_name)
        raise ValueError("engagement_id is required by policy")

    principal = get_transport_principal()
    if TRANSPORT_MODE == "remote_gateway" and principal is None:
        _record_call_denied(tool_name)
        raise PermissionError("Remote transport authentication is required")
    if auth_token is not None:
        logger.warning(
            "Ignoring deprecated tool-level auth_token for %s; use HTTP Authorization",
            tool_name,
        )

    configured_max = active_policy.config.max_tool_level
    if configured_max not in TOOL_LEVELS:
        configured_max = "intrusive"
    if TOOL_LEVELS[normalized_tool_level] > TOOL_LEVELS[configured_max]:
        _record_call_denied(tool_name)
        raise ValueError(
            f"Tool level '{normalized_tool_level}' exceeds configured max '{configured_max}'"
        )
    if TOOL_LEVELS[normalized_tool_level] > TOOL_LEVELS[normalized_engagement_mode]:
        _record_call_denied(tool_name)
        raise ValueError(
            f"Tool level '{normalized_tool_level}' exceeds engagement mode '{normalized_engagement_mode}'"
        )
    if (
        normalized_tool_level == "intrusive"
        and active_policy.scope_digest is None
        and not active_policy.config.allow_unscoped_intrusive
    ):
        _record_call_denied(tool_name)
        raise PermissionError(
            "Intrusive tools require a policy-backed engagement scope"
        )

    return {
        "engagement_id": engagement_id or "unspecified",
        "engagement_mode": normalized_engagement_mode,
        "tool_level": normalized_tool_level,
        "principal_id": principal.principal_id if principal else "stdio:local",
        "scope_digest": active_policy.scope_digest,
        "approval_id": active_policy.approval_id,
        "approved_by": active_policy.approved_by,
    }


def _audit_tool_call(
    tool_name: str,
    context: dict,
    target: str | None = None,
) -> None:
    event = AUDIT_CHAIN.append(
        {
            "ts": datetime.now(UTC).isoformat(),
            "tool": tool_name,
            "engagement_id": context["engagement_id"],
            "engagement_mode": context["engagement_mode"],
            "tool_level": context["tool_level"],
            "principal_id": context["principal_id"],
            "scope_digest": context["scope_digest"],
            "approval_id": context["approval_id"],
            "approved_by": context["approved_by"],
            "target": target,
        }
    )
    logger.info("audit %s", json.dumps(event, separators=(",", ":")))


def _enforce_url_scope(url: str) -> None:
    policy.validate_url(url)


@mcp.tool()
@_instrument_tool("dns_lookup_tool", "passive")
def dns_lookup_tool(
    domain: str,
    record_type: Literal["A"] = "A",
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
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
    engagement_mode: EngagementMode = "passive",
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
    engagement_mode: EngagementMode = "passive",
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
    engagement_mode: EngagementMode = "active",
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
    engagement_mode: EngagementMode = "active",
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
    engagement_mode: EngagementMode = "active",
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
    engagement_mode: EngagementMode = "intrusive",
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
    engagement_mode: EngagementMode = "passive",
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
    engagement_mode: EngagementMode = "passive",
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
    engagement_mode: EngagementMode = "passive",
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
    engagement_mode: EngagementMode = "passive",
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
    engagement_mode: EngagementMode = "passive",
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
    engagement_mode: EngagementMode = "intrusive",
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
    engagement_mode: EngagementMode = "active",
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
    engagement_mode: EngagementMode = "intrusive",
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
    engagement_mode: EngagementMode = "passive",
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
    engagement_mode: EngagementMode = "intrusive",
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
    engagement_mode: EngagementMode = "active",
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
    engagement_mode: EngagementMode = "active",
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
    engagement_mode: EngagementMode = "passive",
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
@_instrument_tool("tool_manifest_tool", "passive")
def tool_manifest_tool(
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Return versioned security metadata for every GhostMCP tool."""
    context = _authorize(
        "tool_manifest_tool",
        "passive",
        engagement_id,
        engagement_mode,
        auth_token,
    )
    _audit_tool_call("tool_manifest_tool", context)
    return TOOL_MANIFEST.export(__version__)


@mcp.tool()
@_instrument_tool("metrics_tool", "passive")
def metrics_tool(
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
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
@_instrument_tool("verify_audit_log_integrity_tool", "passive")
def verify_audit_log_integrity_tool(
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Validate the integrity of the audit log hash chain."""
    context = _authorize(
        "verify_audit_log_integrity_tool", "passive", engagement_id, engagement_mode, auth_token
    )
    if not AUDIT_SINK_PATH:
        return {"status": "error", "message": "Audit sink is not enabled"}
    _audit_tool_call("verify_audit_log_integrity_tool", context)
    return verify_audit_log(AUDIT_SINK_PATH, AUDIT_HMAC_KEY)


@_optional_binary_tool("sqlmap_tool")
@_instrument_tool("sqlmap_tool", "intrusive")
def sqlmap_tool(
    url: str,
    args: list[str] | None = None,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run automated SQL injection tests using sqlmap."""
    context = _authorize("sqlmap_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    _enforce_url_scope(url)
    safe_args = _validate_raw_tool_args("sqlmap", args)
    injected_args = policy.inject_credentials("sqlmap", url, safe_args)
    _audit_tool_call("sqlmap_tool", context, target=url)
    return sqlmap_scan(url, args=injected_args)


@_optional_binary_tool("hydra_tool")
@_instrument_tool("hydra_tool", "intrusive")
def hydra_tool(
    target: str,
    service: str,
    user: str,
    wordlist: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run password brute-force tests using hydra."""
    context = _authorize("hydra_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    policy.validate_target(target)
    _audit_tool_call("hydra_tool", context, target=target)
    return hydra_scan(target, service, user, wordlist)


@_optional_binary_tool("enum4linux_ng_tool")
@_instrument_tool("enum4linux_ng_tool", "active")
def enum4linux_ng_tool(
    host: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "active",
    auth_token: str | None = None,
) -> dict:
    """Run SMB/Windows enumeration using enum4linux-ng."""
    context = _authorize("enum4linux_ng_tool", "active", engagement_id, engagement_mode, auth_token)
    policy.validate_target(host)
    _audit_tool_call("enum4linux_ng_tool", context, target=host)
    return enum4linux_ng_scan(host)


@_optional_binary_tool("crackmapexec_tool")
@_instrument_tool("crackmapexec_tool", "intrusive")
def crackmapexec_tool(
    service: str,
    target: str,
    args: list[str] | None = None,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run network service assessment using crackmapexec."""
    context = _authorize("crackmapexec_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    policy.validate_target(target)
    safe_args = _validate_raw_tool_args("crackmapexec", args)
    injected_args = policy.inject_credentials("crackmapexec", target, safe_args)
    _audit_tool_call("crackmapexec_tool", context, target=target)
    return crackmapexec_scan(service, target, args=injected_args)


@_optional_binary_tool("theharvester_tool")
@_instrument_tool("theharvester_tool", "passive")
def theharvester_tool(
    domain: str,
    source: str = "google",
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Run OSINT gathering with theHarvester."""
    context = _authorize("theharvester_tool", "passive", engagement_id, engagement_mode, auth_token)
    validated_domain = policy.validate_domain(domain)
    _audit_tool_call("theharvester_tool", context, target=validated_domain)
    return theharvester_scan(validated_domain, source=source)


@_optional_binary_tool("masscan_tool")
@_instrument_tool("masscan_tool", "intrusive")
def masscan_tool(
    targets: str,
    ports: str,
    rate: int = 1000,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run high-speed port scanning with masscan."""
    context = _authorize("masscan_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    validated_targets = policy.validate_masscan_targets(targets)
    _audit_tool_call("masscan_tool", context, target=validated_targets)
    return masscan_scan(validated_targets, ports, rate=rate)


@_optional_binary_tool("dnsrecon_tool")
@_instrument_tool("dnsrecon_tool", "active")
def dnsrecon_tool(
    domain: str,
    scan_type: str = "std",
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "active",
    auth_token: str | None = None,
) -> dict:
    """Run DNS enumeration with dnsrecon."""
    context = _authorize("dnsrecon_tool", "active", engagement_id, engagement_mode, auth_token)
    validated_domain = policy.validate_domain(domain)
    _audit_tool_call("dnsrecon_tool", context, target=validated_domain)
    return dnsrecon_scan(validated_domain, scan_type=scan_type)


@_optional_binary_tool("wpscan_tool")
@_instrument_tool("wpscan_tool", "intrusive")
def wpscan_tool(
    url: str,
    args: list[str] | None = None,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run WordPress vulnerability scanning with wpscan."""
    context = _authorize("wpscan_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    _enforce_url_scope(url)
    _audit_tool_call("wpscan_tool", context, target=url)
    return wpscan_scan(url, args=_validate_raw_tool_args("wpscan", args))


@_optional_binary_tool("dirsearch_tool")
@_instrument_tool("dirsearch_tool", "intrusive")
def dirsearch_tool(
    url: str,
    args: list[str] | None = None,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run directory brute-forcing with dirsearch."""
    context = _authorize("dirsearch_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    _enforce_url_scope(url)
    _audit_tool_call("dirsearch_tool", context, target=url)
    return dirsearch_scan(url, args=_validate_raw_tool_args("dirsearch", args))


@_optional_binary_tool("sslyze_tool")
@_instrument_tool("sslyze_tool", "active")
def sslyze_tool(
    target: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "active",
    auth_token: str | None = None,
) -> dict:
    """Run advanced SSL/TLS analysis with sslyze."""
    context = _authorize("sslyze_tool", "active", engagement_id, engagement_mode, auth_token)
    policy.validate_target(target)
    _audit_tool_call("sslyze_tool", context, target=target)
    return sslyze_scan(target)


@_optional_binary_tool("smbmap_tool")
@_instrument_tool("smbmap_tool", "intrusive")
def smbmap_tool(
    host: str,
    args: list[str] | None = None,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run SMB share enumeration with smbmap."""
    context = _authorize("smbmap_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    policy.validate_target(host)
    _audit_tool_call("smbmap_tool", context, target=host)
    return smbmap_scan(host, args=_validate_raw_tool_args("smbmap", args))


@_optional_binary_tool("smbclient_tool")
@_instrument_tool("smbclient_tool", "intrusive")
def smbclient_tool(
    host: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """List SMB shares with smbclient."""
    context = _authorize("smbclient_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    policy.validate_target(host)
    _audit_tool_call("smbclient_tool", context, target=host)
    return smbclient_list(host)


@_optional_binary_tool("rpcclient_tool")
@_instrument_tool("rpcclient_tool", "intrusive")
def rpcclient_tool(
    host: str,
    command: str = "enumdomusers",
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Query MSRPC endpoints with rpcclient."""
    context = _authorize("rpcclient_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    policy.validate_target(host)
    _audit_tool_call("rpcclient_tool", context, target=host)
    return rpcclient_query(host, command=command)


@_optional_binary_tool("searchsploit_tool")
@_instrument_tool("searchsploit_tool", "passive")
def searchsploit_tool(
    query: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Search for exploits in the local Exploit Database mirror."""
    context = _authorize("searchsploit_tool", "passive", engagement_id, engagement_mode, auth_token)
    _audit_tool_call("searchsploit_tool", context, target=query)
    return searchsploit_query(query)


@_optional_binary_tool("nuclei_tool")
@_instrument_tool("nuclei_tool", "intrusive")
def nuclei_tool(
    target: str,
    templates: str | None = None,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run vulnerability scanning with nuclei templates."""
    context = _authorize("nuclei_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    # target can be URL or IP
    _audit_tool_call("nuclei_tool", context, target=target)
    return nuclei_scan(target, templates=templates)


@_optional_binary_tool("exiftool_tool")
@_instrument_tool("exiftool_tool", "passive")
def exiftool_tool(
    file_path: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Extract metadata from files with exiftool."""
    context = _authorize("exiftool_tool", "passive", engagement_id, engagement_mode, auth_token)
    # file_path should be local or in /tmp
    _audit_tool_call("exiftool_tool", context, target=file_path)
    return exiftool_scan(file_path)


@_optional_binary_tool("binwalk_tool")
@_instrument_tool("binwalk_tool", "passive")
def binwalk_tool(
    file_path: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Analyze files for embedded data with binwalk."""
    context = _authorize("binwalk_tool", "passive", engagement_id, engagement_mode, auth_token)
    _audit_tool_call("binwalk_tool", context, target=file_path)
    return binwalk_scan(file_path)


@_optional_binary_tool("ffuf_tool")
@_instrument_tool("ffuf_tool", "intrusive")
def ffuf_tool(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run ffuf directory fuzzing against a target URL."""
    context = _authorize("ffuf_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    _enforce_url_scope(url)
    _audit_tool_call("ffuf_tool", context, target=url)
    return ffuf_scan(url=url, wordlist=wordlist)


@_optional_binary_tool("feroxbuster_tool")
@_instrument_tool("feroxbuster_tool", "intrusive")
def feroxbuster_tool(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run feroxbuster directory enumeration against a target URL."""
    context = _authorize("feroxbuster_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    _enforce_url_scope(url)
    _audit_tool_call("feroxbuster_tool", context, target=url)
    return feroxbuster_scan(url=url, wordlist=wordlist)


@_optional_binary_tool("wfuzz_tool")
@_instrument_tool("wfuzz_tool", "intrusive")
def wfuzz_tool(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run wfuzz web application fuzzing against a target URL."""
    context = _authorize("wfuzz_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    _enforce_url_scope(url)
    _audit_tool_call("wfuzz_tool", context, target=url)
    return wfuzz_scan(url=url, wordlist=wordlist)


@_optional_binary_tool("subfinder_tool")
@_instrument_tool("subfinder_tool", "passive")
def subfinder_tool(
    domain: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Run passive subdomain enumeration with subfinder."""
    context = _authorize("subfinder_tool", "passive", engagement_id, engagement_mode, auth_token)
    validated_domain = policy.validate_domain(domain)
    _audit_tool_call("subfinder_tool", context, target=validated_domain)
    return subfinder_scan(validated_domain)


@_optional_binary_tool("assetfinder_tool")
@_instrument_tool("assetfinder_tool", "passive")
def assetfinder_tool(
    domain: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Run subdomain enumeration with assetfinder."""
    context = _authorize("assetfinder_tool", "passive", engagement_id, engagement_mode, auth_token)
    validated_domain = policy.validate_domain(domain)
    _audit_tool_call("assetfinder_tool", context, target=validated_domain)
    return assetfinder_scan(validated_domain)


@_optional_binary_tool("dnsx_tool")
@_instrument_tool("dnsx_tool", "passive")
def dnsx_tool(
    domain: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Run DNS probing with dnsx."""
    context = _authorize("dnsx_tool", "passive", engagement_id, engagement_mode, auth_token)
    validated_domain = policy.validate_domain(domain)
    _audit_tool_call("dnsx_tool", context, target=validated_domain)
    return dnsx_scan(validated_domain)


@_optional_binary_tool("gowitness_tool")
@_instrument_tool("gowitness_tool", "active")
def gowitness_tool(
    target: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "active",
    auth_token: str | None = None,
) -> dict:
    """Take screenshot and gather info with gowitness."""
    context = _authorize("gowitness_tool", "active", engagement_id, engagement_mode, auth_token)
    _audit_tool_call("gowitness_tool", context, target=target)
    return gowitness_scan(target)


@_optional_binary_tool("jaeles_tool")
@_instrument_tool("jaeles_tool", "intrusive")
def jaeles_tool(
    target: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run vulnerability scanning with jaeles."""
    context = _authorize("jaeles_tool", "intrusive", engagement_id, engagement_mode, auth_token)
    _audit_tool_call("jaeles_tool", context, target=target)
    return jaeles_scan(target)


@_optional_binary_tool("cloudflair_tool")
@_instrument_tool("cloudflair_tool", "passive")
def cloudflair_tool(
    domain: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Detect Cloudflare bypasses and origin IPs with cloudflair."""
    context = _authorize("cloudflair_tool", "passive", engagement_id, engagement_mode, auth_token)
    validated_domain = policy.validate_domain(domain)
    _audit_tool_call("cloudflair_tool", context, target=validated_domain)
    return cloudflair_scan(validated_domain)


@_optional_binary_tool("s3scanner_tool")
@_instrument_tool("s3scanner_tool", "active")
def s3scanner_tool(
    bucket: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "active",
    auth_token: str | None = None,
) -> dict:
    """Scan S3 buckets for misconfigurations with s3scanner."""
    context = _authorize("s3scanner_tool", "active", engagement_id, engagement_mode, auth_token)
    _audit_tool_call("s3scanner_tool", context, target=bucket)
    return s3scanner_scan(bucket)


@_optional_binary_tool("trufflehog_tool")
@_instrument_tool("trufflehog_tool", "passive")
def trufflehog_tool(
    file_path: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Scan for secrets in filesystem with trufflehog."""
    context = _authorize("trufflehog_tool", "passive", engagement_id, engagement_mode, auth_token)
    _audit_tool_call("trufflehog_tool", context, target=file_path)
    return trufflehog_scan(file_path)


@_optional_binary_tool("gitleaks_tool")
@_instrument_tool("gitleaks_tool", "passive")
def gitleaks_tool(
    file_path: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
    auth_token: str | None = None,
) -> dict:
    """Scan for secrets in git repos with gitleaks."""
    context = _authorize("gitleaks_tool", "passive", engagement_id, engagement_mode, auth_token)
    _audit_tool_call("gitleaks_tool", context, target=file_path)
    return gitleaks_scan(file_path)


@mcp.tool()
@_instrument_tool("web_surface_assessment_tool", "active")
def web_surface_assessment_tool(
    url: str,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "active",
    auth_token: str | None = None,
) -> dict:
    """Run a normalized web surface assessment using available guarded probes."""
    context = _authorize(
        "web_surface_assessment_tool",
        "active",
        engagement_id,
        engagement_mode,
        auth_token,
    )
    _audit_tool_call("web_surface_assessment_tool", context, target=url)
    return web_surface_assessment(_current_policy.get(), url, cfg.user_agent)


@mcp.tool()
@_instrument_tool("tls_posture_assessment_tool", "active")
def tls_posture_assessment_tool(
    host: str,
    port: int = 443,
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "active",
    auth_token: str | None = None,
) -> dict:
    """Run certificate, expiry, and optional sslscan checks as one workflow."""
    context = _authorize(
        "tls_posture_assessment_tool",
        "active",
        engagement_id,
        engagement_mode,
        auth_token,
    )
    _audit_tool_call(
        "tls_posture_assessment_tool", context, target=f"{host}:{port}"
    )
    return tls_posture_assessment(_current_policy.get(), host, port)


@mcp.tool()
@_instrument_tool("host_exposure_assessment_tool", "intrusive")
def host_exposure_assessment_tool(
    host: str,
    ports: list[int],
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "intrusive",
    auth_token: str | None = None,
) -> dict:
    """Run a policy-bounded TCP exposure assessment with normalized output."""
    context = _authorize(
        "host_exposure_assessment_tool",
        "intrusive",
        engagement_id,
        engagement_mode,
        auth_token,
    )
    _audit_tool_call("host_exposure_assessment_tool", context, target=host)
    return host_exposure_assessment(
        _current_policy.get(), host, ports, cfg.connect_timeout_ms
    )


@mcp.tool()
@_instrument_tool("runtime_probe_tool", "passive")
def runtime_probe_tool(
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
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
        "tool_count_enabled": (
            len(ENABLED_BINARY_MCP_TOOLS)
            + CORE_TOOL_COUNT
            + sum(len(names) for names in PLUGIN_REGISTRATION.values())
        ),
    }


@mcp.tool()
@_instrument_tool("server_health_tool", "passive")
def server_health_tool(
    engagement_id: str | None = None,
    engagement_mode: EngagementMode = "passive",
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
            "audit_signed": AUDIT_CHAIN.signed,
            "raw_tools_enabled": ENABLE_RAW_TOOLS,
            "raw_tool_allowlist": sorted(RAW_TOOL_ALLOWLIST),
            "plugins_enabled": ENABLE_PLUGINS,
            "plugin_allowlist": sorted(PLUGIN_ALLOWLIST),
        },
        "toolchain": {
            "enabled_binary_mcp_tools": ENABLED_BINARY_MCP_TOOLS,
            "enabled_curated_mcp_tools": ENABLED_CURATED_MCP_TOOLS,
            "enabled_raw_mcp_tools": ENABLED_RAW_MCP_TOOLS,
            "binary_mcp_tool_count": len(BINARY_MCP_TOOL_BINARIES),
            "installed_common_kali_tool_count": sum(
                1
                for info in KALI_TOOLCHAIN_SNAPSHOT.values()
                if info.get("installed")
            ),
            "common_kali_tool_count": len(KALI_TOOLCHAIN_SNAPSHOT),
        },
        "plugins": get_plugin_manager().list_plugins(),
        "runtime": {
            "started_at": STARTED_AT.isoformat(),
            "uptime_seconds": int((datetime.now(UTC) - STARTED_AT).total_seconds()),
            "shutting_down": _shutdown_event.is_set(),
        },
    }


def _register_plugins() -> None:
    if not ENABLE_PLUGINS:
        logger.info("External plugin loading is disabled")
        return
    load_all_plugins(PLUGIN_GROUP, allowlist=PLUGIN_ALLOWLIST)
    PLUGIN_REGISTRATION.update(register_plugin_tools(mcp))


_register_dynamic_kali_raw_tools()
_register_plugins()


def main() -> None:
    if "--version" in sys.argv:
        print(f"GhostMCP v{__version__}")
        sys.exit(0)
    if "--healthcheck" in sys.argv:
        _validate_runtime_security()
        _validate_transport_auth_configuration()
        print(
            json.dumps(
                {
                    "status": "ok",
                    "version": __version__,
                    "manifest_schema": TOOL_MANIFEST.export(__version__)[
                        "schema_version"
                    ],
                },
                sort_keys=True,
            )
        )
        sys.exit(0)

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
    core_tool_count = CORE_TOOL_COUNT
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

            app = TransportAuthMiddleware(
                mcp.streamable_http_app(),
                auth_mode=AUTH_MODE,
                token=AUTH_TOKEN,
                allow_insecure_none=ALLOW_INSECURE_REMOTE_NO_AUTH,
            )
            uvicorn_kwargs: dict[str, Any] = {
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
            elif AUTH_MODE == "token" and TLS_CERT and TLS_KEY:
                uvicorn_kwargs.update(
                    {
                        "ssl_keyfile": TLS_KEY,
                        "ssl_certfile": TLS_CERT,
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
