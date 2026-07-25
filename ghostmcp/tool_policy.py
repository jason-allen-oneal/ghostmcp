"""Versioned metadata and effective-target enforcement for every MCP tool."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

ManifestRisk = Literal["passive", "active", "intrusive"]
RouteSupport = Literal["not_applicable", "direct_only", "proxy_aware"]
TargetKind = Literal[
    "host",
    "domain",
    "url",
    "url_or_host",
    "network",
    "raw_argv",
    "extra_argv",
    "path",
    "resource",
]

MANIFEST_SCHEMA_VERSION = "1.0"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

CREDENTIAL_TOOLS = {
    "crackmapexec",
    "hydra",
    "rpcclient",
    "smbclient",
    "smbmap",
    "sqlmap",
}
COLLECTION_TOOLS = {
    "binwalk",
    "exiftool",
    "gitleaks",
    "s3scanner",
    "smbclient",
    "smbmap",
    "sqlmap",
    "theharvester",
    "trufflehog",
}
REMOTE_EXECUTION_TOOLS = {
    "commix",
    "crackmapexec",
    "evil_winrm",
    "impacket_psexec",
    "impacket_wmiexec",
    "msfconsole",
    "netexec",
}
LOCAL_RAW_BINARIES = {
    "aircrack-ng",
    "binwalk",
    "cewl",
    "exiftool",
    "gdb",
    "ghidra",
    "gitleaks",
    "hash-identifier",
    "hashcat",
    "john",
    "pwndbg",
    "radare2",
    "searchsploit",
    "trufflehog",
}
PROXY_AWARE_CURATED = {
    "amass_passive_tool",
    "assetfinder_tool",
    "cloudflair_tool",
    "crackmapexec_tool",
    "dirsearch_tool",
    "dnsrecon_tool",
    "dnsx_tool",
    "enum4linux_ng_tool",
    "feroxbuster_tool",
    "ffuf_tool",
    "gobuster_dir_tool",
    "gowitness_tool",
    "http_probe_tool",
    "hydra_tool",
    "jaeles_tool",
    "masscan_tool",
    "nikto_tool",
    "nmap_service_scan_tool",
    "nuclei_tool",
    "rpcclient_tool",
    "smbclient_tool",
    "smbmap_tool",
    "security_txt_tool",
    "sqlmap_tool",
    "sslscan_tool",
    "sslyze_tool",
    "subfinder_tool",
    "theharvester_tool",
    "wafw00f_tool",
    "wfuzz_tool",
    "whatweb_tool",
    "web_surface_assessment_tool",
    "wpscan_tool",
}


@dataclass(frozen=True)
class TargetField:
    name: str
    kind: TargetKind


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    risk: ManifestRisk
    capabilities: tuple[str, ...]
    target_fields: tuple[TargetField, ...]
    route_support: RouteSupport
    raw: bool = False
    binary: str | None = None
    available: bool = True
    sensitive_output: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["target_fields"] = [asdict(field) for field in self.target_fields]
        return payload


class ToolManifest:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDescriptor] = {}

    def register(self, descriptor: ToolDescriptor) -> ToolDescriptor:
        existing = self._tools.get(descriptor.name)
        if existing is not None and existing != descriptor:
            raise ValueError(f"Conflicting security metadata: {descriptor.name}")
        self._tools[descriptor.name] = descriptor
        return descriptor

    def get(self, name: str) -> ToolDescriptor:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ValueError(f"Tool has no security metadata: {name}") from exc

    def export(self, server_version: str) -> dict[str, Any]:
        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "server_version": server_version,
            "tools": [
                self._tools[name].to_dict() for name in sorted(self._tools)
            ],
        }


TOOL_MANIFEST = ToolManifest()


def _normalized(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def capabilities_for(name: str, *, raw: bool = False) -> tuple[str, ...]:
    normalized = _normalized(name.removesuffix("_tool"))
    capabilities = {"discovery"}
    if any(token in normalized for token in CREDENTIAL_TOOLS):
        capabilities.add("credential_access")
    if any(token in normalized for token in COLLECTION_TOOLS):
        capabilities.add("collection")
    if any(token in normalized for token in REMOTE_EXECUTION_TOOLS):
        capabilities.add("remote_execution")
    if raw:
        capabilities.add("raw_execution")
    return tuple(sorted(capabilities))


def target_fields_for(name: str) -> tuple[TargetField, ...]:
    if name in {
        "metrics_tool",
        "runtime_probe_tool",
        "server_health_tool",
        "tool_manifest_tool",
        "toolchain_status_tool",
        "verify_audit_log_integrity_tool",
    }:
        return ()
    if name in {
        "common_web_paths_tool",
        "ioc_extract_tool",
        "searchsploit_tool",
        "subdomain_candidates_tool",
        "url_risk_score_tool",
    }:
        return ()
    if name in {
        "dns_lookup_tool",
        "amass_passive_tool",
        "theharvester_tool",
        "dnsrecon_tool",
        "subfinder_tool",
        "assetfinder_tool",
        "dnsx_tool",
        "cloudflair_tool",
        "security_txt_tool",
    }:
        return (TargetField("domain", "domain"),)
    if name in {
        "http_probe_tool",
        "sqlmap_tool",
        "gobuster_dir_tool",
        "whatweb_tool",
        "wafw00f_tool",
        "nikto_tool",
        "wpscan_tool",
        "dirsearch_tool",
        "ffuf_tool",
        "feroxbuster_tool",
        "wfuzz_tool",
        "web_surface_assessment_tool",
    }:
        return (
            TargetField("url", "url"),
            TargetField("args", "extra_argv"),
            TargetField("wordlist", "path"),
        )
    if name in {"nuclei_tool", "gowitness_tool", "jaeles_tool"}:
        return (
            TargetField("target", "url_or_host"),
            TargetField("templates", "path"),
        )
    if name == "masscan_tool":
        return (TargetField("targets", "network"),)
    if name in {
        "exiftool_tool",
        "binwalk_tool",
        "trufflehog_tool",
        "gitleaks_tool",
    }:
        return (TargetField("file_path", "path"),)
    if name == "s3scanner_tool":
        return (TargetField("bucket", "resource"),)
    if name == "reverse_dns_tool":
        return (TargetField("ip", "host"),)
    if name == "hydra_tool":
        return (TargetField("target", "host"), TargetField("wordlist", "path"))
    if name == "crackmapexec_tool":
        return (
            TargetField("target", "host"),
            TargetField("args", "extra_argv"),
        )
    if name == "smbmap_tool":
        return (
            TargetField("host", "host"),
            TargetField("args", "extra_argv"),
        )
    return (
        TargetField("host", "host"),
        TargetField("target", "host"),
        TargetField("ip_address", "host"),
    )


def descriptor_for_curated(
    name: str,
    risk: ManifestRisk,
    *,
    available: bool = True,
) -> ToolDescriptor:
    fields = target_fields_for(name)
    networked = any(field.kind not in {"path", "resource"} for field in fields)
    capabilities = capabilities_for(name)
    return ToolDescriptor(
        name=name,
        risk=risk,
        capabilities=capabilities,
        target_fields=fields,
        route_support=(
            "proxy_aware"
            if name in PROXY_AWARE_CURATED
            else "direct_only"
            if networked
            else "not_applicable"
        ),
        available=available,
        sensitive_output=bool(
            {"credential_access", "collection", "remote_execution"}
            & set(capabilities)
        ),
    )


def descriptor_for_raw(
    name: str,
    binary: str,
    *,
    available: bool,
) -> ToolDescriptor:
    local = binary in LOCAL_RAW_BINARIES
    capabilities = capabilities_for(binary, raw=True)
    return ToolDescriptor(
        name=name,
        risk="intrusive",
        capabilities=capabilities,
        target_fields=(TargetField("args", "path" if local else "raw_argv"),),
        route_support="not_applicable" if local else "proxy_aware",
        raw=True,
        binary=binary,
        available=available,
        sensitive_output=True,
    )


def extract_network_targets(
    binary: str,
    args: list[str],
    *,
    required: bool,
) -> list[tuple[str, str]]:
    if binary in LOCAL_RAW_BINARIES:
        return []
    targets: list[tuple[str, str]] = []
    for token in args:
        candidate = token.strip().strip("[](),")
        if not candidate:
            continue
        if candidate.startswith("-"):
            if "=" not in candidate:
                continue
            candidate = candidate.split("=", 1)[1]
        if "://" in candidate:
            if urlsplit(candidate).hostname:
                targets.append(("url", candidate))
            continue
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[1]
        candidate = candidate.split(":", 1)[0]
        try:
            ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            if DOMAIN_RE.fullmatch(candidate.rstrip(".")):
                targets.append(("domain", candidate.rstrip(".")))
        else:
            targets.append(("network", candidate))
    if required and not targets:
        raise ValueError(
            f"Raw network tool '{binary}' requires a recognizable target"
        )
    return targets


def enforce_capabilities(
    descriptor: ToolDescriptor,
    allowed_capabilities: tuple[str, ...],
) -> None:
    denied = sorted(set(descriptor.capabilities) - set(allowed_capabilities))
    if denied:
        raise PermissionError(f"Tool capability not allowed: {', '.join(denied)}")


def validate_effective_arguments(
    descriptor: ToolDescriptor,
    arguments: dict[str, Any],
    security_policy: Any,
) -> None:
    for field in descriptor.target_fields:
        value = arguments.get(field.name)
        if value in (None, "", []):
            continue
        if field.kind == "host":
            security_policy.validate_target(str(value))
        elif field.kind == "domain":
            security_policy.validate_domain(str(value))
        elif field.kind == "url":
            security_policy.validate_url(str(value))
        elif field.kind == "url_or_host":
            if "://" in str(value):
                security_policy.validate_url(str(value))
            else:
                security_policy.validate_target(str(value))
        elif field.kind == "network":
            security_policy.validate_network_targets(str(value))
        elif field.kind in {"raw_argv", "extra_argv"}:
            if not isinstance(value, list):
                raise ValueError("Tool args must be a list")
            if field.kind == "extra_argv":
                continue
            for kind, target in extract_network_targets(
                descriptor.binary or descriptor.name,
                [str(item) for item in value],
                required=True,
            ):
                if kind == "url":
                    security_policy.validate_url(target)
                elif kind == "domain":
                    security_policy.validate_domain(target)
                else:
                    security_policy.validate_network_targets(target)
        elif field.kind == "path":
            values = value if isinstance(value, list) else [value]
            paths = [
                str(item)
                for item in values
                if str(item) and not str(item).startswith("-")
            ]
            if descriptor.raw and not paths:
                raise ValueError(
                    f"Raw filesystem tool '{descriptor.name}' requires a path"
                )
            for path in paths:
                security_policy.validate_path(path)
        elif field.kind == "resource":
            security_policy.validate_resource(str(value))
