"""Versioned tool metadata and effective-argument policy enforcement.

GhostMCP is frequently embedded by a higher-level orchestrator, but it must
remain safe when called directly.  This module is therefore deliberately
client-agnostic: it describes what tools can do and validates the targets they
will actually receive.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal
from urllib.parse import urlparse

ManifestRisk = Literal["passive", "active", "intrusive"]
RouteSupport = Literal["not_applicable", "direct_only", "proxy_aware"]

MANIFEST_SCHEMA_VERSION = "1.0"

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

_CREDENTIAL_NAMES = {
    "aircrack_ng",
    "crackmapexec",
    "evil_winrm",
    "hydra",
    "hashcat",
    "impacket_secretsdump",
    "kerbrute",
    "john",
    "medusa",
    "netexec",
    "patator",
    "rpcclient",
    "smbclient",
    "smbmap",
    "sqlmap",
}
_EXECUTION_NAMES = {
    "bettercap",
    "commix",
    "crackmapexec",
    "ettercap",
    "evil_winrm",
    "hping3",
    "impacket_psexec",
    "impacket_wmiexec",
    "metasploit",
    "mitm6",
    "msfconsole",
    "nc",
    "netcat",
    "netexec",
    "responder",
    "socat",
}
_COLLECTION_NAMES = {
    "binwalk",
    "bloodhound_python",
    "exiftool",
    "gitleaks",
    "impacket_secretsdump",
    "smbclient",
    "smbmap",
    "sqlmap",
    "tcpdump",
    "theharvester",
    "trufflehog",
    "tshark",
    "wireshark",
}
_LOCAL_RAW_BINARIES = {
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


@dataclass(frozen=True)
class TargetField:
    name: str
    kind: Literal[
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

    def to_manifest_entry(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["target_fields"] = [asdict(field) for field in self.target_fields]
        return payload


class ToolManifest:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDescriptor] = {}

    def register(self, descriptor: ToolDescriptor) -> ToolDescriptor:
        current = self._tools.get(descriptor.name)
        if current is not None and current != descriptor:
            raise ValueError(f"Conflicting metadata for tool: {descriptor.name}")
        self._tools[descriptor.name] = descriptor
        return descriptor

    def get(self, name: str) -> ToolDescriptor:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ValueError(f"Tool has no security metadata: {name}") from exc

    def export(self, *, server_version: str) -> dict[str, Any]:
        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "server_version": server_version,
            "tools": [
                self._tools[name].to_manifest_entry()
                for name in sorted(self._tools)
            ],
        }


TOOL_MANIFEST = ToolManifest()


def _normalized_binary_name(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _capabilities(name: str, *, raw: bool) -> tuple[str, ...]:
    normalized = _normalized_binary_name(name)
    capabilities = {"discovery"}
    if any(token in normalized for token in _CREDENTIAL_NAMES):
        capabilities.add("credential_access")
    if any(token in normalized for token in _EXECUTION_NAMES):
        capabilities.add("remote_execution")
    if any(token in normalized for token in _COLLECTION_NAMES):
        capabilities.add("collection")
    if raw:
        capabilities.add("raw_execution")
    return tuple(sorted(capabilities))


def _curated_target_fields(name: str) -> tuple[TargetField, ...]:
    if name in {
        "runtime_probe_tool",
        "server_health_tool",
        "toolchain_status_tool",
        "metrics_tool",
        "ioc_extract_tool",
        "searchsploit_tool",
        "verify_audit_log_integrity_tool",
        "tool_manifest_tool",
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
        "subdomain_candidates_tool",
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
    }:
        fields = [TargetField("url", "url")]
        if name in {
            "sqlmap_tool",
            "wpscan_tool",
            "dirsearch_tool",
        }:
            fields.append(TargetField("args", "extra_argv"))
        if name in {
            "gobuster_dir_tool",
            "ffuf_tool",
            "feroxbuster_tool",
            "wfuzz_tool",
        }:
            fields.append(TargetField("wordlist", "path"))
        return tuple(fields)
    if name in {"url_risk_score_tool"}:
        return (TargetField("url", "url"),)
    if name == "common_web_paths_tool":
        return (TargetField("base_url", "url"),)
    if name in {"nuclei_tool", "gowitness_tool", "jaeles_tool"}:
        fields = [TargetField("target", "url_or_host")]
        if name == "nuclei_tool":
            fields.append(TargetField("templates", "path"))
        return tuple(fields)
    if name == "masscan_tool":
        return (TargetField("targets", "network"),)
    if name in {"exiftool_tool", "binwalk_tool", "trufflehog_tool", "gitleaks_tool"}:
        return (TargetField("file_path", "path"),)
    if name == "s3scanner_tool":
        return (TargetField("bucket", "resource"),)
    if name == "reverse_dns_tool":
        return (TargetField("ip", "host"),)
    if name == "hydra_tool":
        return (
            TargetField("target", "host"),
            TargetField("wordlist", "path"),
        )
    if name in {"crackmapexec_tool", "smbmap_tool"}:
        return (
            TargetField("target", "host"),
            TargetField("host", "host"),
            TargetField("args", "extra_argv"),
        )
    for field in ("host", "ip", "target"):
        if field in name:
            return (TargetField(field, "host"),)
    # Most remaining structured network wrappers use host or target. The
    # runtime binder simply ignores a declared field when it is absent.
    return (TargetField("host", "host"), TargetField("target", "host"))


def descriptor_for_curated(name: str, risk: ManifestRisk) -> ToolDescriptor:
    fields = _curated_target_fields(name)
    networked = any(field.kind != "path" for field in fields)
    capabilities = _capabilities(name.removesuffix("_tool"), raw=False)
    return ToolDescriptor(
        name=name,
        risk=risk,
        capabilities=capabilities,
        target_fields=fields,
        route_support="direct_only" if networked else "not_applicable",
        sensitive_output=bool(
            {"credential_access", "collection"} & set(capabilities)
        ),
    )


def descriptor_for_raw(
    name: str,
    binary: str,
    *,
    available: bool,
) -> ToolDescriptor:
    normalized = _normalized_binary_name(binary)
    local_only = binary in _LOCAL_RAW_BINARIES
    capabilities = _capabilities(normalized, raw=True)
    return ToolDescriptor(
        name=name,
        risk="intrusive",
        capabilities=capabilities,
        target_fields=(
            TargetField("args", "path" if local_only else "raw_argv"),
        ),
        route_support="not_applicable" if local_only else "proxy_aware",
        raw=True,
        binary=binary,
        available=available,
        sensitive_output=bool(
            {"credential_access", "collection", "remote_execution"}
            & set(capabilities)
        ),
    )


def extract_raw_network_targets(
    binary: str,
    args: list[str],
    *,
    require_target: bool = True,
) -> list[tuple[str, str]]:
    """Extract network destinations from raw argv.

    The parser is intentionally conservative. A network-capable raw tool is
    rejected when no recognizable target is present; callers should use a
    structured wrapper rather than inventing opaque syntax.
    """
    if binary in _LOCAL_RAW_BINARIES:
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
            parsed = urlparse(candidate)
            if parsed.hostname:
                targets.append(("url", candidate))
            continue
        # Common credential@host syntax. Credentials are not retained.
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[1]
        candidate = candidate.split(":", 1)[0]
        try:
            ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            if _DOMAIN_RE.match(candidate.rstrip(".")):
                targets.append(("domain", candidate.rstrip(".")))
        else:
            targets.append(("network", candidate))
    if require_target and not targets:
        raise ValueError(
            f"Raw network tool '{binary}' requires a recognizable explicit target"
        )
    return targets


def enforce_capabilities(
    descriptor: ToolDescriptor,
    allowed_capabilities: tuple[str, ...],
) -> None:
    if not allowed_capabilities:
        return
    denied = sorted(set(descriptor.capabilities) - set(allowed_capabilities))
    if denied:
        raise PermissionError(
            f"Tool capability not allowed: {', '.join(denied)}"
        )


def validate_effective_arguments(
    descriptor: ToolDescriptor,
    arguments: dict[str, Any],
    security_policy: Any,
) -> None:
    """Validate the bound arguments that will reach the tool implementation."""
    for field in descriptor.target_fields:
        value = arguments.get(field.name)
        if value in (None, "", []):
            continue
        if field.kind == "host":
            security_policy.validate_target(str(value))
        elif field.kind == "domain":
            security_policy.validate_domain(str(value), resolve=True)
        elif field.kind == "url":
            security_policy.validate_url(str(value))
        elif field.kind == "url_or_host":
            if "://" in str(value):
                security_policy.validate_url(str(value))
            else:
                security_policy.validate_target(str(value))
        elif field.kind == "network":
            security_policy.validate_network_targets(str(value))
        elif field.kind == "raw_argv":
            if not isinstance(value, list):
                raise ValueError("Raw tool args must be a list")
            for kind, target in extract_raw_network_targets(
                descriptor.binary or descriptor.name,
                [str(item) for item in value],
            ):
                if kind == "url":
                    security_policy.validate_url(target)
                elif kind == "domain":
                    security_policy.validate_domain(target, resolve=True)
                else:
                    security_policy.validate_network_targets(target)
        elif field.kind == "extra_argv":
            if not isinstance(value, list):
                raise ValueError("Tool args must be a list")
            for kind, target in extract_raw_network_targets(
                descriptor.binary or descriptor.name,
                [str(item) for item in value],
                require_target=False,
            ):
                if kind == "url":
                    security_policy.validate_url(target)
                elif kind == "domain":
                    security_policy.validate_domain(target, resolve=True)
                else:
                    security_policy.validate_network_targets(target)
        elif field.kind == "path":
            values = value if isinstance(value, list) else [value]
            candidates = [
                str(item)
                for item in values
                if str(item) and not str(item).startswith("-")
            ]
            if descriptor.raw and not candidates:
                raise ValueError(
                    f"Raw filesystem tool '{descriptor.name}' requires an explicit path"
                )
            for candidate in candidates:
                security_policy.validate_path(candidate)
        elif field.kind == "resource":
            security_policy.validate_resource(str(value))
