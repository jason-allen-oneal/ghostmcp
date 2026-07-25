from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class ServerConfig:
    max_ports_per_scan: int = 256
    connect_timeout_ms: int = 1500
    max_concurrent_connects: int = 64
    max_target_addresses: int = 4096
    allow_private_only: bool = True
    allowed_cidrs: tuple[IPNetwork, ...] = field(default_factory=tuple)
    blocked_ports: tuple[int, ...] = (22, 2375, 2376, 3389)
    user_agent: str = "GhostMCP/0.2"
    require_engagement_context: bool = False
    allowed_domains: tuple[str, ...] = field(default_factory=tuple)
    max_tool_level: str = "intrusive"
    allowed_capabilities: tuple[str, ...] = field(default_factory=tuple)
    allow_raw_tools: bool = False
    require_routed_execution: bool = False
    allowed_paths: tuple[Path, ...] = field(default_factory=tuple)
    forbidden_paths: tuple[Path, ...] = field(default_factory=tuple)
    allowed_resources: tuple[str, ...] = field(default_factory=tuple)
    engagement_policy_file: Path | None = None
    allow_unscoped_intrusive: bool = False

    def __post_init__(self) -> None:
        positive_values = {
            "max_ports_per_scan": self.max_ports_per_scan,
            "connect_timeout_ms": self.connect_timeout_ms,
            "max_concurrent_connects": self.max_concurrent_connects,
            "max_target_addresses": self.max_target_addresses,
        }
        for name, value in positive_values.items():
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_tool_level not in {"passive", "active", "intrusive"}:
            raise ValueError(f"Unsupported max_tool_level: {self.max_tool_level}")
        known_capabilities = {
            "collection",
            "credential_access",
            "discovery",
            "raw_execution",
            "remote_execution",
        }
        unknown = sorted(set(self.allowed_capabilities) - known_capabilities)
        if unknown:
            raise ValueError(f"Unknown allowed capabilities: {', '.join(unknown)}")


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    return int(value)


def _parse_cidrs(value: str | None) -> tuple[IPNetwork, ...]:
    if not value:
        return tuple()
    cidrs = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        cidrs.append(ipaddress.ip_network(raw, strict=False))
    return tuple(cidrs)


def _parse_ports(value: str | None, default: tuple[int, ...]) -> tuple[int, ...]:
    if not value:
        return default
    ports = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        port = int(raw)
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid blocked port value: {port}")
        ports.append(port)
    return tuple(sorted(set(ports)))


def _parse_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return tuple()
    return tuple(item.strip().lower() for item in value.split(",") if item.strip())


def _parse_paths(value: str | None) -> tuple[Path, ...]:
    if not value:
        return tuple()
    return tuple(
        Path(item.strip()).expanduser().resolve()
        for item in value.split(",")
        if item.strip()
    )


def _parse_optional_path(value: str | None) -> Path | None:
    if not value or not value.strip():
        return None
    return Path(value.strip()).expanduser().resolve()


def _env(name: str, default: str | None = None) -> str | None:
    return os.getenv(f"GHOSTMCP_{name}", default)


def load_config() -> ServerConfig:
    return ServerConfig(
        max_ports_per_scan=_parse_int(_env("MAX_PORTS_PER_SCAN"), 256),
        connect_timeout_ms=_parse_int(_env("CONNECT_TIMEOUT_MS"), 1500),
        max_concurrent_connects=_parse_int(
            _env("MAX_CONCURRENT_CONNECTS"), 64
        ),
        max_target_addresses=_parse_int(
            _env("MAX_TARGET_ADDRESSES"),
            4096,
        ),
        allow_private_only=_parse_bool(
            _env("ALLOW_PRIVATE_ONLY"),
            True,
        ),
        allowed_cidrs=_parse_cidrs(_env("ALLOWED_CIDRS")),
        blocked_ports=_parse_ports(
            _env("BLOCKED_PORTS"),
            (22, 2375, 2376, 3389),
        ),
        user_agent=_env("USER_AGENT", "GhostMCP/0.2") or "GhostMCP/0.2",
        require_engagement_context=_parse_bool(
            _env("REQUIRE_ENGAGEMENT_CONTEXT"),
            False,
        ),
        allowed_domains=_parse_csv(_env("ALLOWED_DOMAINS")),
        max_tool_level=(_env("MAX_TOOL_LEVEL", "intrusive") or "intrusive")
        .strip()
        .lower(),
        allowed_capabilities=_parse_csv(_env("ALLOWED_CAPABILITIES")),
        allow_raw_tools=_parse_bool(_env("ALLOW_RAW_TOOLS"), False),
        require_routed_execution=_parse_bool(
            _env("REQUIRE_ROUTED_EXECUTION"),
            False,
        ),
        allowed_paths=_parse_paths(_env("ALLOWED_PATHS")),
        forbidden_paths=_parse_paths(_env("FORBIDDEN_PATHS")),
        allowed_resources=_parse_csv(_env("ALLOWED_RESOURCES")),
        engagement_policy_file=_parse_optional_path(
            _env("ENGAGEMENT_POLICY_FILE")
        ),
        allow_unscoped_intrusive=_parse_bool(
            _env("ALLOW_UNSCOPED_INTRUSIVE"),
            False,
        ),
    )
