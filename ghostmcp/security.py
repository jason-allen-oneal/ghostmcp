from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import ServerConfig
from .credentials import CredentialStore

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _network_is_within(child: IPNetwork, parent: IPNetwork) -> bool:
    if isinstance(child, ipaddress.IPv4Network) and isinstance(
        parent, ipaddress.IPv4Network
    ):
        return child.subnet_of(parent)
    if isinstance(child, ipaddress.IPv6Network) and isinstance(
        parent, ipaddress.IPv6Network
    ):
        return child.subnet_of(parent)
    return False


@dataclass(frozen=True)
class ValidationResult:
    host: str
    ips: list[str]


class SecurityPolicy:
    def __init__(
        self,
        config: ServerConfig,
        *,
        credentials: Any | None = None,
        scope_digest: str | None = None,
        approval_id: str | None = None,
        approved_by: str | None = None,
    ) -> None:
        self.config = config
        if credentials is None:
            store_path = os.getenv("GHOSTMCP_CREDENTIAL_STORE", "credentials.json")
            credentials = CredentialStore(store_path)
        self.credentials = credentials
        self.scope_digest = scope_digest
        self.approval_id = approval_id
        self.approved_by = approved_by

    def for_engagement(self, engagement_id: str | None) -> SecurityPolicy:
        policy_file = self.config.engagement_policy_file
        if policy_file is None:
            return self
        if not engagement_id:
            raise ValueError(
                "engagement_id is required when an engagement policy file is configured"
            )
        payload = self._load_policy_file(policy_file)
        raw_scope = payload["engagements"].get(engagement_id)
        if not isinstance(raw_scope, dict):
            raise PermissionError(f"No execution policy for engagement: {engagement_id}")
        for required in ("expires_at", "max_tool_level", "allowed_capabilities"):
            if required not in raw_scope:
                raise ValueError(
                    f"Engagement policy is missing required field: {required}"
                )
        if not isinstance(raw_scope["allowed_capabilities"], list):
            raise ValueError("allowed_capabilities must be a list")
        for field in (
            "allowed_cidrs",
            "allowed_domains",
            "allowed_paths",
            "forbidden_paths",
            "allowed_resources",
        ):
            if field in raw_scope and not isinstance(raw_scope[field], list):
                raise ValueError(f"{field} must be a list")
        try:
            expiry = datetime.fromisoformat(
                str(raw_scope["expires_at"]).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError("Invalid engagement policy expiration") from exc
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        if datetime.now(UTC) >= expiry:
            raise PermissionError(f"Execution policy expired for engagement: {engagement_id}")

        capabilities = {
            str(item).strip().lower()
            for item in raw_scope["allowed_capabilities"]
            if str(item).strip()
        }
        requires_approval = (
            str(raw_scope["max_tool_level"]).lower() == "intrusive"
            or bool(
                capabilities
                & {
                    "collection",
                    "credential_access",
                    "raw_execution",
                    "remote_execution",
                }
            )
        )
        authorization = raw_scope.get("authorization")
        if requires_approval:
            self._validate_authorization(authorization)
            if not any(
                raw_scope.get(field)
                for field in (
                    "allowed_cidrs",
                    "allowed_domains",
                    "allowed_paths",
                    "allowed_resources",
                )
            ):
                raise PermissionError(
                    "Intrusive or sensitive policy requires an explicit target scope"
                )

        canonical = json.dumps(raw_scope, sort_keys=True, separators=(",", ":"))
        scoped_config = self._narrow_config(raw_scope)
        return SecurityPolicy(
            scoped_config,
            credentials=self.credentials,
            scope_digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            approval_id=(
                str(authorization["approval_id"])
                if isinstance(authorization, dict)
                else None
            ),
            approved_by=(
                str(authorization["approved_by"])
                if isinstance(authorization, dict)
                else None
            ),
        )

    def narrow(self, scope: dict[str, Any]) -> SecurityPolicy:
        """Return a policy narrowed by a trusted, already-authorized scope."""
        return SecurityPolicy(
            self._narrow_config(scope),
            credentials=self.credentials,
            scope_digest=self.scope_digest,
            approval_id=self.approval_id,
            approved_by=self.approved_by,
        )

    @staticmethod
    def _load_policy_file(path: Path) -> dict[str, Any]:
        stat = path.stat()
        if stat.st_mode & 0o077:
            raise PermissionError("Engagement policy file must have mode 0600")
        if hasattr(os, "getuid") and stat.st_uid != os.getuid():
            raise PermissionError("Engagement policy file must be owned by GhostMCP")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
            raise ValueError("Unsupported engagement policy schema")
        if not isinstance(payload.get("engagements"), dict):
            raise ValueError("Engagement policy file requires an engagements object")
        return payload

    @staticmethod
    def _validate_authorization(authorization: Any) -> None:
        if not isinstance(authorization, dict):
            raise PermissionError(
                "Intrusive or sensitive policy requires authorization provenance"
            )
        for required in ("approval_id", "approved_by", "approved_at", "reason"):
            if not str(authorization.get(required, "")).strip():
                raise ValueError(f"Engagement authorization is missing: {required}")
        for identifier in ("approval_id", "approved_by"):
            value = str(authorization[identifier]).strip()
            if len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9._:@/-]+", value):
                raise ValueError(f"Invalid engagement authorization {identifier}")
        if len(str(authorization["reason"])) > 500:
            raise ValueError("Engagement authorization reason is too long")
        try:
            approved_at = datetime.fromisoformat(
                str(authorization["approved_at"]).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError("Invalid engagement authorization approved_at") from exc
        if approved_at.tzinfo is None:
            approved_at = approved_at.replace(tzinfo=UTC)
        if approved_at > datetime.now(UTC):
            raise ValueError("Engagement authorization approved_at is in the future")

    def _narrow_config(self, scope: dict[str, Any]) -> ServerConfig:
        scoped_cidrs = tuple(
            ipaddress.ip_network(str(item), strict=False)
            for item in scope.get("allowed_cidrs", ())
        )
        if self.config.allowed_cidrs:
            for network in scoped_cidrs:
                if not any(
                    _network_is_within(network, parent)
                    for parent in self.config.allowed_cidrs
                ):
                    raise PermissionError(
                        f"Engagement CIDR broadens server policy: {network}"
                    )
        scoped_domains = tuple(
            str(item).strip().lower().rstrip(".")
            for item in scope.get("allowed_domains", ())
            if str(item).strip()
        )
        if self.config.allowed_domains:
            for domain in scoped_domains:
                if not any(
                    domain == parent or domain.endswith(f".{parent}")
                    for parent in self.config.allowed_domains
                ):
                    raise PermissionError(
                        f"Engagement domain broadens server policy: {domain}"
                    )
        scoped_paths = tuple(
            Path(str(item)).expanduser().resolve()
            for item in scope.get("allowed_paths", ())
        )
        if self.config.allowed_paths:
            for path in scoped_paths:
                if not any(
                    path == parent or path.is_relative_to(parent)
                    for parent in self.config.allowed_paths
                ):
                    raise PermissionError(
                        f"Engagement path broadens server policy: {path}"
                    )
        scoped_forbidden = tuple(
            Path(str(item)).expanduser().resolve()
            for item in scope.get("forbidden_paths", ())
        )
        scoped_capabilities = {
            str(item).strip().lower()
            for item in scope.get("allowed_capabilities", ())
            if str(item).strip()
        }
        if self.config.allowed_capabilities and not scoped_capabilities.issubset(
            self.config.allowed_capabilities
        ):
            raise PermissionError("Engagement capabilities broaden server policy")
        scoped_resources = tuple(
            str(item).strip().lower()
            for item in scope.get("allowed_resources", ())
            if str(item).strip()
        )
        if self.config.allowed_resources and not set(scoped_resources).issubset(
            self.config.allowed_resources
        ):
            raise PermissionError("Engagement resources broaden server policy")
        risk_order = {"passive": 1, "active": 2, "intrusive": 3}
        scoped_risk = str(scope["max_tool_level"]).lower()
        if scoped_risk not in risk_order:
            raise ValueError(f"Unknown engagement max tool level: {scoped_risk}")
        if risk_order[scoped_risk] > risk_order[self.config.max_tool_level]:
            raise PermissionError("Engagement risk broadens server policy")
        return replace(
            self.config,
            allow_private_only=(
                self.config.allow_private_only
                or bool(scope.get("allow_private_only", False))
            ),
            allowed_cidrs=scoped_cidrs,
            allowed_domains=scoped_domains,
            allowed_paths=scoped_paths,
            forbidden_paths=tuple(
                dict.fromkeys((*self.config.forbidden_paths, *scoped_forbidden))
            ),
            allowed_resources=scoped_resources,
            max_tool_level=scoped_risk,
            allowed_capabilities=tuple(sorted(scoped_capabilities)),
            require_routed_execution=(
                self.config.require_routed_execution
                or bool(scope.get("require_routed_execution", False))
            ),
            deny_unscoped_network=True,
        )

    def inject_credentials(self, tool_id: str, target: str, args: list[str]) -> list[str]:
        """Inject stored credentials without mutating the caller's argument list."""
        creds = self.credentials.get_credentials(tool_id, target)
        if not creds:
            return list(args)

        new_args = list(args)
        if tool_id == "sqlmap" and "auth_type" in creds:
            user = str(creds.get("user", ""))
            password = str(creds.get("pass", ""))
            auth_type = str(creds["auth_type"])
            if not user or not password:
                raise ValueError("Stored sqlmap credentials require user and pass")
            new_args.extend(
                [f"--auth-type={auth_type}", f"--auth-cred={user}:{password}"]
            )
        return new_args

    def validate_domain(self, domain: str, *, resolve: bool = True) -> str:
        candidate = domain.strip().lower().rstrip(".")
        if not candidate or len(candidate) > 253 or not DOMAIN_RE.fullmatch(candidate):
            raise ValueError("Invalid domain name")
        if resolve:
            self.enforce_domain_scope(candidate)
        elif self.config.allowed_domains and not any(
            candidate == allowed or candidate.endswith(f".{allowed}")
            for allowed in self.config.allowed_domains
        ):
            raise ValueError(
                f"Domain policy violation: {candidate} not in allowed domains"
            )
        return candidate

    def enforce_domain_scope(self, domain: str) -> None:
        candidate = domain.strip().lower().rstrip(".")
        if not candidate or not DOMAIN_RE.fullmatch(candidate):
            raise ValueError("Invalid domain name")
        domain_allowed = bool(self.config.allowed_domains) and any(
            candidate == allowed or candidate.endswith(f".{allowed}")
            for allowed in self.config.allowed_domains
        )
        if self.config.allowed_domains and not domain_allowed:
            raise ValueError(
                f"Domain policy violation: {candidate} not in allowed domains"
            )
        if (
            self.config.deny_unscoped_network
            and not domain_allowed
            and not self.config.allowed_cidrs
        ):
            raise ValueError(
                f"Domain policy violation: {candidate} has no explicit scope"
            )

        ips = self._resolve_ips(candidate)
        if not ips:
            raise ValueError("Unable to resolve target host")
        self._validate_ip_set(ips, allow_without_cidr=domain_allowed)

    def validate_url(self, url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("URL scheme must be http or https")
        if not parsed.hostname:
            raise ValueError("URL host is required")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials in URLs are not allowed")
        self.validate_target(parsed.hostname)
        if parsed.port is not None:
            self.parse_ports([parsed.port])
        return url

    def parse_ports(self, ports: list[int]) -> list[int]:
        if not ports:
            raise ValueError("At least one port is required")
        deduped = sorted(set(ports))
        if len(deduped) > self.config.max_ports_per_scan:
            raise ValueError(
                f"Port list too large: {len(deduped)} > {self.config.max_ports_per_scan}"
            )
        for port in deduped:
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")
            if port in self.config.blocked_ports:
                raise ValueError(f"Port is blocked by policy: {port}")
        return deduped

    def validate_target(self, host: str) -> ValidationResult:
        candidate = host.strip().strip("[]")
        if not candidate:
            raise ValueError("Target host is required")

        literal: IPAddress | None = None
        try:
            literal = ipaddress.ip_address(candidate)
        except ValueError:
            normalized = self.validate_domain(candidate)
            ips = self._resolve_ips(normalized)
            candidate = normalized
        else:
            ips = [str(literal)]

        if not ips:
            raise ValueError("Unable to resolve target host")
        if literal is not None:
            self._validate_ip_set(ips)
        return ValidationResult(host=candidate, ips=ips)

    def validate_masscan_targets(self, targets: str) -> str:
        """Validate every masscan IP, CIDR, or explicit address range."""
        candidate = targets.strip()
        if not candidate:
            raise ValueError("Masscan targets are required")
        if any(ch in candidate for ch in ";|&`$(){}<>\\\n\r\t"):
            raise ValueError("Invalid characters in masscan targets")

        tokens = [token.strip() for token in candidate.split(",") if token.strip()]
        if not tokens:
            raise ValueError("Masscan targets are required")
        if len(tokens) > 256:
            raise ValueError("Too many masscan target expressions")

        total_addresses = 0
        for token in tokens:
            self._validate_network_expression(token)
            if "-" in token and "/" not in token:
                start_raw, end_raw = token.split("-", 1)
                start = ipaddress.ip_address(start_raw)
                if "." not in end_raw and isinstance(start, ipaddress.IPv4Address):
                    end_raw = ".".join(start_raw.split(".")[:-1] + [end_raw])
                total_addresses += int(ipaddress.ip_address(end_raw)) - int(start) + 1
            else:
                total_addresses += ipaddress.ip_network(
                    token, strict=False
                ).num_addresses
        if total_addresses > self.config.max_target_addresses:
            raise ValueError(
                f"Target set is too large: {total_addresses} > "
                f"{self.config.max_target_addresses}"
            )
        return ",".join(tokens)

    def validate_network_targets(self, targets: str) -> str:
        return self.validate_masscan_targets(targets)

    def validate_path(self, path: str) -> Path:
        candidate = Path(path).expanduser().resolve()
        if not self.config.allowed_paths:
            raise ValueError(
                "Filesystem-scoped tools require explicit allowed paths"
            )
        if any(
            candidate == forbidden or candidate.is_relative_to(forbidden)
            for forbidden in self.config.forbidden_paths
        ):
            raise ValueError(f"Filesystem policy violation: forbidden path {candidate}")
        if self.config.allowed_paths and not any(
            candidate == allowed or candidate.is_relative_to(allowed)
            for allowed in self.config.allowed_paths
        ):
            raise ValueError(
                f"Filesystem policy violation: {candidate} is outside allowed paths"
            )
        return candidate

    def validate_resource(self, resource: str) -> str:
        candidate = resource.strip().lower()
        if not candidate:
            raise ValueError("Resource identifier is required")
        if not self.config.allowed_resources:
            raise ValueError(
                "Resource-scoped tools require an explicit allowed-resources policy"
            )
        if candidate not in self.config.allowed_resources:
            raise ValueError(f"Resource policy violation: {candidate}")
        return candidate

    def _validate_network_expression(self, token: str) -> None:
        if "-" in token:
            start_raw, separator, end_raw = token.partition("-")
            if not separator or not start_raw or not end_raw or "-" in end_raw:
                raise ValueError(f"Invalid address range: {token}")
            start = ipaddress.ip_address(start_raw)
            end = ipaddress.ip_address(end_raw)
            if start.version != end.version or int(start) > int(end):
                raise ValueError(f"Invalid address range: {token}")
            self._validate_range(start, end)
            return

        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            address = ipaddress.ip_address(token)
            self._validate_ip_set([str(address)])
            return
        self._validate_network(network)

    def _validate_network(self, network: ipaddress._BaseNetwork) -> None:
        start = network.network_address
        end = network.broadcast_address
        self._validate_range(start, end)

    def _validate_range(
        self, start: ipaddress._BaseAddress, end: ipaddress._BaseAddress
    ) -> None:
        if self.config.allow_private_only and not any(
            start in network and end in network
            for network in _PRIVATE_NETWORKS
            if network.version == start.version
        ):
            raise ValueError(
                f"Target policy violation: range {start}-{end} is not fully private"
            )
        if self.config.allowed_cidrs and not any(
            start in cidr and end in cidr
            for cidr in self.config.allowed_cidrs
            if cidr.version == start.version
        ):
            raise ValueError(
                f"Target policy violation: range {start}-{end} is outside allowed CIDRs"
            )
        if self.config.deny_unscoped_network and not self.config.allowed_cidrs:
            raise ValueError("Network target has no explicit CIDR scope")

    def _validate_ip_set(
        self, ips: list[str], *, allow_without_cidr: bool = False
    ) -> None:
        for ip in ips:
            address = ipaddress.ip_address(ip)
            if address.is_unspecified or address.is_multicast:
                raise ValueError(f"Target policy violation: disallowed address {ip}")
            if self.config.allow_private_only and not any(
                address in network
                for network in _PRIVATE_NETWORKS
                if network.version == address.version
            ):
                raise ValueError(
                    "Target policy violation: only private addresses are allowed"
                )
            if self.config.allowed_cidrs and not any(
                address in cidr
                for cidr in self.config.allowed_cidrs
                if cidr.version == address.version
            ):
                raise ValueError(
                    f"Target policy violation: {ip} not in allowed CIDRs"
                )
            if (
                self.config.deny_unscoped_network
                and not self.config.allowed_cidrs
                and not allow_without_cidr
            ):
                raise ValueError(f"IP target has no explicit CIDR scope: {ip}")

    @staticmethod
    def _resolve_ips(host: str) -> list[str]:
        try:
            addrinfo = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return []
        ips: list[str] = []
        for info in addrinfo:
            ip = str(info[4][0])
            if ip not in ips:
                ips.append(ip)
        return ips
