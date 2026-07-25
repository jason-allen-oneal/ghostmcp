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
from urllib.parse import urlparse

from .config import ServerConfig
from .credentials import CredentialStore

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
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


@dataclass
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
            raise ValueError("engagement_id is required when an engagement policy file is configured")
        payload = self._load_policy_file(policy_file)
        raw_scope = payload.get("engagements", {}).get(engagement_id)
        if not isinstance(raw_scope, dict):
            raise PermissionError(f"No execution policy for engagement: {engagement_id}")
        for required in ("expires_at", "max_tool_level", "allowed_capabilities"):
            if required not in raw_scope:
                raise ValueError(
                    f"Engagement policy is missing required field: {required}"
                )
        if not isinstance(raw_scope["allowed_capabilities"], list):
            raise ValueError("allowed_capabilities must be a list")
        expires_at = raw_scope.get("expires_at")
        if expires_at:
            try:
                expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("Invalid engagement policy expiration") from exc
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if datetime.now(UTC) >= expiry:
                raise PermissionError(f"Execution policy expired for engagement: {engagement_id}")
        canonical = json.dumps(raw_scope, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        capabilities = {
            str(item).strip().lower()
            for item in raw_scope.get("allowed_capabilities", ())
        }
        requires_approval = (
            str(raw_scope.get("max_tool_level", "")).lower() == "intrusive"
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
            if not isinstance(authorization, dict):
                raise PermissionError(
                    "Intrusive or sensitive engagement policy requires authorization provenance"
                )
            for required in ("approval_id", "approved_by", "approved_at", "reason"):
                if not str(authorization.get(required, "")).strip():
                    raise ValueError(
                        f"Engagement authorization is missing: {required}"
                    )
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
        scoped_config = self._narrow_config(raw_scope)
        return SecurityPolicy(
            scoped_config,
            credentials=self.credentials,
            scope_digest=digest,
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

    @staticmethod
    def _load_policy_file(path: Path) -> dict[str, Any]:
        stat = path.stat()
        if stat.st_mode & 0o077:
            raise PermissionError("Engagement policy file must have mode 0600")
        if hasattr(os, "getuid") and stat.st_uid != os.getuid():
            raise PermissionError("Engagement policy file must be owned by the GhostMCP user")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
            raise ValueError("Unsupported engagement policy schema")
        if not isinstance(payload.get("engagements"), dict):
            raise ValueError("Engagement policy file requires an engagements object")
        return payload

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
            str(item).strip().lower()
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
        global_capabilities = set(self.config.allowed_capabilities)
        scoped_capabilities = {
            str(item).strip().lower()
            for item in scope.get("allowed_capabilities", ())
            if str(item).strip()
        }
        if global_capabilities and not scoped_capabilities.issubset(global_capabilities):
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
        scoped_risk = str(scope.get("max_tool_level", self.config.max_tool_level)).lower()
        if scoped_risk not in risk_order:
            raise ValueError(f"Unknown engagement max tool level: {scoped_risk}")
        if risk_order[scoped_risk] > risk_order.get(self.config.max_tool_level, 3):
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
        )

    def inject_credentials(self, tool_id: str, target: str, args: list[str]) -> list[str]:
        """Inject credentials from the store into the command arguments."""
        creds = self.credentials.get_credentials(tool_id, target)
        if not creds:
            return args

        # Tool-specific injection logic
        new_args = list(args)
        if tool_id == "sqlmap" and "auth_type" in creds:
            # Example: --auth-type=basic --auth-cred=user:pass
            new_args.extend([f"--auth-type={creds['auth_type']}", f"--auth-cred={creds['user']}:{creds['pass']}"])
        elif tool_id == "hydra":
            # For hydra, we might override user/pass if provided in store
            pass # hydra usually takes user/pass as positional or -l/-p

        return new_args

    def validate_domain(self, domain: str, *, resolve: bool = False) -> str:
        candidate = domain.strip().lower()
        if not candidate or len(candidate) > 253 or not DOMAIN_RE.match(candidate):
            raise ValueError("Invalid domain name")
        candidate = candidate.rstrip(".")
        self.enforce_domain_scope(candidate)
        if resolve:
            # Domain policy and address policy are separate restrictions. This
            # closes domain-key bypasses of private/CIDR scope.
            self.validate_target(candidate)
        return candidate

    def enforce_domain_scope(self, domain: str) -> None:
        if not self.config.allowed_domains:
            return
        if any(
            domain == allowed or domain.endswith(f".{allowed}")
            for allowed in self.config.allowed_domains
        ):
            return
        raise ValueError(f"Domain policy violation: {domain} not in allowed domains")

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
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            if "." in candidate:
                normalized_domain = candidate.lower().rstrip(".")
                if not DOMAIN_RE.match(normalized_domain):
                    raise ValueError("Invalid target hostname") from None
                self.enforce_domain_scope(normalized_domain)
            elif self.config.allowed_domains:
                raise ValueError(
                    "Single-label hostnames are not allowed by domain policy"
                ) from None

        ips = self._resolve_ips(candidate)
        if not ips:
            raise ValueError("Unable to resolve target host")

        for ip in ips:
            ip_obj = ipaddress.ip_address(ip)
            self._validate_ip(ip_obj)

        return ValidationResult(host=candidate, ips=ips)

    def validate_url(self, url: str) -> str:
        candidate = url.strip()
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http and https URLs are allowed")
        if not parsed.hostname:
            raise ValueError("URL host is required")
        if parsed.username or parsed.password:
            raise ValueError("Credentials in URLs are not allowed")
        if parsed.port is not None:
            self.parse_ports([parsed.port])
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            self.validate_domain(parsed.hostname, resolve=True)
        else:
            self.validate_target(parsed.hostname)
        return candidate

    def parse_port_spec(self, ports: str) -> str:
        candidate = ports.strip()
        if not candidate:
            raise ValueError("Port specification is required")
        expanded: list[int] = []
        for item in candidate.split(","):
            item = item.strip()
            if not item:
                raise ValueError("Invalid empty port item")
            if "-" in item:
                start_raw, end_raw = item.split("-", 1)
                start, end = int(start_raw), int(end_raw)
                if end < start:
                    raise ValueError(f"Invalid port range: {item}")
                if end - start + 1 > self.config.max_ports_per_scan:
                    raise ValueError(f"Port range is too large: {item}")
                expanded.extend(range(start, end + 1))
            else:
                expanded.append(int(item))
        self.parse_ports(expanded)
        return candidate

    def validate_network_targets(self, targets: str) -> str:
        """Validate comma/space separated IP addresses, CIDRs, and IP ranges."""
        candidate = targets.strip()
        if not candidate:
            raise ValueError("Network targets are required")

        if any(ch in candidate for ch in ";|&`$"):
            raise ValueError("Invalid characters in network targets")
        raw_targets = [
            item for chunk in candidate.split(",") for item in chunk.split() if item
        ]
        if not raw_targets:
            raise ValueError("Network targets are required")
        total_addresses = 0
        for raw in raw_targets:
            if "-" in raw and "/" not in raw:
                start_raw, end_raw = raw.split("-", 1)
                start = ipaddress.ip_address(start_raw)
                # Support abbreviated IPv4 final-octet ranges.
                if "." not in end_raw and isinstance(start, ipaddress.IPv4Address):
                    end_raw = ".".join(start_raw.split(".")[:-1] + [end_raw])
                end = ipaddress.ip_address(end_raw)
                if start.version != end.version or int(end) < int(start):
                    raise ValueError(f"Invalid address range: {raw}")
                total_addresses += int(end) - int(start) + 1
                self._validate_ip(start)
                self._validate_ip(end)
                if self.config.allowed_cidrs and not any(
                    start in cidr and end in cidr
                    for cidr in self.config.allowed_cidrs
                ):
                    raise ValueError(f"Address range crosses allowed scope: {raw}")
                continue
            network = ipaddress.ip_network(raw, strict=False)
            total_addresses += network.num_addresses
            self._validate_ip(network.network_address)
            self._validate_ip(network.broadcast_address)
            if self.config.allowed_cidrs and not any(
                _network_is_within(network, cidr)
                for cidr in self.config.allowed_cidrs
            ):
                raise ValueError(f"Network not in allowed CIDRs: {raw}")
        if total_addresses > self.config.max_target_addresses:
            raise ValueError(
                f"Target set is too large: {total_addresses} > "
                f"{self.config.max_target_addresses}"
            )
        return candidate

    def validate_masscan_targets(self, targets: str) -> str:
        """Backward-compatible alias for structured masscan wrappers."""
        return self.validate_network_targets(targets)

    def validate_path(self, path: str) -> Path:
        candidate = Path(path).expanduser().resolve()
        if any(
            candidate == forbidden or candidate.is_relative_to(forbidden)
            for forbidden in self.config.forbidden_paths
        ):
            raise ValueError(f"Filesystem policy violation: forbidden path {candidate}")
        if self.config.allowed_paths and not any(
            candidate == allowed or candidate.is_relative_to(allowed)
            for allowed in self.config.allowed_paths
        ):
            raise ValueError(f"Filesystem policy violation: {candidate} is outside allowed paths")
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

    def _validate_ip(self, ip_obj: IPAddress) -> None:
        if self.config.allow_private_only and not ip_obj.is_private:
            raise ValueError("Target policy violation: only private addresses are allowed")
        if self.config.allowed_cidrs and not any(
            ip_obj in cidr
            for cidr in self.config.allowed_cidrs
            if ip_obj.version == cidr.version
        ):
            raise ValueError(f"Target policy violation: {ip_obj} not in allowed CIDRs")

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
