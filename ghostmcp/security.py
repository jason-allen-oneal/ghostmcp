from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from .config import ServerConfig

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


@dataclass
class ValidationResult:
    host: str
    ips: list[str]


class SecurityPolicy:
    def __init__(self, config: ServerConfig) -> None:
        self.config = config

    def validate_domain(self, domain: str) -> str:
        candidate = domain.strip().lower()
        if not candidate or len(candidate) > 253 or not DOMAIN_RE.match(candidate):
            raise ValueError("Invalid domain name")
        candidate = candidate.rstrip(".")
        self.enforce_domain_scope(candidate)
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
        candidate = host.strip()
        if not candidate:
            raise ValueError("Target host is required")

        ips = self._resolve_ips(candidate)
        if not ips:
            raise ValueError("Unable to resolve target host")

        for ip in ips:
            ip_obj = ipaddress.ip_address(ip)
            if self.config.allow_private_only and not ip_obj.is_private:
                raise ValueError(
                    "Target policy violation: only private addresses are allowed"
                )
            if self.config.allowed_cidrs and not any(
                ip_obj in cidr for cidr in self.config.allowed_cidrs
            ):
                raise ValueError(
                    f"Target policy violation: {ip} not in allowed CIDRs"
                )

        return ValidationResult(host=candidate, ips=ips)

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
