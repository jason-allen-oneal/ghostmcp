import json
import os
import sys
import tempfile
import types
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from ghostmcp.config import ServerConfig
from ghostmcp.proxy import ProxyConfigurationError, apply_proxy_mode
from ghostmcp.security import SecurityPolicy
from ghostmcp.tool_policy import (
    descriptor_for_curated,
    descriptor_for_raw,
    enforce_capabilities,
    validate_effective_arguments,
)

os.environ.setdefault("GHOSTMCP_REQUIRE_ENGAGEMENT_CONTEXT", "false")

if "mcp.server.fastmcp" not in sys.modules:
    mcp_module = types.ModuleType("mcp")
    mcp_server_module = types.ModuleType("mcp.server")
    fastmcp_module = types.ModuleType("mcp.server.fastmcp")

    class _FakeFastMCP:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def tool(self):
            def decorator(fn):
                return fn

            return decorator

        def run(self, *_args, **_kwargs) -> None:
            return None

    fastmcp_module.FastMCP = _FakeFastMCP
    sys.modules["mcp"] = mcp_module
    sys.modules["mcp.server"] = mcp_server_module
    sys.modules["mcp.server.fastmcp"] = fastmcp_module

from ghostmcp.server import TOOL_MANIFEST


class ExecutionPolicyTests(unittest.TestCase):
    def _policy_file(self, engagement: dict) -> Path:
        directory = Path(tempfile.mkdtemp())
        path = directory / "engagement-policy.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "engagements": {"eng-1": engagement},
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        self.addCleanup(lambda: directory.rmdir())
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def test_empty_capability_set_denies_tools(self) -> None:
        descriptor = descriptor_for_curated("dns_lookup_tool", "passive")
        with self.assertRaises(PermissionError):
            enforce_capabilities(descriptor, ())

    def test_intrusive_policy_requires_target_scope(self) -> None:
        policy_file = self._policy_file(
            {
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "max_tool_level": "intrusive",
                "allowed_capabilities": ["discovery"],
                "authorization": {
                    "approval_id": "change-123",
                    "approved_by": "owner@example.test",
                    "approved_at": datetime.now(UTC).isoformat(),
                    "reason": "Authorized lab validation",
                },
            }
        )
        policy = SecurityPolicy(
            ServerConfig(engagement_policy_file=policy_file)
        )
        with self.assertRaises(PermissionError):
            policy.for_engagement("eng-1")

    def test_engagement_scope_is_narrowed_and_auditable(self) -> None:
        policy_file = self._policy_file(
            {
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "max_tool_level": "intrusive",
                "allowed_capabilities": ["discovery", "remote_execution"],
                "allowed_cidrs": ["10.20.30.0/24"],
                "authorization": {
                    "approval_id": "change-123",
                    "approved_by": "owner@example.test",
                    "approved_at": datetime.now(UTC).isoformat(),
                    "reason": "Authorized lab validation",
                },
            }
        )
        policy = SecurityPolicy(
            ServerConfig(
                allowed_cidrs=(),
                engagement_policy_file=policy_file,
                max_tool_level="intrusive",
            )
        ).for_engagement("eng-1")

        self.assertEqual(policy.approval_id, "change-123")
        self.assertIsNotNone(policy.scope_digest)
        self.assertEqual(
            tuple(str(item) for item in policy.config.allowed_cidrs),
            ("10.20.30.0/24",),
        )
        policy.validate_target("10.20.30.10")
        with self.assertRaises(ValueError):
            policy.validate_target("10.20.31.10")

    def test_expired_engagement_policy_is_denied(self) -> None:
        policy_file = self._policy_file(
            {
                "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
                "max_tool_level": "active",
                "allowed_capabilities": ["discovery"],
                "allowed_cidrs": ["10.20.30.0/24"],
            }
        )
        policy = SecurityPolicy(
            ServerConfig(engagement_policy_file=policy_file)
        )
        with self.assertRaises(PermissionError):
            policy.for_engagement("eng-1")

    @patch(
        "ghostmcp.security.SecurityPolicy._resolve_ips",
        return_value=["203.0.113.10"],
    )
    def test_domain_only_scope_does_not_authorize_literal_ips(
        self, _resolve
    ) -> None:
        policy = SecurityPolicy(
            ServerConfig(allow_private_only=False)
        ).narrow(
            {
                "max_tool_level": "active",
                "allowed_capabilities": ["discovery"],
                "allowed_domains": ["lab.example"],
            }
        )
        policy.validate_target("lab.example")
        with self.assertRaises(ValueError):
            policy.validate_target("203.0.113.10")

    def test_filesystem_tool_requires_allowed_path(self) -> None:
        descriptor = descriptor_for_curated("exiftool_tool", "passive")
        with tempfile.TemporaryDirectory() as allowed:
            target = Path(allowed) / "evidence.bin"
            target.touch()
            validate_effective_arguments(
                descriptor,
                {"file_path": str(target)},
                SecurityPolicy(ServerConfig(allowed_paths=(Path(allowed),))),
            )
            with self.assertRaises(ValueError):
                validate_effective_arguments(
                    descriptor,
                    {"file_path": "/etc/passwd"},
                    SecurityPolicy(ServerConfig(allowed_paths=(Path(allowed),))),
                )

    def test_raw_network_tool_requires_recognizable_target(self) -> None:
        descriptor = descriptor_for_raw(
            "nmap_raw_tool", "nmap", available=True
        )
        with self.assertRaises(ValueError):
            validate_effective_arguments(
                descriptor,
                {"args": ["-sV", "-Pn"]},
                SecurityPolicy(ServerConfig()),
            )

    @patch("ghostmcp.proxy.shutil.which", return_value=None)
    def test_proxy_mode_fails_closed_when_wrapper_missing(self, _which) -> None:
        with patch.dict(os.environ, {"GHOSTMCP_PROXY_MODE": "tor"}):
            with self.assertRaises(ProxyConfigurationError):
                apply_proxy_mode(["nmap", "10.0.0.1"])

    def test_high_impact_curated_tools_are_intrusive(self) -> None:
        for name in (
            "crackmapexec_tool",
            "rpcclient_tool",
            "smbclient_tool",
            "smbmap_tool",
            "sqlmap_tool",
        ):
            with self.subTest(tool=name):
                self.assertEqual(
                    TOOL_MANIFEST.get(name).risk,
                    "intrusive",
                )


if __name__ == "__main__":
    unittest.main()
