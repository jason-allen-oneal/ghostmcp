import ipaddress
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ghostmcp.config import ServerConfig
from ghostmcp.security import SecurityPolicy
from ghostmcp.tool_policy import (
    MANIFEST_SCHEMA_VERSION,
    ToolManifest,
    descriptor_for_raw,
    extract_raw_network_targets,
    validate_effective_arguments,
)


class ExecutionPolicyTests(unittest.TestCase):
    def test_manifest_is_versioned_and_describes_raw_capabilities(self) -> None:
        manifest = ToolManifest()
        manifest.register(
            descriptor_for_raw(
                "netexec_raw_tool",
                "netexec",
                available=False,
            )
        )
        payload = manifest.export(server_version="test")
        self.assertEqual(payload["schema_version"], MANIFEST_SCHEMA_VERSION)
        names = [entry["name"] for entry in payload["tools"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("netexec_raw_tool", names)
        netexec = next(
            entry for entry in payload["tools"]
            if entry["name"] == "netexec_raw_tool"
        )
        self.assertFalse(netexec["available"])

        descriptor = descriptor_for_raw(
            "impacket_psexec_raw_tool",
            "impacket-psexec",
            available=True,
        )
        self.assertEqual(descriptor.risk, "intrusive")
        self.assertIn("raw_execution", descriptor.capabilities)
        self.assertIn("remote_execution", descriptor.capabilities)
        self.assertTrue(descriptor.sensitive_output)

    def test_raw_argv_extracts_actual_destination(self) -> None:
        self.assertEqual(
            extract_raw_network_targets(
                "netexec",
                ["smb", "10.20.30.40"],
            ),
            [("network", "10.20.30.40")],
        )

    def test_raw_network_tool_without_target_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "recognizable explicit target"):
            extract_raw_network_targets("netexec", ["smb", "--shares"])

    def test_raw_argv_target_is_checked_against_cidr_policy(self) -> None:
        descriptor = descriptor_for_raw(
            "netexec_raw_tool",
            "netexec",
            available=True,
        )
        policy = SecurityPolicy(
            ServerConfig(
                allow_private_only=False,
                allowed_cidrs=(ipaddress.ip_network("10.0.0.0/24"),),
            ),
            credentials=object(),
        )
        with self.assertRaisesRegex(ValueError, "allowed CIDRs"):
            validate_effective_arguments(
                descriptor,
                {"args": ["smb", "10.0.1.8"]},
                policy,
            )

    def test_network_ranges_must_remain_inside_one_allowed_network(self) -> None:
        policy = SecurityPolicy(
            ServerConfig(
                allow_private_only=False,
                allowed_cidrs=(ipaddress.ip_network("10.0.0.0/24"),),
            ),
            credentials=object(),
        )
        self.assertEqual(
            policy.validate_network_targets("10.0.0.4-20"),
            "10.0.0.4-20",
        )
        with self.assertRaises(ValueError):
            policy.validate_network_targets("10.0.0.250-10.0.1.2")

    def test_network_target_cardinality_is_bounded(self) -> None:
        policy = SecurityPolicy(
            ServerConfig(
                allow_private_only=False,
                max_target_addresses=16,
            ),
            credentials=object(),
        )
        with self.assertRaisesRegex(ValueError, "Target set is too large"):
            policy.validate_network_targets("10.0.0.0/24")

    def test_filesystem_scope_rejects_sibling_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            allowed = base / "allowed"
            sibling = base / "sibling"
            allowed.mkdir()
            sibling.mkdir()
            policy = SecurityPolicy(
                ServerConfig(allowed_paths=(allowed.resolve(),)),
                credentials=object(),
            )
            self.assertEqual(policy.validate_path(str(allowed)), allowed.resolve())
            with self.assertRaisesRegex(ValueError, "outside allowed paths"):
                policy.validate_path(str(allowed / ".." / "sibling"))

    def test_domain_resolution_is_subject_to_address_policy(self) -> None:
        policy = SecurityPolicy(ServerConfig(), credentials=object())
        with patch.object(policy, "_resolve_ips", return_value=["8.8.8.8"]):
            with self.assertRaisesRegex(ValueError, "private addresses"):
                policy.validate_domain("example.com", resolve=True)

    def test_host_key_cannot_bypass_allowed_domain_policy(self) -> None:
        policy = SecurityPolicy(
            ServerConfig(
                allow_private_only=False,
                allowed_domains=("authorized.example",),
            ),
            credentials=object(),
        )
        with self.assertRaisesRegex(ValueError, "Domain policy violation"):
            policy.validate_target("outside.example")

    def test_engagement_policy_is_permission_checked_and_narrowing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_path = Path(temp_dir) / "policy.json"
            payload = {
                "schema_version": "1.0",
                "engagements": {
                    "eng-1": {
                        "allowed_cidrs": ["10.0.0.0/24"],
                        "max_tool_level": "active",
                        "allowed_capabilities": ["discovery"],
                        "expires_at": "2099-01-01T00:00:00Z",
                    }
                },
            }
            policy_path.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(policy_path, 0o600)
            base = SecurityPolicy(
                ServerConfig(
                    allow_private_only=False,
                    allowed_cidrs=(ipaddress.ip_network("10.0.0.0/8"),),
                    max_tool_level="intrusive",
                    engagement_policy_file=policy_path,
                ),
                credentials=object(),
            )
            scoped = base.for_engagement("eng-1")
            self.assertEqual(
                scoped.config.allowed_cidrs,
                (ipaddress.ip_network("10.0.0.0/24"),),
            )
            self.assertEqual(scoped.config.max_tool_level, "active")
            self.assertEqual(len(scoped.scope_digest or ""), 64)

            os.chmod(policy_path, 0o644)
            with self.assertRaisesRegex(PermissionError, "mode 0600"):
                base.for_engagement("eng-1")

    def test_sensitive_engagement_requires_approval_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_path = Path(temp_dir) / "policy.json"
            scope = {
                "expires_at": "2099-01-01T00:00:00Z",
                "max_tool_level": "intrusive",
                "allowed_capabilities": ["discovery", "raw_execution"],
                "allowed_cidrs": ["10.0.0.0/24"],
            }
            payload = {
                "schema_version": "1.0",
                "engagements": {"eng-1": scope},
            }
            policy_path.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(policy_path, 0o600)
            base = SecurityPolicy(
                ServerConfig(
                    allow_private_only=False,
                    engagement_policy_file=policy_path,
                ),
                credentials=object(),
            )
            with self.assertRaisesRegex(PermissionError, "authorization provenance"):
                base.for_engagement("eng-1")

            scope["authorization"] = {
                "approval_id": "approval-1",
                "approved_by": "operator-1",
                "approved_at": "2026-01-01T00:00:00Z",
                "reason": "Authorized validation",
            }
            policy_path.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(policy_path, 0o600)
            scoped = base.for_engagement("eng-1")
            self.assertEqual(scoped.approval_id, "approval-1")
            self.assertEqual(scoped.approved_by, "operator-1")


if __name__ == "__main__":
    unittest.main()
