import ipaddress
import socket
import unittest
from unittest.mock import patch

from ghostmcp.config import ServerConfig
from ghostmcp.security import SecurityPolicy


class SecurityHardeningTests(unittest.TestCase):
    def test_masscan_rejects_public_cidr_under_private_policy(self) -> None:
        policy = SecurityPolicy(ServerConfig())
        with self.assertRaises(ValueError):
            policy.validate_masscan_targets("8.8.8.0/24")

    def test_masscan_accepts_bounded_private_cidr(self) -> None:
        policy = SecurityPolicy(ServerConfig())
        self.assertEqual(
            policy.validate_masscan_targets("10.10.0.0/24"),
            "10.10.0.0/24",
        )

    def test_masscan_rejects_target_set_above_cardinality_limit(self) -> None:
        policy = SecurityPolicy(ServerConfig(max_target_addresses=4096))
        with self.assertRaises(ValueError):
            policy.validate_masscan_targets("10.10.0.0/16")

    def test_masscan_range_must_fit_allowed_cidr(self) -> None:
        policy = SecurityPolicy(
            ServerConfig(allowed_cidrs=(ipaddress.ip_network("10.0.0.0/24"),))
        )
        with self.assertRaises(ValueError):
            policy.validate_masscan_targets("10.0.0.1-10.0.1.2")

    def test_literal_url_ip_is_scope_checked(self) -> None:
        policy = SecurityPolicy(ServerConfig())
        with self.assertRaises(ValueError):
            policy.validate_url("http://8.8.8.8/")

    @patch("socket.getaddrinfo")
    def test_domain_with_mixed_private_and_public_answers_is_rejected(
        self, mock_getaddrinfo
    ) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.2", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 0)),
        ]
        policy = SecurityPolicy(ServerConfig())
        with self.assertRaises(ValueError):
            policy.validate_domain("mixed.example")

    def test_url_rejects_embedded_credentials(self) -> None:
        policy = SecurityPolicy(ServerConfig(allow_private_only=False))
        with self.assertRaises(ValueError):
            policy.validate_url("https://user:pass@example.com/")


if __name__ == "__main__":
    unittest.main()
