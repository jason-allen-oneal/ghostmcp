import socket
import unittest
from unittest.mock import patch

from ghostmcp.config import ServerConfig
from ghostmcp.security import SecurityPolicy


class SecurityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = SecurityPolicy(ServerConfig())

    def test_parse_ports_rejects_blocked_port(self) -> None:
        with self.assertRaises(ValueError):
            self.policy.parse_ports([80, 22])

    def test_parse_ports_deduplicates(self) -> None:
        self.assertEqual(self.policy.parse_ports([443, 80, 443]), [80, 443])

    @patch("socket.getaddrinfo")
    def test_validate_target_private_only(self, mock_getaddrinfo) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 0))
        ]
        res = self.policy.validate_target("internal.local")
        self.assertEqual(res.ips, ["10.0.0.1"])

    @patch("socket.getaddrinfo")
    def test_validate_target_rejects_public_ip(self, mock_getaddrinfo) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 0))
        ]
        with self.assertRaises(ValueError):
            self.policy.validate_target("google-public-dns-a.google.com")

    def test_validate_domain_respects_allowed_domains(self) -> None:
        policy = SecurityPolicy(ServerConfig(allowed_domains=("example.com",)))
        self.assertEqual(policy.validate_domain("api.example.com"), "api.example.com")
        with self.assertRaises(ValueError):
            policy.validate_domain("evil.com")


if __name__ == "__main__":
    unittest.main()
