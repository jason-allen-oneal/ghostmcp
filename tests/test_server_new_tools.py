import sys
import types
import unittest
from unittest.mock import patch

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

        def run(self) -> None:
            return None

    fastmcp_module.FastMCP = _FakeFastMCP
    sys.modules["mcp"] = mcp_module
    sys.modules["mcp.server"] = mcp_server_module
    sys.modules["mcp.server.fastmcp"] = fastmcp_module

from ghostmcp.security import ValidationResult
from ghostmcp.server import (
    amass_passive_tool,
    common_web_paths_tool,
    gobuster_dir_tool,
    ioc_extract_tool,
    nikto_tool,
    nmap_service_scan_tool,
    security_txt_tool,
    sslscan_tool,
    subdomain_candidates_tool,
    tls_certificate_expiry_tool,
    toolchain_status_tool,
    url_risk_score_tool,
    wafw00f_tool,
    whatweb_tool,
)


class NewServerToolsTests(unittest.TestCase):
    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.fetch_security_txt")
    @patch("ghostmcp.server.policy.validate_domain", return_value="example.com")
    def test_security_txt_tool(self, _validate_domain, mock_fetch, _allow) -> None:
        mock_fetch.return_value = {
            "domain": "example.com",
            "url": "https://example.com/.well-known/security.txt",
            "content_type": "text/plain",
            "found": True,
            "raw": "Contact: mailto:security@example.com",
            "fields": {"contact": ["mailto:security@example.com"]},
        }

        result = security_txt_tool("Example.COM")

        self.assertEqual(result["domain"], "example.com")
        self.assertIn("contact", result["fields"])

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    def test_ioc_extract_tool(self, _allow) -> None:
        payload = (
            "URL https://evil.example/path?a=1 and IP 1.2.3.4 with hash "
            "d41d8cd98f00b204e9800998ecf8427e"
        )

        result = ioc_extract_tool(payload)

        self.assertEqual(result["urls"], ["https://evil.example/path?a=1"])
        self.assertEqual(result["ips"], ["1.2.3.4"])
        self.assertEqual(result["hashes"]["md5"], ["d41d8cd98f00b204e9800998ecf8427e"])

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    def test_url_risk_score_tool(self, _allow) -> None:
        result = url_risk_score_tool("http://127.0.0.1:8080/login?x=1&y=2")

        self.assertGreaterEqual(result["score"], 40)
        self.assertIn("plain_http", result["reasons"])
        self.assertIn("ip_literal_host", result["reasons"])

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.tls_certificate_expiry")
    @patch(
        "ghostmcp.server.policy.validate_target",
        return_value=ValidationResult(host="10.0.0.10", ips=["10.0.0.10"]),
    )
    def test_tls_certificate_expiry_tool(
        self, _validate_target, mock_expiry, _allow
    ) -> None:
        mock_expiry.return_value = {
            "host": "10.0.0.10",
            "port": 443,
            "expires_at": "2030-01-01T00:00:00+00:00",
            "days_remaining": 1000,
            "expired": False,
        }

        result = tls_certificate_expiry_tool("internal.example", 443)

        self.assertEqual(result["host"], "10.0.0.10")
        self.assertFalse(result["expired"])

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.policy.validate_domain", return_value="example.com")
    def test_subdomain_candidates_tool(self, _validate_domain, _allow) -> None:
        result = subdomain_candidates_tool("example.com", words=["api", "admin"])
        self.assertEqual(result["domain"], "example.com")
        self.assertIn("api.example.com", result["candidates"])
        self.assertIn("admin.example.com", result["candidates"])

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    def test_common_web_paths_tool(self, _allow) -> None:
        result = common_web_paths_tool("https://app.example.com", profile="light")
        self.assertEqual(result["profile"], "light")
        self.assertIn("https://app.example.com/robots.txt", result["urls"])

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    def test_engagement_id_required_when_enabled(self, _allow) -> None:
        cfg_stub = types.SimpleNamespace(
            require_engagement_context=True,
            max_tool_level="intrusive",
        )
        with patch("ghostmcp.server.cfg", cfg_stub):
            with self.assertRaises(ValueError):
                ioc_extract_tool("abc")

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.nmap_service_scan")
    @patch(
        "ghostmcp.server.policy.validate_target",
        return_value=ValidationResult(host="10.0.0.8", ips=["10.0.0.8"]),
    )
    def test_nmap_service_scan_tool(
        self, _validate_target, mock_nmap, _allow
    ) -> None:
        mock_nmap.return_value = {
            "tool": "nmap",
            "command": ["nmap", "-Pn", "-sV", "--top-ports", "100", "10.0.0.8"],
            "exit_code": 0,
            "duration_ms": 1234,
            "stdout": "open ports",
            "stderr": "",
            "host": "10.0.0.8",
        }
        result = nmap_service_scan_tool("internal.example", top_ports=100)
        self.assertEqual(result["tool"], "nmap")
        self.assertEqual(result["host"], "10.0.0.8")

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.whatweb_scan")
    def test_whatweb_tool(self, mock_whatweb, _allow) -> None:
        mock_whatweb.return_value = {
            "tool": "whatweb",
            "command": ["whatweb", "--color=never", "https://app.example.com"],
            "exit_code": 0,
            "duration_ms": 500,
            "stdout": "Apache",
            "stderr": "",
            "url": "https://app.example.com",
        }
        result = whatweb_tool("https://app.example.com")
        self.assertEqual(result["tool"], "whatweb")
        self.assertEqual(result["url"], "https://app.example.com")

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.nikto_scan")
    def test_nikto_tool(self, mock_nikto, _allow) -> None:
        mock_nikto.return_value = {
            "tool": "nikto",
            "command": ["nikto", "-host", "https://app.example.com", "-Format", "txt"],
            "exit_code": 0,
            "duration_ms": 1600,
            "stdout": "Nikto findings",
            "stderr": "",
            "url": "https://app.example.com",
        }
        result = nikto_tool("https://app.example.com")
        self.assertEqual(result["tool"], "nikto")
        self.assertEqual(result["url"], "https://app.example.com")

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.amass_passive_enum")
    @patch("ghostmcp.server.policy.validate_domain", return_value="example.com")
    def test_amass_passive_tool(
        self, _validate_domain, mock_amass, _allow
    ) -> None:
        mock_amass.return_value = {
            "tool": "amass",
            "command": ["amass", "enum", "-passive", "-d", "example.com"],
            "exit_code": 0,
            "duration_ms": 2100,
            "stdout": "api.example.com",
            "stderr": "",
            "domain": "example.com",
        }
        result = amass_passive_tool("example.com")
        self.assertEqual(result["tool"], "amass")
        self.assertEqual(result["domain"], "example.com")

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.gobuster_dir_scan")
    def test_gobuster_dir_tool(self, mock_gobuster, _allow) -> None:
        mock_gobuster.return_value = {
            "tool": "gobuster",
            "command": ["gobuster", "dir"],
            "exit_code": 0,
            "duration_ms": 3200,
            "stdout": "/admin (Status: 200)",
            "stderr": "",
            "url": "https://app.example.com",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
        }
        result = gobuster_dir_tool("https://app.example.com")
        self.assertEqual(result["tool"], "gobuster")
        self.assertEqual(result["url"], "https://app.example.com")

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.sslscan_target")
    @patch(
        "ghostmcp.server.policy.validate_target",
        return_value=ValidationResult(host="10.0.0.9", ips=["10.0.0.9"]),
    )
    def test_sslscan_tool(self, _validate_target, mock_sslscan, _allow) -> None:
        mock_sslscan.return_value = {
            "tool": "sslscan",
            "command": ["sslscan", "10.0.0.9:443"],
            "exit_code": 0,
            "duration_ms": 1400,
            "stdout": "TLSv1.2 enabled",
            "stderr": "",
            "host": "10.0.0.9",
            "port": 443,
        }
        result = sslscan_tool("internal.example", 443)
        self.assertEqual(result["tool"], "sslscan")
        self.assertEqual(result["host"], "10.0.0.9")

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    @patch("ghostmcp.server.wafw00f_scan")
    def test_wafw00f_tool(self, mock_wafw00f, _allow) -> None:
        mock_wafw00f.return_value = {
            "tool": "wafw00f",
            "command": ["wafw00f", "https://app.example.com"],
            "exit_code": 0,
            "duration_ms": 650,
            "stdout": "No WAF detected",
            "stderr": "",
            "url": "https://app.example.com",
        }
        result = wafw00f_tool("https://app.example.com")
        self.assertEqual(result["tool"], "wafw00f")
        self.assertEqual(result["url"], "https://app.example.com")

    @patch("ghostmcp.server.rate_limiter.allow", return_value=True)
    def test_toolchain_status_tool(self, _allow) -> None:
        snapshot_stub = {
            "nmap": {"installed": True, "path": "/usr/bin/nmap"},
            "nikto": {"installed": False, "path": None},
        }
        binary_tools_stub = {
            "nmap_service_scan_tool": "nmap",
            "nikto_tool": "nikto",
            "nmap_raw_tool": "nmap",
        }
        enabled_stub = ["nmap_service_scan_tool", "nmap_raw_tool"]
        with patch("ghostmcp.server.KALI_TOOLCHAIN_SNAPSHOT", snapshot_stub):
            with patch("ghostmcp.server.BINARY_MCP_TOOL_BINARIES", binary_tools_stub):
                with patch("ghostmcp.server.ENABLED_BINARY_MCP_TOOLS", enabled_stub):
                    result = toolchain_status_tool()
        self.assertEqual(result["installed_count"], 1)
        self.assertEqual(result["missing_count"], 1)
        self.assertIn("nmap_service_scan_tool", result["enabled_binary_mcp_tools"])
        self.assertIn("nmap_raw_tool", result["enabled_binary_mcp_tools"])


if __name__ == "__main__":
    unittest.main()
