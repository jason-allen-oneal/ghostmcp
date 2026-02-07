import os
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

import ghostmcp.server as server


class ServerControlTests(unittest.TestCase):
    def test_validate_raw_args_blocks_shell_tokens(self) -> None:
        with self.assertRaises(ValueError):
            server._validate_raw_tool_args("nmap", ["-sV", "$(id)"])

    def test_validate_raw_args_accepts_safe_flags(self) -> None:
        args = server._validate_raw_tool_args("nmap", ["-sV", "-Pn"])
        self.assertEqual(args, ["-sV", "-Pn"])

    def test_token_auth_denies_invalid_token(self) -> None:
        with patch("ghostmcp.server.TRANSPORT_MODE", "remote_gateway"):
            with patch("ghostmcp.server.AUTH_MODE", "token"):
                with patch("ghostmcp.server.AUTH_TOKEN", "secret"):
                    with self.assertRaises(PermissionError):
                        server._authorize(
                            "x",
                            "passive",
                            engagement_id="eng-1",
                            engagement_mode="passive",
                            auth_token="wrong",
                        )


if __name__ == "__main__":
    unittest.main()
