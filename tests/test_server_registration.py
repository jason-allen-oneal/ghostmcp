import sys
import types
import unittest

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


class ServerRegistrationTests(unittest.TestCase):
    def test_enabled_binary_tools_subset_of_registered(self) -> None:
        for name in server.ENABLED_BINARY_MCP_TOOLS:
            self.assertIn(name, server.BINARY_MCP_TOOL_BINARIES)

    def test_missing_binary_not_enabled(self) -> None:
        fake_snapshot = {
            "nmap": {"installed": False, "path": None},
            "whatweb": {"installed": True, "path": "/usr/bin/whatweb"},
        }
        fake_tools = {
            "nmap_service_scan_tool": "nmap",
            "whatweb_tool": "whatweb",
        }
        enabled = sorted(
            name
            for name, binary in fake_tools.items()
            if fake_snapshot.get(binary, {}).get("installed")
        )
        self.assertEqual(enabled, ["whatweb_tool"])


if __name__ == "__main__":
    unittest.main()
