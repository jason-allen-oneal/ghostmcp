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


class IntegrationRegistrationTests(unittest.TestCase):
    def test_enabled_binary_tools_have_installed_binaries(self) -> None:
        for tool_name in server.ENABLED_BINARY_MCP_TOOLS:
            binary = server.BINARY_MCP_TOOL_BINARIES[tool_name]
            self.assertTrue(server.KALI_TOOLCHAIN_SNAPSHOT[binary]["installed"])


if __name__ == "__main__":
    unittest.main()
