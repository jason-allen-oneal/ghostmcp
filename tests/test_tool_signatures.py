import inspect
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


class ToolSignatureTests(unittest.TestCase):
    def test_dns_lookup_signature_not_args_kwargs(self) -> None:
        sig = inspect.signature(server.dns_lookup_tool)
        self.assertIn("domain", sig.parameters)
        self.assertNotIn("args", sig.parameters)
        self.assertNotIn("kwargs", sig.parameters)

    def test_runtime_probe_signature_not_args_kwargs(self) -> None:
        sig = inspect.signature(server.runtime_probe_tool)
        self.assertIn("engagement_id", sig.parameters)
        self.assertNotIn("args", sig.parameters)
        self.assertNotIn("kwargs", sig.parameters)


if __name__ == "__main__":
    unittest.main()
