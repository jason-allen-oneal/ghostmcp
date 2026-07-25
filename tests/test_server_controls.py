import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from typing import get_args, get_type_hints
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
from ghostmcp.scanners import verify_audit_log_integrity


class ServerControlTests(unittest.TestCase):
    def test_manifest_contains_conservative_metadata_and_disabled_raw_tools(self) -> None:
        payload = server.tool_manifest_tool()
        tools = {entry["name"]: entry for entry in payload["tools"]}
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(tools["crackmapexec_tool"]["risk"], "intrusive")
        self.assertIn(
            "credential_access",
            tools["crackmapexec_tool"]["capabilities"],
        )
        self.assertFalse(tools["netexec_raw_tool"]["available"])

    def test_concurrent_audit_writes_preserve_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "audit.jsonl"
            context = {
                "engagement_id": "eng-1",
                "engagement_mode": "passive",
                "tool_level": "passive",
                "scope_digest": "a" * 64,
            }
            with (
                patch("ghostmcp.server.AUDIT_SINK_PATH", str(path)),
                patch("ghostmcp.server._last_audit_hash", "0" * 64),
                patch("ghostmcp.server._audit_sequence", 0),
            ):
                threads = [
                    threading.Thread(
                        target=server._audit_tool_call,
                        args=(f"tool-{index}", context),
                    )
                    for index in range(20)
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
            integrity = verify_audit_log_integrity(str(path))
            self.assertEqual(integrity["status"], "success")
            self.assertEqual(integrity["events_processed"], 20)

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

    def test_remote_transport_without_auth_is_rejected(self) -> None:
        with (
            patch("ghostmcp.server.TRANSPORT_MODE", "remote_gateway"),
            patch("ghostmcp.server.AUTH_MODE", "none"),
        ):
            with self.assertRaisesRegex(RuntimeError, "requires token"):
                server._validate_transport_auth_configuration()

    def test_intrusive_tool_requires_versioned_engagement_policy(self) -> None:
        with self.assertRaisesRegex(PermissionError, "engagement policy"):
            server.sqlmap_tool(
                "https://127.0.0.1/",
                engagement_mode="intrusive",
            )

    def test_authorize_accepts_default_engagement_mode_alias(self) -> None:
        with patch("ghostmcp.server.rate_limiter.allow", return_value=True):
            context = server._authorize(
                "runtime_probe_tool",
                "passive",
                engagement_id=None,
                engagement_mode="default",
            )
        self.assertEqual(context["engagement_mode"], "passive")
        self.assertEqual(context["tool_level"], "passive")

    def test_runtime_probe_accepts_default_engagement_mode_alias(self) -> None:
        with patch("ghostmcp.server.rate_limiter.allow", return_value=True):
            payload = server.runtime_probe_tool(engagement_mode="default")
        self.assertIn(payload["status"], {"ready", "stopping"})

    def test_runtime_probe_type_hints_advertise_default_engagement_mode_alias(self) -> None:
        engagement_mode_hint = get_type_hints(server.runtime_probe_tool)["engagement_mode"]
        self.assertEqual(
            get_args(engagement_mode_hint),
            ("default", "passive", "active", "intrusive"),
        )


class BearerMiddlewareTests(unittest.IsolatedAsyncioTestCase):
    async def test_bearer_middleware_rejects_missing_token(self) -> None:
        called = False

        async def app(_scope, _receive, _send):
            nonlocal called
            called = True

        messages = []

        async def send(message):
            messages.append(message)

        middleware = server._BearerAuthMiddleware(app, "expected")
        await middleware(
            {"type": "http", "headers": []},
            None,
            send,
        )
        self.assertFalse(called)
        self.assertEqual(messages[0]["status"], 401)

    async def test_bearer_middleware_sets_transport_context(self) -> None:
        authenticated = False

        async def app(_scope, _receive, send):
            nonlocal authenticated
            authenticated = server._transport_authenticated.get()
            await send({"type": "http.response.start", "status": 200, "headers": []})

        messages = []

        async def send(message):
            messages.append(message)

        middleware = server._BearerAuthMiddleware(app, "expected")
        await middleware(
            {
                "type": "http",
                "headers": [(b"authorization", b"Bearer expected")],
            },
            None,
            send,
        )
        self.assertTrue(authenticated)
        self.assertEqual(messages[0]["status"], 200)


if __name__ == "__main__":
    unittest.main()
