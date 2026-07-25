"""GhostMCP CLI entry points."""

import ipaddress
import os
import sys

from . import __version__


def main() -> None:
    """Main CLI entry point."""
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command in {"--version", "version"}:
        print(__version__)
    elif command == "--healthcheck":
        # Importing the server exercises configuration validation, policy
        # initialization, and tool registration without starting a transport.
        os.environ["GHOSTMCP_LOG_LEVEL"] = "ERROR"
        from . import server  # noqa: F401

        server._validate_runtime_security()
        server._validate_transport_auth_configuration()
        print("ok")
    elif command == "dashboard":
        run_dashboard()
    else:
        from .server import main as server_main

        server_main()


def run_dashboard() -> None:
    """Run the GhostMCP web dashboard."""
    import uvicorn

    from .dashboard import app

    host = os.getenv("GHOSTMCP_DASHBOARD_HOST", "127.0.0.1")
    port = int(os.getenv("GHOSTMCP_DASHBOARD_PORT", "8080"))
    password = os.getenv("GHOSTMCP_DASHBOARD_AUTH_PASSWORD", "")
    token = os.getenv("GHOSTMCP_DASHBOARD_AUTH_TOKEN", "")
    if not password and not token:
        raise RuntimeError(
            "Dashboard authentication is required. Configure "
            "GHOSTMCP_DASHBOARD_AUTH_PASSWORD or GHOSTMCP_DASHBOARD_AUTH_TOKEN."
        )
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host.lower() == "localhost"
    trusted_tls_proxy = os.getenv(
        "GHOSTMCP_DASHBOARD_TRUSTED_TLS_PROXY",
        "false",
    ).lower() in {"1", "true", "yes", "on"}
    if not is_loopback and not trusted_tls_proxy:
        raise RuntimeError(
            "Non-loopback dashboard binding requires a trusted TLS reverse proxy"
        )
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
