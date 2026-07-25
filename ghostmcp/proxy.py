"""Proxy/Tor support for GhostMCP."""

import os
import shutil
from typing import Literal

ProxyMode = Literal["none", "tor", "proxychains", "torsocks"]


class ProxyConfigurationError(RuntimeError):
    """Configured routing cannot be enforced safely."""


def get_proxy_mode() -> ProxyMode:
    """Get the configured proxy mode from environment."""
    mode = os.getenv("GHOSTMCP_PROXY_MODE", "none").strip().lower()
    valid_modes: tuple[ProxyMode, ...] = ("none", "tor", "proxychains", "torsocks")
    if mode not in valid_modes:
        raise ProxyConfigurationError(f"Unsupported proxy mode: {mode}")
    return mode


def get_tor_proxy() -> dict[str, str] | None:
    """Get Tor proxy configuration."""
    host = os.getenv("GHOSTMCP_TOR_HOST", "127.0.0.1")
    port = int(os.getenv("GHOSTMCP_TOR_PORT", "9050"))
    return {
        "http": f"socks5h://{host}:{port}",
        "https": f"socks5h://{host}:{port}",
    }


def build_proxychains_command(command: list[str]) -> list[str]:
    """Wrap a command with proxychains4."""
    if shutil.which("proxychains4"):
        return ["proxychains4", "-q"] + command
    if shutil.which("proxychains"):
        return ["proxychains", "-q"] + command
    raise ProxyConfigurationError(
        "proxychains mode requested but proxychains is not installed"
    )


def build_torsocks_command(command: list[str]) -> list[str]:
    """Wrap a command with torsocks."""
    if shutil.which("torsocks"):
        return ["torsocks"] + command
    raise ProxyConfigurationError("torsocks mode requested but torsocks is not installed")


def apply_proxy_mode(command: list[str]) -> list[str]:
    """Apply the configured proxy mode to a command."""
    mode = get_proxy_mode()

    if mode == "tor":
        if shutil.which("torsocks"):
            return build_torsocks_command(command)
        return build_proxychains_command(command)
    elif mode == "proxychains":
        return build_proxychains_command(command)
    elif mode == "torsocks":
        return build_torsocks_command(command)
    return command


def get_proxy_env() -> dict[str, str] | None:
    """Get proxy environment variables for subprocess."""
    mode = get_proxy_mode()

    if mode == "tor":
        proxy = get_tor_proxy()
        if proxy:
            return {
                "http_proxy": proxy["http"],
                "https_proxy": proxy["https"],
                "HTTP_PROXY": proxy["http"],
                "HTTPS_PROXY": proxy["https"],
                "ALL_PROXY": proxy["http"],
                "all_proxy": proxy["http"],
            }
    return None


def validate_proxy_configuration(*, required: bool = False) -> None:
    mode = get_proxy_mode()
    if required and mode == "none":
        raise ProxyConfigurationError(
            "Routed execution is required but GHOSTMCP_PROXY_MODE is none"
        )
    if mode == "proxychains":
        build_proxychains_command(["true"])
    elif mode == "torsocks":
        build_torsocks_command(["true"])
    elif mode == "tor" and not (
        shutil.which("torsocks")
        or shutil.which("proxychains4")
        or shutil.which("proxychains")
    ):
        raise ProxyConfigurationError("Tor mode requires torsocks or proxychains")
