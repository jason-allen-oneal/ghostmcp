from __future__ import annotations

import subprocess
import sys

from ghostmcp import __version__


def test_version_command_exits_without_starting_server() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ghostmcp", "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.stdout.strip() == __version__
    assert result.stderr == ""


def test_healthcheck_validates_server_initialization() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ghostmcp", "--healthcheck"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.stdout.strip() == "ok"
    assert result.stderr == ""
