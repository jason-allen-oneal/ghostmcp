#!/usr/bin/env python3
"""Fail a release when required runtime files are absent or unsafe files leak."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

REQUIRED_SUFFIXES = {
    "ghostmcp/tool_policy.py",
    "ghostmcp/security.py",
    "ghostmcp/redaction.py",
    "ghostmcp/parsers/nmap.py",
    "ghostmcp/templates/base.html",
    "ghostmcp/static/style.css",
}
FORBIDDEN_SUFFIXES = {
    "credentials.json",
    "credentials.json.key",
    "ghostmcp.db",
}


def _validate_names(
    names: list[str],
    artifact: Path,
    *,
    required_suffixes: set[str] | None = None,
) -> None:
    required_suffixes = required_suffixes or REQUIRED_SUFFIXES
    normalized = [name.replace("\\", "/") for name in names]
    for name in normalized:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe archive path in {artifact.name}: {name}")
        if name.endswith(".pyc") or "__pycache__/" in name:
            raise SystemExit(f"bytecode leaked into {artifact.name}: {name}")
        if any(name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
            raise SystemExit(f"sensitive runtime file leaked into {artifact.name}: {name}")
    missing = [
        suffix
        for suffix in sorted(required_suffixes)
        if not any(name.endswith(suffix) for name in normalized)
    ]
    if missing:
        raise SystemExit(
            f"{artifact.name} is missing required runtime files: {', '.join(missing)}"
        )


def main() -> None:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("expected exactly one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as archive:
        _validate_names(archive.namelist(), wheels[0])
    with tarfile.open(sdists[0], "r:gz") as archive:
        _validate_names(
            archive.getnames(),
            sdists[0],
            required_suffixes=REQUIRED_SUFFIXES
            | {
                "CHANGELOG.md",
                "docs/SECURITY_MODEL.md",
                "scripts/verify_distribution.py",
            },
        )
    print("distribution contents verified")


if __name__ == "__main__":
    main()
