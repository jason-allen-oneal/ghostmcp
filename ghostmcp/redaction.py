"""Conservative redaction helpers for persisted or externally visible data."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+")
_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "auth",
    "auth_token",
    "authorization",
    "credential",
    "credentials",
    "password",
    "passwd",
    "secret",
    "token",
}


def redact_text(value: str) -> str:
    value = _SENSITIVE_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", value)
    return _BEARER_RE.sub("Bearer [REDACTED]", value)


def redact_url(value: str) -> str:
    if "://" not in value:
        return redact_text(value.rsplit("@", 1)[-1] if "@" in value else value)
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def redact_value(value: Any, *, key: str | None = None) -> Any:
    if key and key.lower().replace("-", "_") in _SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(item_key): redact_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value
