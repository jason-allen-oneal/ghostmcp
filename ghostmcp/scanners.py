from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess  # nosec B404
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import UTC, datetime


@dataclass
class PortScanResult:
    port: int
    state: str
    latency_ms: int


class ScannerError(RuntimeError):
    pass


class ScannerTimeoutError(ScannerError):
    pass


_ACTIVE_PROCS: set[subprocess.Popen] = set()
_ACTIVE_PROCS_LOCK = threading.Lock()


def terminate_active_processes() -> int:
    with _ACTIVE_PROCS_LOCK:
        procs = list(_ACTIVE_PROCS)
    terminated = 0
    for proc in procs:
        try:
            os.killpg(proc.pid, 15)
        except ProcessLookupError:
            terminated += 0
        except OSError:
            terminated += 0
        else:
            terminated += 1
    return terminated


def _run_external_tool(
    command: list[str],
    timeout_s: float = 120.0,
    max_stdout_bytes: int = 20000,
    max_stderr_bytes: int = 8000,
) -> dict:
    binary = command[0]
    path = shutil.which(binary)
    if not path:
        raise ScannerError(f"Required tool is not installed: {binary}")

    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        proc = subprocess.Popen(  # nosec B603
            command,
            stdout=stdout_file,
            stderr=stderr_file,
            text=False,
            start_new_session=True,
        )
        with _ACTIVE_PROCS_LOCK:
            _ACTIVE_PROCS.add(proc)
        try:
            try:
                proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired as exc:
                try:
                    os.killpg(proc.pid, 15)
                    proc.wait(timeout=2)
                except OSError:
                    try:
                        os.killpg(proc.pid, 9)
                    except OSError:
                        _ = False
                raise ScannerTimeoutError(
                    f"External tool timed out after {timeout_s}s: {binary}"
                ) from exc

            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(max_stdout_bytes).decode("utf-8", errors="replace")
            stderr = stderr_file.read(max_stderr_bytes).decode("utf-8", errors="replace")
            stdout_file.seek(0, os.SEEK_END)
            stderr_file.seek(0, os.SEEK_END)
            stdout_size = stdout_file.tell()
            stderr_size = stderr_file.tell()
            elapsed = int((time.monotonic() - started) * 1000)
            return {
                "tool": binary,
                "command": command,
                "exit_code": proc.returncode,
                "duration_ms": elapsed,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": (
                    stdout_size > max_stdout_bytes
                    or stderr_size > max_stderr_bytes
                ),
            }
        finally:
            with _ACTIVE_PROCS_LOCK:
                _ACTIVE_PROCS.discard(proc)


def run_external_binary(
    binary: str,
    args: list[str] | None = None,
    timeout_s: float = 120.0,
    max_stdout_bytes: int = 20000,
    max_stderr_bytes: int = 8000,
) -> dict:
    command = [binary]
    if args:
        command.extend(args)
    return _run_external_tool(
        command,
        timeout_s=timeout_s,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
    )


def _with_retry(fn, retries: int = 1, backoff_s: float = 0.5):
    attempts = retries + 1
    last_exc = None
    for idx in range(attempts):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if idx >= attempts - 1:
                break
            time.sleep(backoff_s * (idx + 1))
    raise last_exc  # type: ignore[misc]


def dns_lookup(domain: str, record_type: str = "A") -> list[str]:
    rtype = record_type.upper().strip()
    if rtype != "A":
        raise ValueError("Only A records are currently supported")

    _, _, ips = socket.gethostbyname_ex(domain)
    return sorted(set(ips))


def reverse_dns(ip: str) -> str:
    host, _, _ = socket.gethostbyaddr(ip)
    return host


def whois_query(target: str, timeout_s: float = 4.0) -> str:
    server = "whois.iana.org"
    query = f"{target}\r\n".encode()

    def _query() -> str:
        with socket.create_connection((server, 43), timeout=timeout_s) as sock:
            sock.sendall(query)
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        payload = b"".join(chunks).decode("utf-8", errors="replace")
        return payload[:12000]

    return _with_retry(_query, retries=1, backoff_s=0.25)


def http_probe(url: str, user_agent: str, timeout_s: float = 4.0) -> dict:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https")
    if not parsed.netloc:
        raise ValueError("URL host is required")

    req = urllib.request.Request(
        url=url,
        method="GET",
        headers={"User-Agent": user_agent, "Accept": "*/*"},
    )
    started = time.monotonic()
    def _probe() -> dict:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
            elapsed = int((time.monotonic() - started) * 1000)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "url": url,
                "status": resp.status,
                "reason": resp.reason,
                "latency_ms": elapsed,
                "server": headers.get("server"),
                "content_type": headers.get("content-type"),
                "security_headers": {
                    "strict_transport_security": headers.get(
                        "strict-transport-security"
                    ),
                    "content_security_policy": headers.get(
                        "content-security-policy"
                    ),
                    "x_frame_options": headers.get("x-frame-options"),
                    "x_content_type_options": headers.get("x-content-type-options"),
                },
            }

    try:
        return _with_retry(_probe, retries=1, backoff_s=0.25)
    except urllib.error.URLError as exc:
        raise ScannerError(str(exc)) from exc


def tls_certificate(host: str, port: int = 443, timeout_s: float = 4.0) -> dict:
    ctx = ssl.create_default_context()
    # Ensure only modern TLS versions are used (prefer TLS 1.2+).
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        # Fallback for older Python/OpenSSL: disable TLSv1 and TLSv1.1 explicitly if available.
        if hasattr(ssl, "OP_NO_TLSv1"):
            ctx.options |= ssl.OP_NO_TLSv1
        if hasattr(ssl, "OP_NO_TLSv1_1"):
            ctx.options |= ssl.OP_NO_TLSv1_1
    with socket.create_connection((host, port), timeout=timeout_s) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()

    if cert is None:
        raise ScannerError("Failed to retrieve certificate")
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")

    return {
        "host": host,
        "port": port,
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "serial_number": cert.get("serialNumber"),
        "version": cert.get("version"),
        "not_before": not_before,
        "not_after": not_after,
        "subject_alt_names": cert.get("subjectAltName"),
    }


def tls_certificate_expiry(host: str, port: int = 443, timeout_s: float = 4.0) -> dict:
    cert = tls_certificate(host=host, port=port, timeout_s=timeout_s)
    not_after = cert.get("not_after")
    if not not_after:
        raise ScannerError("Certificate notAfter field is unavailable")
    try:
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=UTC
        )
    except ValueError as exc:
        raise ScannerError("Unable to parse certificate expiration timestamp") from exc

    now = datetime.now(UTC)
    seconds_remaining = (expires_at - now).total_seconds()
    days_remaining = int(seconds_remaining // 86400)
    return {
        "host": host,
        "port": port,
        "expires_at": expires_at.isoformat(),
        "days_remaining": days_remaining,
        "expired": seconds_remaining <= 0,
    }


def fetch_security_txt(domain: str, user_agent: str, timeout_s: float = 4.0) -> dict:
    url = f"https://{domain}/.well-known/security.txt"
    req = urllib.request.Request(
        url=url,
        method="GET",
        headers={"User-Agent": user_agent, "Accept": "text/plain"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
            body = resp.read().decode("utf-8", errors="replace")
            content_type = resp.headers.get("content-type")
            lines = body.splitlines()
    except urllib.error.URLError as exc:
        raise ScannerError(str(exc)) from exc

    parsed: dict[str, list[str]] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        parsed.setdefault(key, []).append(value)

    return {
        "domain": domain,
        "url": url,
        "content_type": content_type,
        "found": bool(lines),
        "raw": body[:12000],
        "fields": parsed,
    }


URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b"
)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")


def extract_iocs(text: str) -> dict:
    urls = sorted(set(URL_RE.findall(text)))

    ips = []
    for candidate in IP_RE.findall(text):
        try:
            ipaddress.ip_address(candidate)
            ips.append(candidate)
        except ValueError:
            continue

    domains = sorted(set(DOMAIN_RE.findall(text)))
    hashes = {
        "sha256": sorted(set(SHA256_RE.findall(text))),
        "sha1": sorted(set(SHA1_RE.findall(text))),
        "md5": sorted(set(MD5_RE.findall(text))),
    }
    return {
        "urls": urls,
        "ips": sorted(set(ips)),
        "domains": domains,
        "hashes": hashes,
    }


def url_risk_score(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must include http(s) scheme and host")

    score = 0
    reasons = []
    host = parsed.hostname or ""

    if parsed.scheme == "http":
        score += 15
        reasons.append("plain_http")
    if len(url) > 120:
        score += 10
        reasons.append("long_url")
    if host.startswith("xn--") or ".xn--" in host:
        score += 20
        reasons.append("punycode_domain")
    if "@" in parsed.netloc:
        score += 25
        reasons.append("userinfo_in_url")
    if parsed.port and parsed.port not in {80, 443}:
        score += 10
        reasons.append("non_standard_port")
    if parsed.query.count("&") >= 6:
        score += 5
        reasons.append("many_query_params")

    host_parts = [p for p in host.split(".") if p]
    if len(host_parts) >= 5:
        score += 10
        reasons.append("many_subdomains")

    try:
        ipaddress.ip_address(host)
        score += 25
        reasons.append("ip_literal_host")
    except ValueError:
        pass

    score = min(score, 100)
    if score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    return {"url": url, "score": score, "severity": severity, "reasons": reasons}


def generate_subdomain_candidates(
    domain: str,
    words: list[str] | None = None,
    max_items: int = 200,
) -> list[str]:
    seed_words = words or [
        "www",
        "api",
        "app",
        "dev",
        "staging",
        "admin",
        "portal",
        "vpn",
        "cdn",
        "mail",
    ]
    cleaned = []
    for word in seed_words:
        token = word.strip().lower()
        if token and token.replace("-", "").isalnum():
            cleaned.append(token)

    deduped = sorted(set(cleaned))[:max_items]
    return [f"{label}.{domain}" for label in deduped]


def generate_common_web_paths(
    base_url: str,
    profile: str = "light",
) -> list[str]:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Base URL must include http(s) scheme and host")
    root = f"{parsed.scheme}://{parsed.netloc}"

    light = [
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/login",
        "/admin",
    ]
    standard = light + [
        "/api",
        "/api/v1",
        "/graphql",
        "/dashboard",
        "/health",
        "/status",
        "/.git/config",
        "/backup.zip",
    ]
    paths = standard if profile == "standard" else light
    return [f"{root}{path}" for path in paths]


def nmap_service_scan(
    host: str,
    ports: list[int] | None = None,
    top_ports: int = 100,
    timeout_s: float = 120.0,
) -> dict:
    command = ["nmap", "-Pn", "-sV"]
    if ports:
        command.extend(["-p", ",".join(str(p) for p in ports)])
    else:
        command.extend(["--top-ports", str(top_ports)])
    command.append(host)
    result = _run_external_tool(command, timeout_s=timeout_s)
    result["host"] = host
    return result


def whatweb_scan(url: str, timeout_s: float = 90.0) -> dict:
    command = ["whatweb", "--color=never", url]
    result = _run_external_tool(command, timeout_s=timeout_s)
    result["url"] = url
    return result


def nikto_scan(url: str, timeout_s: float = 180.0) -> dict:
    command = ["nikto", "-host", url, "-Format", "txt"]
    result = _run_external_tool(command, timeout_s=timeout_s)
    result["url"] = url
    return result


def amass_passive_enum(domain: str, timeout_s: float = 240.0) -> dict:
    command = ["amass", "enum", "-passive", "-d", domain]
    result = _run_external_tool(command, timeout_s=timeout_s)
    result["domain"] = domain
    return result


def gobuster_dir_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    threads: int = 20,
    timeout_s: float = 300.0,
) -> dict:
    command = [
        "gobuster",
        "dir",
        "-u",
        url,
        "-w",
        wordlist,
        "-t",
        str(threads),
        "--no-error",
    ]
    result = _run_external_tool(command, timeout_s=timeout_s)
    result["url"] = url
    result["wordlist"] = wordlist
    return result


def sslscan_target(host: str, port: int = 443, timeout_s: float = 180.0) -> dict:
    command = ["sslscan", f"{host}:{port}"]
    result = _run_external_tool(command, timeout_s=timeout_s)
    result["host"] = host
    result["port"] = port
    return result


def wafw00f_scan(url: str, timeout_s: float = 90.0) -> dict:
    command = ["wafw00f", url]
    result = _run_external_tool(command, timeout_s=timeout_s)
    result["url"] = url
    return result


def port_scan(
    host: str,
    ports: list[int],
    connect_timeout_ms: int,
    max_workers: int,
) -> dict:
    workers = max(1, min(max_workers, len(ports)))

    def scan(port: int) -> PortScanResult:
        started = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(connect_timeout_ms / 1000)
            outcome = sock.connect_ex((host, port))
        latency = int((time.monotonic() - started) * 1000)
        state = "open" if outcome == 0 else "closed"
        return PortScanResult(port=port, state=state, latency_ms=latency)

    results: list[PortScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(scan, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda item: item.port)
    now = datetime.now(UTC).isoformat()
    return {
        "host": host,
        "scanned_at": now,
        "summary": {
            "total": len(results),
            "open": sum(1 for item in results if item.state == "open"),
            "closed": sum(1 for item in results if item.state == "closed"),
        },
        "results": [asdict(item) for item in results],
    }
