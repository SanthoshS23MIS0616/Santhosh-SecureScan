"""Core scanning engine for Santhosh SecureScan.

The module keeps scanning intentionally bounded: small port lists, short timeouts,
banner checks, HTTP header inspection, and a report-friendly findings model.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


COMMON_PORTS = {
    20: "FTP data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    2375: "Docker API",
    3000: "Node/Dev app",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask/Dev app",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP alternate",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

PORT_PROFILES = {
    "quick": [22, 80, 443, 8080, 8443, 3306, 5432, 6379],
    "web": [80, 443, 3000, 5000, 8000, 8080, 8443, 9000],
    "extended": [
        20,
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        139,
        143,
        389,
        443,
        445,
        465,
        587,
        993,
        995,
        1433,
        1521,
        2049,
        2375,
        3000,
        3306,
        3389,
        5000,
        5432,
        5601,
        5900,
        6379,
        8000,
        8080,
        8443,
        9200,
        11211,
        27017,
    ],
}

HTTP_PORTS = {80, 3000, 5000, 8000, 8080, 9000}
HTTPS_PORTS = {443, 8443}
RISKY_PORTS = {
    21: ("medium", "FTP is open", "FTP is commonly unencrypted. Prefer SFTP or disable it if unnecessary."),
    23: ("critical", "Telnet is open", "Telnet sends credentials in clear text. Disable it and use SSH."),
    445: ("high", "SMB is exposed", "SMB should not be publicly exposed. Restrict by firewall and VPN."),
    1433: ("high", "MSSQL is exposed", "Database ports should be private. Restrict access to trusted hosts."),
    2375: ("critical", "Docker API is exposed", "Unauthenticated Docker API exposure can lead to host compromise."),
    3306: ("high", "MySQL is exposed", "Database ports should be private. Bind to localhost or private networks."),
    3389: ("high", "RDP is exposed", "RDP exposure increases brute-force and exploitation risk. Use VPN and MFA."),
    5432: ("high", "PostgreSQL is exposed", "Database ports should be private. Restrict access by network policy."),
    5900: ("high", "VNC is exposed", "VNC should be protected behind VPN and strong authentication."),
    6379: ("high", "Redis is exposed", "Redis should not be internet-facing. Bind locally and require authentication."),
    9200: ("high", "Elasticsearch is exposed", "Elasticsearch should be private and authenticated."),
    11211: ("high", "Memcached is exposed", "Memcached should never be public. Restrict with firewall rules."),
    27017: ("high", "MongoDB is exposed", "MongoDB should be private and authenticated."),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": "Add a CSP to reduce XSS impact.",
    "X-Frame-Options": "Add clickjacking protection.",
    "X-Content-Type-Options": "Add nosniff to reduce MIME confusion.",
    "Referrer-Policy": "Limit referrer leakage.",
    "Strict-Transport-Security": "Enforce HTTPS with HSTS on HTTPS services.",
}

VERSION_RULES = {
    "apache": ((2, 4), "Apache versions below 2.4 should be upgraded."),
    "nginx": ((1, 20), "Older nginx branches should be reviewed and updated."),
    "php": ((8, 1), "PHP 7.x and older 8.0 stacks should be upgraded."),
    "openssh": ((8, 9), "Older OpenSSH versions should be reviewed for patch level."),
    "openssl": ((1, 1), "Very old OpenSSL branches should be replaced."),
}


@dataclass
class Finding:
    severity: str
    title: str
    evidence: str
    recommendation: str
    category: str

    def as_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "category": self.category,
        }


def normalize_target(raw_target: str) -> dict[str, Any]:
    value = (raw_target or "").strip()
    if not value:
        raise ValueError("Target is required.")

    if "://" not in value:
        value_for_parse = f"scan://{value}"
    else:
        value_for_parse = value

    parsed = urlparse(value_for_parse)
    host = parsed.hostname
    scheme = parsed.scheme if parsed.scheme != "scan" else ""
    port = parsed.port

    if not host:
        raise ValueError("Enter a valid hostname, IP address, or URL.")

    host = host.strip("[]").lower()
    if len(host) > 253:
        raise ValueError("Target hostname is too long.")

    return {
        "input": raw_target,
        "host": host,
        "scheme": scheme,
        "requested_port": port,
        "display": f"{scheme + '://' if scheme else ''}{host}{':' + str(port) if port else ''}",
    }


def parse_ports(profile: str = "quick", custom_ports: str = "") -> list[int]:
    selected = set(PORT_PROFILES.get(profile or "quick", PORT_PROFILES["quick"]))

    custom_ports = (custom_ports or "").strip()
    if custom_ports:
        selected.clear()
        for item in custom_ports.split(","):
            item = item.strip()
            if not item:
                continue
            if "-" in item:
                start_raw, end_raw = item.split("-", 1)
                start = int(start_raw.strip())
                end = int(end_raw.strip())
                if start > end:
                    start, end = end, start
                selected.update(range(start, end + 1))
            else:
                selected.add(int(item))

    clean = sorted(port for port in selected if 1 <= port <= 65535)
    if not clean:
        raise ValueError("No valid ports selected.")
    if len(clean) > 80:
        raise ValueError("Keep scans focused: maximum 80 ports per scan.")
    return clean


def resolve_host(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses[:6]


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "Unknown")


def _read_banner(sock: socket.socket, port: int, host: str) -> str:
    sock.settimeout(0.8)
    try:
        if port in HTTP_PORTS:
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SanthoshSecureScan/1.0\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode("ascii", "ignore"))
        elif port in {21, 22, 25, 110, 143}:
            pass
        else:
            sock.sendall(b"\r\n")
        data = sock.recv(512)
        return data.decode("utf-8", "replace").strip()
    except OSError:
        return ""


def scan_port(host: str, port: int, timeout: float = 0.8) -> dict[str, Any]:
    started = time.perf_counter()
    result = {
        "port": port,
        "service": service_name(port),
        "state": "closed",
        "latency_ms": None,
        "banner": "",
    }

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result["state"] = "open"
            result["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
            result["banner"] = _read_banner(sock, port, host)[:400]
    except OSError:
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)

    return result


def _socket_for_http(host: str, port: int, use_https: bool, timeout: float = 2.0) -> socket.socket:
    raw = socket.create_connection((host, port), timeout=timeout)
    if not use_https:
        return raw
    context = ssl.create_default_context()
    return context.wrap_socket(raw, server_hostname=host)


def fetch_http_headers(host: str, port: int, use_https: bool) -> dict[str, Any]:
    scheme = "https" if use_https else "http"
    check = {
        "url": f"{scheme}://{host}:{port}/",
        "port": port,
        "scheme": scheme,
        "status": None,
        "headers": {},
        "server": "",
        "powered_by": "",
        "tls": None,
        "error": "",
    }

    try:
        with _socket_for_http(host, port, use_https) as sock:
            tls_info = None
            if use_https and isinstance(sock, ssl.SSLSocket):
                cert = sock.getpeercert()
                tls_info = {
                    "version": sock.version(),
                    "cipher": sock.cipher()[0] if sock.cipher() else "",
                    "expires": cert.get("notAfter", "") if cert else "",
                }
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SanthoshSecureScan/1.0\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode("ascii", "ignore"))
            raw = b""
            while len(raw) < 8192:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                raw += chunk
                if b"\r\n\r\n" in raw:
                    break

        text = raw.decode("utf-8", "replace")
        lines = text.splitlines()
        if lines:
            status_match = re.search(r"\s(\d{3})\s", lines[0])
            if status_match:
                check["status"] = int(status_match.group(1))

        headers = {}
        for line in lines[1:]:
            if not line.strip():
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        check["headers"] = headers
        check["server"] = headers.get("Server", "")
        check["powered_by"] = headers.get("X-Powered-By", "")
        check["tls"] = tls_info
    except (OSError, ssl.SSLError) as exc:
        check["error"] = str(exc)[:180]

    return check


def extract_versions(text: str) -> list[dict[str, Any]]:
    found = []
    haystack = text or ""
    patterns = {
        "apache": r"apache/?\s*([0-9]+(?:\.[0-9]+){0,2})",
        "nginx": r"nginx/?\s*([0-9]+(?:\.[0-9]+){0,2})",
        "php": r"php/?\s*([0-9]+(?:\.[0-9]+){0,2})",
        "openssh": r"openssh[_/\s-]*([0-9]+(?:\.[0-9]+){0,2})",
        "openssl": r"openssl/?\s*([0-9]+(?:\.[0-9]+){0,2})",
    }
    for product, pattern in patterns.items():
        match = re.search(pattern, haystack, re.IGNORECASE)
        if not match:
            continue
        version_text = match.group(1)
        numbers = tuple(int(part) for part in version_text.split(".")[:2])
        baseline, message = VERSION_RULES[product]
        outdated = numbers < baseline
        found.append(
            {
                "product": {"php": "PHP", "openssh": "OpenSSH"}.get(product, product.title()),
                "version": version_text,
                "outdated_hint": outdated,
                "message": message if outdated else "Version banner found. Verify patch level with vendor advisories.",
            }
        )
    return found


def _severity_points(severity: str) -> int:
    return {
        "critical": 25,
        "high": 18,
        "medium": 10,
        "low": 5,
        "info": 1,
    }.get(severity, 1)


def build_findings(open_ports: list[dict[str, Any]], web_checks: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []

    for port_info in open_ports:
        port = port_info["port"]
        if port in RISKY_PORTS:
            severity, title, recommendation = RISKY_PORTS[port]
            findings.append(
                Finding(
                    severity=severity,
                    title=title,
                    evidence=f"Port {port}/{port_info['service']} responded as open.",
                    recommendation=recommendation,
                    category="Open port exposure",
                )
            )

        banner_versions = extract_versions(port_info.get("banner", ""))
        for item in banner_versions:
            severity = "medium" if item["outdated_hint"] else "info"
            findings.append(
                Finding(
                    severity=severity,
                    title=f"{item['product']} version banner detected",
                    evidence=f"{item['product']} {item['version']} observed on port {port}.",
                    recommendation=item["message"],
                    category="Software version",
                )
            )

    for check in web_checks:
        headers = check.get("headers", {})
        url = check.get("url", "")
        if check.get("scheme") == "http":
            findings.append(
                Finding(
                    severity="medium",
                    title="Plain HTTP service detected",
                    evidence=f"{url} responded without transport encryption.",
                    recommendation="Redirect HTTP to HTTPS and use secure cookies.",
                    category="Weak configuration",
                )
            )

        for header, recommendation in SECURITY_HEADERS.items():
            if header == "Strict-Transport-Security" and check.get("scheme") != "https":
                continue
            if header not in headers:
                severity = "medium" if header in {"Content-Security-Policy", "Strict-Transport-Security"} else "low"
                findings.append(
                    Finding(
                        severity=severity,
                        title=f"Missing {header}",
                        evidence=f"{header} was not present on {url}.",
                        recommendation=recommendation,
                        category="HTTP security headers",
                    )
                )

        header_blob = " ".join(
            value for key, value in headers.items() if key.lower() in {"server", "x-powered-by"}
        )
        for item in extract_versions(header_blob):
            severity = "medium" if item["outdated_hint"] else "info"
            findings.append(
                Finding(
                    severity=severity,
                    title=f"{item['product']} version exposed in HTTP headers",
                    evidence=f"{item['product']} {item['version']} observed on {url}.",
                    recommendation=item["message"],
                    category="Software version",
                )
            )

        tls = check.get("tls")
        if tls and tls.get("expires"):
            try:
                expiry = datetime.strptime(tls["expires"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 30:
                    findings.append(
                        Finding(
                            severity="medium",
                            title="TLS certificate expires soon",
                            evidence=f"Certificate for {url} expires in {days_left} days.",
                            recommendation="Renew the TLS certificate before expiration.",
                            category="TLS",
                        )
                    )
            except ValueError:
                pass

    unique = {}
    for finding in findings:
        key = (finding.severity, finding.title, finding.evidence)
        unique[key] = finding
    return list(unique.values())


def risk_score(findings: list[Finding]) -> int:
    penalty = sum(_severity_points(f.severity) for f in findings)
    return max(0, 100 - min(95, penalty))


def scan_target(raw_target: str, profile: str = "quick", custom_ports: str = "") -> dict[str, Any]:
    started = time.perf_counter()
    target = normalize_target(raw_target)
    ports = parse_ports(profile, custom_ports)
    if target.get("requested_port"):
        ports = sorted(set(ports + [int(target["requested_port"])]))

    addresses = resolve_host(target["host"])
    primary_ip = addresses[0] if addresses else target["host"]

    # A readable classification for reports. It does not block scanning because
    # students often test localhost and lab VMs.
    scope = "domain"
    try:
        ip_obj = ipaddress.ip_address(primary_ip)
        if ip_obj.is_loopback:
            scope = "loopback"
        elif ip_obj.is_private:
            scope = "private network"
        elif ip_obj.is_global:
            scope = "public address"
    except ValueError:
        pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(24, len(ports))) as executor:
        port_results = list(executor.map(lambda p: scan_port(target["host"], p), ports))

    open_ports = [item for item in port_results if item["state"] == "open"]

    web_checks = []
    for item in open_ports:
        port = item["port"]
        if port in HTTP_PORTS:
            web_checks.append(fetch_http_headers(target["host"], port, use_https=False))
        if port in HTTPS_PORTS:
            web_checks.append(fetch_http_headers(target["host"], port, use_https=True))

    findings = build_findings(open_ports, web_checks)
    score = risk_score(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity_counts[finding.severity] += 1

    result = {
        "scanner": "Santhosh SecureScan",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        "target": target,
        "scope": scope,
        "resolved_ips": addresses,
        "profile": profile,
        "ports_scanned": ports,
        "open_ports": open_ports,
        "closed_count": len([item for item in port_results if item["state"] != "open"]),
        "web_checks": web_checks,
        "findings": [finding.as_dict() for finding in findings],
        "severity_counts": severity_counts,
        "risk_score": score,
        "risk_label": "Low" if score >= 80 else "Moderate" if score >= 55 else "High" if score >= 30 else "Critical",
    }
    result["report_markdown"] = generate_markdown_report(result)
    return result


def generate_markdown_report(result: dict[str, Any]) -> str:
    target = result["target"]["display"]
    lines = [
        "# Santhosh SecureScan Vulnerability Report",
        "",
        f"Target: `{target}`",
        f"Generated UTC: `{result['generated_at']}`",
        f"Scope Type: `{result['scope']}`",
        f"Risk Score: `{result['risk_score']} / 100` ({result['risk_label']})",
        f"Scan Duration: `{result['duration_ms']} ms`",
        "",
        "## Summary",
        "",
        f"- Ports scanned: {len(result['ports_scanned'])}",
        f"- Open ports: {len(result['open_ports'])}",
        f"- Findings: {len(result['findings'])}",
        f"- Resolved IPs: {', '.join(result['resolved_ips']) if result['resolved_ips'] else 'None'}",
        "",
        "## Open Ports",
        "",
    ]

    if result["open_ports"]:
        for port in result["open_ports"]:
            banner = f" - `{port['banner'][:120]}`" if port.get("banner") else ""
            lines.append(f"- {port['port']} / {port['service']} ({port['latency_ms']} ms){banner}")
    else:
        lines.append("- No open ports found in the selected profile.")

    lines.extend(["", "## Findings", ""])
    if result["findings"]:
        for idx, finding in enumerate(result["findings"], 1):
            lines.extend(
                [
                    f"### {idx}. [{finding['severity'].upper()}] {finding['title']}",
                    "",
                    f"- Category: {finding['category']}",
                    f"- Evidence: {finding['evidence']}",
                    f"- Recommendation: {finding['recommendation']}",
                    "",
                ]
            )
    else:
        lines.append("No vulnerabilities were identified by this basic scan.")

    lines.extend(
        [
            "## Next Steps",
            "",
            "- Verify results manually before making production decisions.",
            "- Patch exposed software and remove public access to unnecessary services.",
            "- Re-scan after remediation.",
            "",
            "Ethical note: scan only systems you own or have permission to assess.",
        ]
    )
    return "\n".join(lines)



