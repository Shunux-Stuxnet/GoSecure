import re
import httpx

# (software_key, display_name, header_name, value_prefix)
HEADER_SOURCES = [
    ("apache", "Apache", "server", "Apache"),
    ("nginx", "nginx", "server", "nginx"),
    ("iis", "IIS", "server", "Microsoft-IIS"),
    ("caddy", "Caddy", "server", "Caddy"),
    ("php", "PHP", "x-powered-by", "PHP"),
    ("aspnet", "ASP.NET", "x-aspnet-version", None),
]

# Tuples of (software_key, version_tuple_or_None, cve, severity, description)
# version == None means "all versions are EOL / always flagged"
VULN_DB = {
    "apache": [
        ((2, 4, 49), (2, 4, 49), "CVE-2021-41773", "critical", "Path traversal and remote code execution"),
        ((2, 4, 50), (2, 4, 50), "CVE-2021-42013", "critical", "Path traversal bypass via URL encoding"),
        ((0, 0, 0), (2, 2, 99), None, "high", "Apache 2.2.x is end-of-life (EOL since January 2018)"),
    ],
    "nginx": [
        ((0, 0, 0), (1, 14, 0), "CVE-2018-16845", "medium", "Off-by-one memory disclosure in mp4 module"),
        ((0, 0, 0), (1, 20, 0), "CVE-2021-23017", "high", "Off-by-one in DNS resolver (remote code exec)"),
    ],
    "php": [
        ((0, 0, 0), (5, 99, 99), None, "critical", "PHP 5.x is end-of-life (EOL since December 2018) — no security patches"),
        ((7, 0, 0), (7, 3, 99), None, "high", "PHP 7.0–7.3 is end-of-life — no security patches"),
        ((7, 4, 0), (7, 4, 99), None, "medium", "PHP 7.4 reached EOL November 2022"),
        ((8, 0, 0), (8, 0, 99), None, "medium", "PHP 8.0 reached EOL November 2023"),
        ((8, 1, 0), (8, 1, 0), "CVE-2021-21708", "high", "Use-after-free vulnerability in PHP_Startup"),
    ],
    "iis": [
        ((0, 0, 0), (7, 99, 99), None, "high", "IIS 7.x and below is end-of-life"),
    ],
}

VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _parse_ver(s: str) -> tuple:
    m = VERSION_RE.search(s)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _in_range(v: tuple, lo: tuple, hi: tuple) -> bool:
    return lo <= v <= hi


def _check_version(key: str, version_str: str) -> list:
    v = _parse_ver(version_str)
    issues = []
    for lo, hi, cve, severity, desc in VULN_DB.get(key, []):
        if _in_range(v, lo, hi):
            issue = {"software": key.upper(), "version": version_str, "severity": severity, "description": desc}
            if cve:
                issue["cve"] = cve
            issues.append(issue)
    return issues


async def check_outdated_software(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)

    headers = {k.lower(): v for k, v in resp.headers.items()}
    findings = []
    software_info = {}

    for key, display, header_name, prefix in HEADER_SOURCES:
        value = headers.get(header_name, "")
        if not value:
            continue

        # Check prefix match (e.g. "Apache" in "Apache/2.4.49 (Ubuntu)")
        if prefix and prefix.lower() not in value.lower():
            continue

        version_match = VERSION_RE.search(value)
        version_str = version_match.group(0) if version_match else "unknown"

        software_info[display] = value
        issues = _check_version(key, version_str)
        findings.extend(issues)

        # Flag version disclosure even if no CVE
        if version_match and not issues:
            findings.append({
                "software": display,
                "version": version_str,
                "severity": "info",
                "description": f"Version disclosed in {header_name} header — consider hiding it",
            })

    return {
        "softwareFound": software_info,
        "issues": findings,
        "safe": not any(f["severity"] in ("critical", "high", "medium") for f in findings),
    }
