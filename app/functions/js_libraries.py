import re
import httpx
from bs4 import BeautifulSoup

JS_FINGERPRINTS = [
    {
        "name": "jQuery",
        "src_patterns": [r"jquery[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"],
        "keywords": ["jquery.min.js", "jquery.js", "jquery-"],
        "cves": [
            {"below": (1, 9, 0), "cve": "CVE-2012-6708", "desc": "XSS via jQuery.parseHTML"},
            {"below": (3, 0, 0), "cve": "CVE-2015-9251", "desc": "XSS via cross-origin AJAX requests"},
            {"below": (3, 4, 0), "cve": "CVE-2019-11358", "desc": "Prototype pollution via jQuery.extend"},
            {"below": (3, 5, 0), "cve": "CVE-2020-11022", "desc": "XSS via HTML passed to manipulation methods"},
        ],
    },
    {
        "name": "Bootstrap",
        "src_patterns": [r"bootstrap[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"],
        "keywords": ["bootstrap.min.js", "bootstrap.js", "bootstrap-"],
        "cves": [
            {"below": (3, 4, 1), "cve": "CVE-2019-8331", "desc": "XSS via data-template in tooltip/popover"},
            {"below": (4, 3, 1), "cve": "CVE-2019-8331", "desc": "XSS via data-template in Bootstrap 4"},
        ],
    },
    {
        "name": "AngularJS",
        "src_patterns": [r"angular(?:js)?[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"],
        "keywords": ["angular.min.js", "angularjs", "angular.js"],
        "cves": [
            {"below": (2, 0, 0), "cve": "N/A", "desc": "AngularJS 1.x is end-of-life since December 2021"},
        ],
    },
    {
        "name": "Moment.js",
        "src_patterns": [r"moment[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"],
        "keywords": ["moment.min.js", "moment.js"],
        "cves": [
            {"below": (2, 29, 2), "cve": "CVE-2022-24785", "desc": "Path traversal in locale loading"},
            {"below": (2, 29, 4), "cve": "CVE-2022-31129", "desc": "ReDoS in rfc2822 date parsing"},
        ],
    },
    {
        "name": "Lodash",
        "src_patterns": [r"lodash[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"],
        "keywords": ["lodash.min.js", "lodash.js"],
        "cves": [
            {"below": (4, 17, 15), "cve": "CVE-2019-10744", "desc": "Prototype pollution in defaultsDeep"},
            {"below": (4, 17, 21), "cve": "CVE-2021-23337", "desc": "Command injection via template options"},
        ],
    },
    {
        "name": "React",
        "src_patterns": [r"react[.\-](\d+\.\d+\.\d+)(?:\.production\.min|\.development)?\.js"],
        "keywords": ["react.production.min.js", "react.development.js"],
        "cves": [],
    },
    {
        "name": "Vue.js",
        "src_patterns": [r"vue[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js"],
        "keywords": ["vue.min.js", "vue.runtime.min.js", "vue.global.js"],
        "cves": [
            {"below": (2, 6, 0), "cve": "CVE-2018-11235", "desc": "XSS via v-html with user input"},
        ],
    },
]

VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _parse_ver(s: str) -> tuple:
    m = VERSION_RE.search(s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (0, 0, 0)


def _find_cves(fp: dict, version: tuple) -> list:
    issues = []
    for entry in fp["cves"]:
        if version < entry["below"]:
            issues.append(f"{entry['cve']}: {entry['desc']}")
    return issues


def _analyze_src(src: str, fp: dict) -> tuple:
    """Try to extract version from a script src URL for a given fingerprint."""
    for pattern in fp["src_patterns"]:
        m = re.search(pattern, src, re.IGNORECASE)
        if m:
            return m.group(1), src
    return None, None


async def audit_js_libraries(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)

    soup = BeautifulSoup(resp.text, "html.parser")
    script_srcs = [
        tag.get("src", "") for tag in soup.find_all("script") if tag.get("src")
    ]

    libraries = []
    seen = set()

    for fp in JS_FINGERPRINTS:
        for src in script_srcs:
            # Quick keyword check first (fast path)
            if not any(kw.lower() in src.lower() for kw in fp["keywords"]):
                continue

            version_str, matched_src = _analyze_src(src, fp)
            name = fp["name"]

            if name in seen:
                break

            if version_str:
                version = _parse_ver(version_str)
                issues = _find_cves(fp, version)
                libraries.append({
                    "name": name,
                    "version": version_str,
                    "vulnerable": len(issues) > 0,
                    "issues": issues,
                    "source": matched_src,
                })
            else:
                # Detected but version unknown
                libraries.append({
                    "name": name,
                    "version": "unknown",
                    "vulnerable": False,
                    "issues": ["Version could not be determined"],
                    "source": src,
                })
            seen.add(name)
            break

    vulnerable_count = sum(1 for lib in libraries if lib["vulnerable"])
    return {
        "libraries": libraries,
        "totalFound": len(libraries),
        "vulnerableCount": vulnerable_count,
    }
