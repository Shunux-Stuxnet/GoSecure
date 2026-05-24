"""Full SSL/TLS certificate chain inspection via `openssl s_client -showcerts`.
Goes beyond the single leaf cert returned by Python's ssl module."""

import asyncio
import re
from urllib.parse import urlparse


CERT_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----")
SUBJECT_RE = re.compile(r"^\s*(\d+)\s+s:(.+)$", re.M)
ISSUER_RE  = re.compile(r"^\s+i:(.+)$", re.M)


async def get_ssl_chain(url: str, port: int = 443) -> dict:
    if url.startswith("http"):
        url = urlparse(url).hostname or url
    host = url

    cmd = ["openssl", "s_client", "-showcerts", "-servername", host,
           "-connect", f"{host}:{port}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=b"Q\n"), timeout=15
            )
        except asyncio.TimeoutError:
            proc.kill()
            return {"host": host, "error": "openssl timeout", "chainLength": 0}
        text = stdout.decode(errors="replace")
    except FileNotFoundError:
        return {"host": host, "error": "openssl binary not available", "chainLength": 0}
    except Exception as exc:
        return {"host": host, "error": str(exc), "chainLength": 0}

    cert_blocks = CERT_BLOCK.findall(text)
    chain = []
    # Parse "Certificate chain" section if present
    chain_section = ""
    m = re.search(r"Certificate chain([\s\S]+?)(?:---|\Z)", text)
    if m:
        chain_section = m.group(1)
    for sub_match in SUBJECT_RE.finditer(chain_section):
        idx = int(sub_match.group(1))
        subject = sub_match.group(2).strip()
        # find the matching issuer line immediately after
        tail = chain_section[sub_match.end():]
        iss = ISSUER_RE.search(tail)
        chain.append({
            "index": idx,
            "subject": subject,
            "issuer": iss.group(1).strip() if iss else None,
            "isLeaf": idx == 0,
            "isRoot": idx > 0 and (iss and subject == iss.group(1).strip()),
        })

    chain_count = max(len(cert_blocks), len(chain))
    return {
        "host": host,
        "chainLength": chain_count,
        "chain": chain,
        "rawCerts": len(cert_blocks),
        "summary": (f"Chain of {chain_count} certificate(s) presented"
                    if chain_count else "No certificate chain returned"),
    }
