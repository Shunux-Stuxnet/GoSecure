"""BIMI (Brand Indicators for Message Identification) record check.
Looks up the default._bimi.<domain> TXT record which lets mail clients
display a company logo next to authenticated email."""

import dns.resolver
import dns.exception
from urllib.parse import urlparse


def check_bimi(domain: str) -> dict:
    if domain.startswith("http"):
        domain = urlparse(domain).hostname or domain

    name = f"default._bimi.{domain}"
    out = {"domain": domain, "queried": name, "present": False}

    try:
        answers = dns.resolver.resolve(name, "TXT")
        records = []
        for r in answers:
            txt = "".join(b.decode(errors="replace") for b in r.strings)
            records.append(txt)
        bimi_rec = next((t for t in records if t.lower().startswith("v=bimi1")), None)
        if not bimi_rec:
            out["error"] = "TXT record exists but no v=BIMI1 directive"
            out["raw"] = records
            out["summary"] = "BIMI record missing"
            return out

        fields = {}
        for part in bimi_rec.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k.strip().lower()] = v.strip()

        logo_url = fields.get("l")
        vmc_url = fields.get("a")
        out.update({
            "present": True,
            "record": bimi_rec,
            "logoUrl": logo_url,
            "vmcUrl": vmc_url,
            "hasLogo": bool(logo_url),
            "hasVmc": bool(vmc_url),
            "summary": (
                f"BIMI configured: logo={'yes' if logo_url else 'no'}, VMC={'yes' if vmc_url else 'no'}"
            ),
        })
        return out
    except dns.resolver.NXDOMAIN:
        out["summary"] = "No BIMI record (NXDOMAIN)"
        return out
    except dns.resolver.NoAnswer:
        out["summary"] = "No BIMI TXT record found"
        return out
    except dns.exception.DNSException as exc:
        out["error"] = str(exc)
        out["summary"] = "DNS lookup failed"
        return out
