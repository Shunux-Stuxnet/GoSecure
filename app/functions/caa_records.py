import dns.resolver
from urllib.parse import urlparse


def get_caa_records(domain: str) -> dict:
    if domain.startswith("http"):
        domain = urlparse(domain).hostname or domain
    domain = domain.lstrip(".")

    records = []
    issue_cas, issuewild_cas, iodef = [], [], []

    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=8)
        for r in answers:
            tag = r.tag.decode() if isinstance(r.tag, bytes) else str(r.tag)
            val = r.value.decode() if isinstance(r.value, bytes) else str(r.value)
            records.append({"flag": r.flags, "tag": tag, "value": val})
            if tag == "issue":
                issue_cas.append(val)
            elif tag == "issuewild":
                issuewild_cas.append(val)
            elif tag == "iodef":
                iodef.append(val)
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        return {"present": False, "error": "Domain does not exist"}
    except Exception as exc:
        return {"present": False, "error": str(exc)}

    return {
        "present": bool(records),
        "records": records,
        "issue": issue_cas,
        "issuewild": issuewild_cas,
        "iodef": iodef,
        "summary": f"{len(records)} CAA record(s) found" if records
                   else "No CAA records — any Certificate Authority can issue certs for this domain",
    }
