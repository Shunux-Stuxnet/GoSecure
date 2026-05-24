import dns.resolver
import dns.exception

DKIM_SELECTORS = ["default", "google", "mail", "selector1", "selector2", "k1"]


def _query_txt(name: str) -> list[str]:
    answers = dns.resolver.resolve(name, "TXT")
    return [b.decode() for rdata in answers for b in rdata.strings]


def check_email_security(domain: str) -> dict:
    # SPF
    spf_record = None
    try:
        for txt in _query_txt(domain):
            if txt.startswith("v=spf1"):
                spf_record = txt
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass

    spf_policy = None
    if spf_record:
        for part in spf_record.split():
            if part in ("~all", "-all", "+all", "?all"):
                spf_policy = part
                break

    # DMARC
    dmarc_record = None
    try:
        for txt in _query_txt(f"_dmarc.{domain}"):
            if txt.startswith("v=DMARC1"):
                dmarc_record = txt
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass

    dmarc_policy = None
    if dmarc_record:
        for tag in dmarc_record.split(";"):
            tag = tag.strip()
            if tag.lower().startswith("p="):
                dmarc_policy = tag.split("=", 1)[1].strip()
                break

    # DKIM
    selectors_found = []
    for selector in DKIM_SELECTORS:
        try:
            results = _query_txt(f"{selector}._domainkey.{domain}")
            if any("v=DKIM1" in r or "p=" in r for r in results):
                selectors_found.append(selector)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass

    return {
        "spf": {
            "present": spf_record is not None,
            "record": spf_record,
            "policy": spf_policy,
        },
        "dmarc": {
            "present": dmarc_record is not None,
            "record": dmarc_record,
            "policy": dmarc_policy,
        },
        "dkim": {
            "present": len(selectors_found) > 0,
            "selectors_checked": DKIM_SELECTORS,
            "selectors_found": selectors_found,
        },
    }
