import socket
import dns.resolver
import dns.rdatatype


def perform_dns_lookup(hostname: str) -> dict:
    result = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": [],
        "SOA": None,
        "SRV": [],
        "PTR": [],
    }

    # A records
    try:
        answers = dns.resolver.resolve(hostname, "A")
        result["A"] = [rdata.address for rdata in answers]
    except Exception:
        pass

    # AAAA records
    try:
        answers = dns.resolver.resolve(hostname, "AAAA")
        result["AAAA"] = [rdata.address for rdata in answers]
    except Exception:
        pass

    # MX records
    try:
        answers = dns.resolver.resolve(hostname, "MX")
        result["MX"] = [{"host": str(rdata.exchange), "pref": rdata.preference} for rdata in answers]
    except Exception:
        pass

    # TXT records
    try:
        answers = dns.resolver.resolve(hostname, "TXT")
        result["TXT"] = [str(rdata) for rdata in answers]
    except Exception:
        pass

    # NS records
    try:
        answers = dns.resolver.resolve(hostname, "NS")
        result["NS"] = [str(rdata.target) for rdata in answers]
    except Exception:
        pass

    # CNAME records
    try:
        answers = dns.resolver.resolve(hostname, "CNAME")
        result["CNAME"] = [str(rdata.target) for rdata in answers]
    except Exception:
        pass

    # SOA record
    try:
        answers = dns.resolver.resolve(hostname, "SOA")
        for rdata in answers:
            result["SOA"] = {
                "ns": str(rdata.mname),
                "mbox": str(rdata.rname),
                "serial": rdata.serial,
                "refresh": rdata.refresh,
                "retry": rdata.retry,
                "expire": rdata.expire,
                "minttl": rdata.minimum,
            }
            break
    except Exception:
        pass

    # SRV records
    try:
        answers = dns.resolver.resolve(hostname, "SRV")
        result["SRV"] = [
            {"target": str(rdata.target), "port": rdata.port, "priority": rdata.priority, "weight": rdata.weight}
            for rdata in answers
        ]
    except Exception:
        pass

    # PTR records (reverse lookup from A records)
    try:
        for ip in result["A"]:
            names = socket.gethostbyaddr(ip)
            if names[0]:
                result["PTR"].append(names[0])
    except Exception:
        pass

    return result
