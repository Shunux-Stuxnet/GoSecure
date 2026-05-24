import dns.resolver
import dns.rdatatype
import dns.message
import dns.query


def get_rrsig_with_key(domain: str) -> dict:
    rrsig_records = []
    dnskey_records = []

    # Query RRSIG records
    try:
        request = dns.message.make_query(domain, dns.rdatatype.RRSIG)
        response = dns.query.udp(request, "8.8.8.8", timeout=5)
        for rrset in response.answer:
            for rdata in rrset:
                if rdata.rdtype == dns.rdatatype.RRSIG:
                    rrsig_records.append({
                        "type_covered": dns.rdatatype.to_text(rdata.type_covered),
                        "algorithm": rdata.algorithm,
                        "labels": rdata.labels,
                        "original_ttl": rdata.original_ttl,
                        "expiration": str(rdata.expiration),
                        "inception": str(rdata.inception),
                        "key_tag": rdata.key_tag,
                        "signer": str(rdata.signer),
                    })
    except Exception as e:
        raise Exception(f"Failed to query RRSIG: {e}")

    # Query DNSKEY records
    try:
        request = dns.message.make_query(domain, dns.rdatatype.DNSKEY)
        response = dns.query.udp(request, "8.8.8.8", timeout=5)
        for rrset in response.answer:
            for rdata in rrset:
                if rdata.rdtype == dns.rdatatype.DNSKEY:
                    dnskey_records.append({
                        "flags": rdata.flags,
                        "protocol": rdata.protocol,
                        "algorithm": rdata.algorithm,
                    })
    except Exception as e:
        raise Exception(f"Failed to query DNSKEY: {e}")

    return {
        "RRSIGRecords": rrsig_records,
        "DNSKEYRecords": dnskey_records,
    }
