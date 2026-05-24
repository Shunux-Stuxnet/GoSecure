import ssl
import socket
from datetime import datetime


def get_ssl_info(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, 443))

        # Get certificate with validation for details
        context2 = ssl.create_default_context()
        conn2 = context2.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn2.settimeout(10)
        try:
            conn2.connect((domain, 443))
            cert = conn2.getpeercert()
            conn2.close()
        except ssl.SSLCertVerificationError:
            # Fall back to unverified
            cert = conn.getpeercert(binary_form=False)
            if not cert:
                # Use binary form and parse
                der_cert = conn.getpeercert(binary_form=True)
                x509 = ssl.DER_cert_to_PEM_cert(der_cert)
                cert = _parse_cert_basic(conn, domain)

        conn.close()

        if not cert:
            return {"certificates": [], "error": "Could not retrieve certificate"}

        certificates = [_format_cert(cert)]
        return {"certificates": certificates}

    except Exception as e:
        return {"certificates": [], "error": str(e)}


def _format_cert(cert: dict) -> dict:
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))

    dns_names = []
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            dns_names.append(san_value)

    return {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("commonName", ""),
        "valid_from": cert.get("notBefore", ""),
        "valid_until": cert.get("notAfter", ""),
        "serial_number": cert.get("serialNumber", ""),
        "signature_algorithm": "",
        "is_ca_cert": False,
        "dns_names": dns_names,
    }


def _parse_cert_basic(conn, domain: str) -> dict:
    """Fallback basic cert parsing when standard getpeercert fails."""
    return {
        "subject": ((("commonName", domain),),),
        "issuer": ((("commonName", "Unknown"),),),
        "notBefore": "",
        "notAfter": "",
        "serialNumber": "",
        "subjectAltName": [],
    }
