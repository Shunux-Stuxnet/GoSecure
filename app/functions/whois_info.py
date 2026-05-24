import socket


WHOIS_SERVER = "whois.iana.org"

UNWANTED_SECTIONS = [
    "URL of the ICANN Whois Inaccuracy Complaint Form:",
    ">>> Last update of whois database:",
    "For more information on Whois status codes, please visit",
    "NOTICE: The expiration date displayed in this record is the date the",
    "database through the use of electronic processes that are high-volume and",
    "automated except as reasonably necessary to register domain names or",
    "modify existing registrations; the Data in VeriSign Global Registry",
    "Services' (\"VeriSign\") Whois database is provided by VeriSign for",
    "information purposes only, and to assist persons in obtaining information",
    "about or related to a domain name registration record. VeriSign does not",
    "guarantee its accuracy. By submitting a Whois query, you agree to abide",
    "by the following terms of use: You agree that you may use this Data only",
    "for lawful purposes and that under no circumstances will you use this Data",
    "to: (1) allow, enable, or otherwise support the transmission of mass",
    "unsolicited, commercial advertising or solicitations via e-mail, telephone,",
    "or facsimile; or (2) enable high volume, automated, electronic processes",
    "that apply to VeriSign (or its computer systems). The compilation,",
    "repackaging, dissemination or other use of this Data is expressly",
    "prohibited without the prior written consent of VeriSign. You agree not to",
    "use electronic processes that are automated and high-volume to access or",
    "query the Whois database except as reasonably necessary to register",
    "domain names or modify existing registrations. VeriSign reserves the right",
    "to restrict your access to the Whois database in its sole discretion to ensure",
    "operational stability.  VeriSign may restrict or terminate your access to the",
    "Whois database for failure to abide by these terms of use. VeriSign",
    "reserves the right to modify these terms at any time.",
    "The Registry database contains ONLY .COM, .NET, .EDU domains and",
    "Registrars.",
]


def get_whois_info(domain: str) -> dict:
    info = _get_whois_info(domain)
    info = _remove_unwanted_sections(info)
    return {"data": info}


def _get_whois_info(domain: str) -> str:
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(10)
        conn.connect((WHOIS_SERVER, 43))
        conn.sendall((domain + "\r\n").encode())

        result = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            result += data

        conn.close()
        text = result.decode("utf-8", errors="replace")

        # Check for referral server
        for line in text.split("\n"):
            if line.startswith("refer:"):
                ref_server = line.split("refer:")[1].strip()
                if ref_server:
                    return _get_whois_from_ref_server(domain, ref_server)

        return text

    except Exception as e:
        raise Exception(f"WHOIS lookup failed: {e}")


def _get_whois_from_ref_server(domain: str, ref_server: str) -> str:
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(10)
        conn.connect((ref_server, 43))
        conn.sendall((domain + "\r\n").encode())

        result = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            result += data

        conn.close()
        return result.decode("utf-8", errors="replace")

    except Exception as e:
        raise Exception(f"WHOIS referral lookup failed: {e}")


def _remove_unwanted_sections(info: str) -> str:
    lines = info.split("\n")
    filtered = []
    for line in lines:
        include = True
        for unwanted in UNWANTED_SECTIONS:
            if unwanted in line:
                include = False
                break
        if include:
            filtered.append(line)
    return "\n".join(filtered)
