import socket

import httpx


async def get_server_info(domain: str) -> dict:
    domain = domain.removeprefix("http://").removeprefix("https://")

    try:
        addresses = socket.gethostbyname_ex(domain)[2]
    except socket.gaierror as e:
        raise Exception(f"An error occurred while resolving DNS. {e}")

    results = []
    for address in addresses:
        # Reverse lookup
        try:
            hostname = socket.gethostbyaddr(address)[0]
        except socket.herror:
            hostname = ""

        # Check DOH support
        doh_url = f"https://{address}/dns-query"
        doh_support = False
        try:
            async with httpx.AsyncClient(timeout=3, verify=False) as client:
                resp = await client.get(doh_url)
                doh_support = resp.status_code == 200
        except Exception:
            pass

        results.append({
            "address": address,
            "hostname": hostname,
            "dohDirectSupports": doh_support,
        })

    return {
        "domain": domain,
        "dns": results,
    }
