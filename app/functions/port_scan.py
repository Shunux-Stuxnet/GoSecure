import asyncio
import socket
from typing import Optional, List


KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
]


async def scan_port(hostname: str, port: int, timeout: float = 1.0) -> Optional[int]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return None


async def scan_ports(hostname: str) -> List[str]:
    tasks = [scan_port(hostname, port) for port in COMMON_PORTS]
    results = await asyncio.gather(*tasks)

    open_ports = []
    for port in results:
        if port is not None:
            service_name = KNOWN_SERVICES.get(port, "Unknown service")
            open_ports.append(f"{service_name} ({port})")

    return open_ports
