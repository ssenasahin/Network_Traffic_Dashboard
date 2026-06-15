import asyncio
import ipaddress
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import AsyncIterator


POPULAR_PORTS: dict[int, str] = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submit",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    2375: "Docker",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
TOP_100_PORTS = sorted(POPULAR_PORTS.keys())
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

# ── Engellenen IP listesi ─────────────────────────────────────────────────────
# Ortam değişkeni ile genişletilebilir: BLOCKED_IPS="1.2.3.4,5.6.7.8"
_DEFAULT_BLOCKED = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
_env_blocked     = {ip.strip() for ip in os.getenv("BLOCKED_IPS", "").split(",") if ip.strip()}
BLOCKED_IPS: frozenset[str] = frozenset(_DEFAULT_BLOCKED | _env_blocked)


@dataclass(frozen=True)
class TargetInfo:
    original: str
    host: str
    ip: str
    family: int
    is_public: bool


class ScannerError(ValueError):
    pass


def parse_ports(mode: str, custom: str | None) -> list[int]:
    if mode == "top20":
        return TOP_20_PORTS
    if mode == "top100":
        return TOP_100_PORTS
    if mode != "custom":
        raise ScannerError("Bilinmeyen port modu.")
    if not custom:
        raise ScannerError("Özel port aralığı boş olamaz.")

    ports: set[int] = set()
    for chunk in custom.split(","):
        part = chunk.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ScannerError("Port aralığı ters olamaz.")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports:
        raise ScannerError("Taranacak port bulunamadı.")
    if any(port < 1 or port > 65535 for port in ports):
        raise ScannerError("Portlar 1 ile 65535 arasında olmalı.")
    if len(ports) > 2000:
        raise ScannerError("Tek taramada en fazla 2000 port taranabilir.")
    return sorted(ports)


async def resolve_target(target: str, allow_public: bool) -> TargetInfo:
    clean = target.strip()
    if not clean:
        raise ScannerError("Hedef boş olamaz. Scan aborted.")

    try:
        address = ipaddress.ip_address(clean)
        host = clean
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        ip = str(address)
    except ValueError:
        if not DOMAIN_RE.match(clean):
            raise ScannerError(
                f"Invalid target: '{clean[:40]}' is not a valid IP address or domain. Scan aborted."
            )
        host = clean.rstrip(".")
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScannerError(f"Hedef çözümlenemedi: '{host}'. DNS kaydı bulunamadı. Scan aborted.") from exc
        family = infos[0][0]
        ip = infos[0][4][0]
        address = ipaddress.ip_address(ip)

    # ── Rate limit / Blocklist kontrolü ──────────────────────────────────────
    if ip in BLOCKED_IPS:
        raise ScannerError(f"[BLOCKED] {ip} adresi engellendi. Scan aborted.")

    is_public = not (address.is_private or address.is_loopback or address.is_link_local)
    if is_public and not allow_public and host.lower() != "scanme.nmap.org":
        raise ScannerError("Güvenlik için public hedefler kapalı. Yetkili test için SCANNER_ALLOW_PUBLIC=1 ayarla.")
    return TargetInfo(original=clean, host=host, ip=ip, family=family, is_public=is_public)


async def scan_port(target: TargetInfo, port: int, timeout: float, banner: bool) -> dict:
    started = time.perf_counter()
    result = {
        "port": port,
        "service": POPULAR_PORTS.get(port, "Unknown"),
        "state": "closed",
        "latency_ms": None,
        "banner": None,
    }
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target.ip, port, family=target.family), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return result

    latency = (time.perf_counter() - started) * 1000
    result["state"] = "open"
    result["latency_ms"] = round(latency, 1)

    if banner:
        result["banner"] = await grab_banner(reader, writer, target.host, port, timeout)

    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ssl.SSLError):
        pass
    return result


async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int, timeout: float) -> str | None:
    probes = {
        80: f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        8080: f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        8000: f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        25: "EHLO scanner.local\r\n",
        587: "EHLO scanner.local\r\n",
        110: "\r\n",
        143: "\r\n",
        21: "\r\n",
        22: "\r\n",
    }
    payload = probes.get(port, "\r\n")
    try:
        writer.write(payload.encode("ascii", errors="ignore"))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=max(0.4, timeout))
    except (OSError, UnicodeError, asyncio.TimeoutError):
        return None

    banner = data.decode("utf-8", errors="replace").strip()
    if not banner:
        return None
    return " ".join(banner.split())[:180]


async def scan_ports(target: TargetInfo, ports: list[int], timeout: float, concurrency: int, banner: bool) -> AsyncIterator[dict]:
    semaphore = asyncio.Semaphore(max(1, min(concurrency, 500)))

    async def run(port: int) -> dict:
        async with semaphore:
            return await scan_port(target, port, timeout, banner)

    tasks = [asyncio.create_task(run(port)) for port in ports]
    for task in asyncio.as_completed(tasks):
        yield await task
