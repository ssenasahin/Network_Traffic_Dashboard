"""
network.py — Canlı İzleme modülü
  - Subnet host keşfi  : async TCP connect sweep
  - Ağ trafik istatistikleri : psutil ile byte/paket hızları
"""

import asyncio
import ipaddress
import socket
import time
from typing import AsyncIterator

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Cihaz keşfinde denenecek portlar (yaygın → hızlı yanıt)
PROBE_PORTS = [80, 443, 22, 445, 8080, 21, 3389, 139]
MAX_SUBNET_HOSTS = 1024   # /22 üstü engellenir


class NetworkError(ValueError):
    pass


# ── Host Keşfi ────────────────────────────────────────────────────────────────

def parse_subnet(subnet: str) -> list[ipaddress.IPv4Address]:
    """Subnet stringini ayrıştır, host listesi döndür."""
    try:
        net = ipaddress.ip_network(subnet.strip(), strict=False)
    except ValueError:
        raise NetworkError("Geçersiz subnet. Örn: 192.168.1.0/24")

    hosts = list(net.hosts())
    if not hosts:
        raise NetworkError("Subnet'te taranabilir host yok.")
    if len(hosts) > MAX_SUBNET_HOSTS:
        raise NetworkError(f"Subnet çok büyük ({len(hosts)} host). Maksimum {MAX_SUBNET_HOSTS} host (/22).")
    return hosts


async def _probe_host(ip: str, timeout: float) -> dict | None:
    """Tek bir host'a TCP connect ile ayakta mı diye bak."""
    for port in PROBE_PORTS:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            # Hostname çözümle (best-effort)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                hostname = None
            return {
                "ip": ip,
                "hostname": hostname,
                "status": "up",
                "open_port": port,
            }
        except (OSError, asyncio.TimeoutError):
            continue
    return None


async def sweep_subnet(
    subnet: str,
    timeout: float = 0.5,
    concurrency: int = 150,
) -> AsyncIterator[dict]:
    """
    Subnet'teki tüm host'ları tarar.
    Her canlı host için dict yield eder:
      {"ip", "hostname", "status", "open_port", "scanned", "total"}
    """
    hosts = parse_subnet(subnet)
    total = len(hosts)
    sem = asyncio.Semaphore(max(1, min(concurrency, 300)))

    async def run(ip: str) -> dict | None:
        async with sem:
            return await _probe_host(ip, timeout)

    tasks = [asyncio.create_task(run(str(ip))) for ip in hosts]
    scanned = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        scanned += 1
        if result:
            result["scanned"] = scanned
            result["total"] = total
            yield result
        else:
            # Kapalı host — sadece ilerleme için
            yield {"status": "down", "scanned": scanned, "total": total}


# ── Trafik İstatistikleri ─────────────────────────────────────────────────────

def _net_counters() -> dict:
    """Anlık ağ sayaçlarını döndür."""
    if not HAS_PSUTIL:
        return {}
    c = psutil.net_io_counters()
    return {
        "bytes_sent":    c.bytes_sent,
        "bytes_recv":    c.bytes_recv,
        "packets_sent":  c.packets_sent,
        "packets_recv":  c.packets_recv,
        "ts":            time.time(),
    }


def _interface_stats() -> list[dict]:
    """Her ağ arayüzü için istatistik listesi."""
    if not HAS_PSUTIL:
        return []
    stats = []
    addrs = psutil.net_if_addrs()
    io    = psutil.net_io_counters(pernic=True)
    for name, counters in io.items():
        addr_list = addrs.get(name, [])
        ipv4 = next((a.address for a in addr_list if a.family == socket.AF_INET), None)
        stats.append({
            "interface":    name,
            "ipv4":         ipv4,
            "bytes_sent":   counters.bytes_sent,
            "bytes_recv":   counters.bytes_recv,
            "packets_sent": counters.packets_sent,
            "packets_recv": counters.packets_recv,
            "errors_in":    counters.errin,
            "errors_out":   counters.errout,
        })
    return stats


async def traffic_stream(interval: float = 1.0) -> AsyncIterator[dict]:
    """
    Her `interval` saniyede bir trafik hızı metrikleri yield eder.
    bytes/s ve packets/s olarak delta hesaplar.
    """
    if not HAS_PSUTIL:
        raise NetworkError("psutil yüklü değil. 'pip install psutil' çalıştır.")

    prev = _net_counters()
    await asyncio.sleep(interval)

    while True:
        curr = _net_counters()
        dt   = max(curr["ts"] - prev["ts"], 0.001)
        yield {
            "type":              "traffic",
            "bytes_sent_rate":   round((curr["bytes_sent"]   - prev["bytes_sent"])   / dt, 1),
            "bytes_recv_rate":   round((curr["bytes_recv"]   - prev["bytes_recv"])   / dt, 1),
            "packets_sent_rate": round((curr["packets_sent"] - prev["packets_sent"]) / dt, 1),
            "packets_recv_rate": round((curr["packets_recv"] - prev["packets_recv"]) / dt, 1),
            "total_bytes_sent":  curr["bytes_sent"],
            "total_bytes_recv":  curr["bytes_recv"],
            "interfaces":        _interface_stats(),
            "ts":                curr["ts"],
        }
        prev = curr
        await asyncio.sleep(interval)
