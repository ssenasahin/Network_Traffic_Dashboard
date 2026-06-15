"""
traffic.py — Trafik Analizi modülü
  - Aktif bağlantılar   : psutil.net_connections()
  - Protokol dağılımı  : port → servis adı mapping
  - Top remote IP'ler   : bağlantı sayısına göre
  - Bağlantı geçmişi   : rolling time-series buffer
"""

import asyncio
import socket
import time
from collections import Counter, deque
from typing import AsyncIterator

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ── Sabitler ─────────────────────────────────────────────────────────────────
PORT_NAMES: dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2375: "Docker", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

STATUS_LABELS = {
    "ESTABLISHED": "KURULU",
    "LISTEN":      "DİNLİYOR",
    "TIME_WAIT":   "BEKLEMEDE",
    "CLOSE_WAIT":  "KAPANMAK_ÜZERE",
    "SYN_SENT":    "SYN_GÖNDERİLDİ",
    "SYN_RECV":    "SYN_ALINDI",
    "FIN_WAIT1":   "FIN_WAIT1",
    "FIN_WAIT2":   "FIN_WAIT2",
    "CLOSING":     "KAPANIYOR",
    "LAST_ACK":    "SON_ACK",
    "NONE":        "—",
}

HISTORY_SIZE = 60   # saniye cinsinden rolling buffer

# Global rolling buffer (tek process içinde paylaşılır)
_history: deque[dict] = deque(maxlen=HISTORY_SIZE)


# ── Yardımcılar ───────────────────────────────────────────────────────────────
def _service_name(port: int | None) -> str:
    if port is None:
        return "Unknown"
    return PORT_NAMES.get(port, f"Port {port}")


def _is_loopback(ip: str | None) -> bool:
    if not ip:
        return True
    return ip.startswith("127.") or ip == "::1"


# ── Anlık veri toplama ────────────────────────────────────────────────────────
def _snapshot() -> dict:
    if not HAS_PSUTIL:
        return {"error": "psutil yüklü değil. 'pip install psutil' çalıştır."}

    try:
        raw = psutil.net_connections(kind="inet")
    except (PermissionError, psutil.AccessDenied):
        try:
            raw = psutil.net_connections(kind="tcp")
        except Exception as exc:
            return {"error": str(exc)}

    connections: list[dict] = []
    proto_counter:    Counter = Counter()
    status_counter:   Counter = Counter()
    remote_ip_counter: Counter = Counter()
    remote_port_counter: Counter = Counter()

    for c in raw:
        is_tcp = c.type == socket.SOCK_STREAM
        proto  = "TCP" if is_tcp else "UDP"
        lport  = c.laddr.port if c.laddr else None
        lip    = c.laddr.ip   if c.laddr else None
        rport  = c.raddr.port if c.raddr else None
        rip    = c.raddr.ip   if c.raddr else None
        status = (c.status or "NONE").upper()

        service = _service_name(rport) if rport else _service_name(lport)

        conn = {
            "proto":   proto,
            "local":   f"{lip}:{lport}"  if lip  else "—",
            "remote":  f"{rip}:{rport}"  if rip  else "—",
            "remote_ip":   rip,
            "remote_port": rport,
            "status":  STATUS_LABELS.get(status, status),
            "service": service,
            "pid":     c.pid,
        }
        connections.append(conn)

        # İstatistik topla
        if rport:
            proto_counter[service] += 1
        if rip and not _is_loopback(rip):
            remote_ip_counter[rip] += 1
        if rport and not _is_loopback(rip):
            remote_port_counter[_service_name(rport)] += 1
        status_counter[STATUS_LABELS.get(status, status)] += 1

    established = sum(1 for c in connections if "KURULU" in c["status"])

    # Geçmişe ekle
    _history.append({
        "ts":    time.time(),
        "total": len(connections),
        "established": established,
    })

    return {
        "type":        "snapshot",
        "ts":          time.time(),
        "connections": connections,
        "stats": {
            "total":       len(connections),
            "established": established,
            "listening":   sum(1 for c in connections if "DİNLİYOR" in c["status"]),
        },
        "protocol_dist":   dict(proto_counter.most_common(10)),
        "status_dist":     dict(status_counter.most_common()),
        "top_remote_ips":  dict(remote_ip_counter.most_common(10)),
        "top_services":    dict(remote_port_counter.most_common(10)),
        "history": list(_history),
    }


# ── Async stream ──────────────────────────────────────────────────────────────
async def traffic_connection_stream(interval: float = 2.0) -> AsyncIterator[dict]:
    """Her `interval` saniyede bir bağlantı snapshot'ı yield eder."""
    if not HAS_PSUTIL:
        yield {"type": "error", "message": "psutil yüklü değil. 'pip install psutil' çalıştır."}
        return

    loop = asyncio.get_running_loop()
    while True:
        data = await loop.run_in_executor(None, _snapshot)
        yield data
        await asyncio.sleep(interval)
