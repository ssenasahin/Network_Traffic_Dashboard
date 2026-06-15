import json
import os
import time
from collections import deque
from datetime import datetime
from typing import Literal

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .database import get_scan, init_db, list_scans, save_scan
from .scanner import ScannerError, parse_ports, resolve_target, scan_ports
from .network import NetworkError, sweep_subnet, traffic_stream
from .cve import CVEError, lookup_cve, search_cves
from .traffic import traffic_connection_stream

# ── In-memory log buffer ──────────────────────────────────────────────────────
_log_buffer: deque[dict] = deque(maxlen=500)

def log_event(level: str, source: str, message: str) -> None:
    _log_buffer.appendleft({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level": level,       # INFO | WARN | ERROR
        "source": source,
        "message": message,
    })

app = FastAPI(title="Sentinel Port Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Geliştirme için açık; prod'da kendi origin'ini yaz
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Canlı İzleme: Gerçek Zamanlı Trafik ──────────────────────────────────────

@app.websocket("/ws/network/traffic")
async def ws_traffic(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        async for snapshot in traffic_stream(interval=1.0):
            await websocket.send_json(snapshot)
    except WebSocketDisconnect:
        pass
    except NetworkError as exc:
        await websocket.send_json({"type": "error", "message": str(exc)})


# ── Canlı İzleme: Subnet Host Keşfi ──────────────────────────────────────────

@app.websocket("/ws/network/sweep")
async def ws_sweep(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        payload = await websocket.receive_json()
        subnet      = payload.get("subnet", "192.168.1.0/24")
        timeout     = float(payload.get("timeout", 0.5))
        concurrency = int(payload.get("concurrency", 150))

        live_hosts: list[dict] = []
        async for result in sweep_subnet(subnet, timeout, concurrency):
            await websocket.send_json(result)
            if result.get("status") == "up":
                live_hosts.append(result)

        await websocket.send_json({
            "type":       "done",
            "live_count": len(live_hosts),
            "hosts":      live_hosts,
        })
    except WebSocketDisconnect:
        pass
    except (NetworkError, ValueError) as exc:
        await websocket.send_json({"type": "error", "message": str(exc)})


# ── CVE Sorgulama ─────────────────────────────────────────────────────────────

# ── Trafik Analizi ───────────────────────────────────────────────────────────

@app.websocket("/ws/traffic/connections")
async def ws_traffic_connections(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        async for snapshot in traffic_connection_stream(interval=2.0):
            await websocket.send_json(snapshot)
    except WebSocketDisconnect:
        pass


@app.get("/api/cve/{cve_id}")
async def api_cve_lookup(cve_id: str):
    """Tekil CVE sorgusu. NVD → CVE.org fallback."""
    try:
        return await lookup_cve(cve_id)
    except CVEError as exc:
        log_event("WARN", "cve/lookup", str(exc))
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/cve/search/{keyword}")
async def api_cve_search(keyword: str, limit: int = 20):
    """Ürün / keyword ile CVE listesi."""
    try:
        return await search_cves(keyword, limit=limit)
    except CVEError as exc:
        log_event("WARN", "cve/search", str(exc))
        raise HTTPException(status_code=400, detail=str(exc))


SCAN_PROFILES: dict[str, dict] = {
    "stealth":    {"timeout": 2.0, "concurrency": 10},
    "default":    {"timeout": 0.8, "concurrency": 150},
    "aggressive": {"timeout": 0.3, "concurrency": 500},
}

class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    mode: Literal["top20", "top100", "custom"] = "top20"
    ports: str | None = None
    timeout: float = Field(default=0.8, ge=0.2, le=5.0)
    concurrency: int = Field(default=150, ge=1, le=500)
    banner: bool = True
    profile: str | None = None   # "stealth" | "default" | "aggressive" | None

    def resolved_timeout(self) -> float:
        if self.profile and self.profile in SCAN_PROFILES:
            return SCAN_PROFILES[self.profile]["timeout"]
        return self.timeout

    def resolved_concurrency(self) -> int:
        if self.profile and self.profile in SCAN_PROFILES:
            return SCAN_PROFILES[self.profile]["concurrency"]
        return self.concurrency


@app.on_event("startup")
def startup() -> None:
    init_db()
    log_event("INFO", "system", "AETHER_SCAN başlatıldı.")


@app.get("/api/v1/logs")
def get_logs(limit: int = 200) -> list[dict]:
    return list(_log_buffer)[:limit]


@app.get("/")
def index() -> FileResponse:
    return FileResponse("static/index.html")


@app.get("/api/v1/history")
def history() -> list[dict]:
    return list_scans()


@app.get("/api/v1/history/{scan_id}")
def history_item(scan_id: int) -> dict:
    scan = get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post("/api/v1/scan")
async def scan(request: ScanRequest) -> dict:
    try:
        ports = parse_ports(request.mode, request.ports)
        target = await resolve_target(request.target, allow_public=os.getenv("SCANNER_ALLOW_PUBLIC", "1") == "1")
    except (ScannerError, ValueError) as exc:
        log_event("ERROR", "scanner", str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    started = time.perf_counter()
    open_results = []
    scanned = 0
    async for result in scan_ports(target, ports, request.resolved_timeout(), request.resolved_concurrency(), request.banner):
        scanned += 1
        if result["state"] == "open":
            open_results.append(result)

    duration_ms = (time.perf_counter() - started) * 1000
    scan_id = save_scan(target.original, target.ip, len(ports), sorted(open_results, key=lambda item: item["port"]), duration_ms)
    return {
        "id": scan_id,
        "target": target.original,
        "resolved_ip": target.ip,
        "ports_scanned": scanned,
        "open_count": len(open_results),
        "duration_ms": round(duration_ms, 1),
        "results": sorted(open_results, key=lambda item: item["port"]),
    }


@app.websocket("/ws/scan")
async def scan_socket(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        payload = await websocket.receive_json()
        request = ScanRequest(**payload)
        ports = parse_ports(request.mode, request.ports)
        target = await resolve_target(request.target, allow_public=os.getenv("SCANNER_ALLOW_PUBLIC", "1") == "1")
        t_out = request.resolved_timeout()
        conc  = request.resolved_concurrency()
        await websocket.send_json({"type": "meta", "target": target.original, "resolved_ip": target.ip, "total": len(ports), "timeout": t_out, "concurrency": conc})

        started = time.perf_counter()
        open_results = []
        scanned = 0
        async for result in scan_ports(target, ports, t_out, conc, request.banner):
            scanned += 1
            if result["state"] == "open":
                open_results.append(result)
            await websocket.send_json({"type": "progress", "scanned": scanned, "total": len(ports), "result": result})

        duration_ms = (time.perf_counter() - started) * 1000
        open_results = sorted(open_results, key=lambda item: item["port"])
        scan_id = save_scan(target.original, target.ip, len(ports), open_results, duration_ms)
        await websocket.send_json(
            {
                "type": "done",
                "id": scan_id,
                "ports_scanned": scanned,
                "open_count": len(open_results),
                "duration_ms": round(duration_ms, 1),
                "results": open_results,
            }
        )
    except WebSocketDisconnect:
        return
    except (ScannerError, ValueError, json.JSONDecodeError) as exc:
        log_event("ERROR", "ws/scan", str(exc))
        await websocket.send_json({"type": "error", "message": str(exc)})
    except Exception as exc:
        log_event("ERROR", "ws/scan", f"Beklenmeyen hata: {exc}")
        await websocket.send_json({"type": "error", "message": f"Beklenmeyen hata: {exc}"})
