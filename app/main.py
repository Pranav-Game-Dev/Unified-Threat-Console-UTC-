"""
UTC — FastAPI Application Entry Point
app/main.py
"""

import logging
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import init_db
from app.ws_manager import ws_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
)
log = logging.getLogger("utc.main")

BASE_DIR      = Path(__file__).parent.parent.resolve()
DASHBOARD_DIR = BASE_DIR / "dashboard"


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("UTC starting up...")
    settings = get_settings()

    init_db()
    log.info("Database initialised ✓")

    # Use get_running_loop() — correct for Python 3.10+
    loop = asyncio.get_running_loop()

    # ── Network Monitor + IDS ────────────────────────────────────────────
    from app.modules.ids_engine      import create_ids
    from app.modules.network_monitor import create_monitor

    ids     = create_ids(ws_manager)
    monitor = create_monitor(ws_manager)
    monitor.set_ids_callback(ids.inspect_packet)
    ids.start(loop)
    monitor.start(loop)
    log.info("Network monitor + IDS active ✓")

    # ── Log Monitor ──────────────────────────────────────────────────────
    from app.modules.log_monitor import create_log_monitor
    log_mon = create_log_monitor(ws_manager)
    log_mon.start(loop)
    log.info("Log monitor active ✓")

    # ── Vuln Scanner (singleton init) ─────────────────────────────────────
    from app.modules.vuln_scanner import create_scanner
    create_scanner(ws_manager)
    log.info("Vulnerability scanner ready ✓")

    # ── Startup log entry ────────────────────────────────────────────────
    from app.database import insert_log
    insert_log("system", "info", "UTC started — all modules active", flagged=False)

    host = settings.get("server", {}).get("host", "127.0.0.1")
    port = settings.get("server", {}).get("port", 8000)
    log.info(f"UTC is live → http://{host}:{port}")

    yield

    # ── Shutdown ─────────────────────────────────────────────────────────
    log.info("UTC shutting down...")
    try:
        from app.modules.network_monitor import get_monitor
        from app.modules.ids_engine      import get_ids
        from app.modules.log_monitor     import get_log_monitor
        m = get_monitor();     m and m.stop()
        i = get_ids();         i and i.stop()
        lm = get_log_monitor(); lm and lm.stop()
    except Exception as exc:
        log.debug(f"Shutdown cleanup: {exc}")
    await ws_manager.broadcast_json({"type": "server_shutdown", "message": "Server is stopping"})


app = FastAPI(
    title="UTC — Unified Threat Console",
    description="Integrated Cyber Security Monitoring and Threat Detection System",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.routers import network, threats, scanner, logs, files  # noqa: E402

app.include_router(network.router, prefix="/api/network", tags=["Network"])
app.include_router(threats.router, prefix="/api/threats", tags=["Threats"])
app.include_router(scanner.router, prefix="/api/scanner", tags=["Scanner"])
app.include_router(logs.router,    prefix="/api/logs",    tags=["Logs"])
app.include_router(files.router,   prefix="/api/files",   tags=["Files"])


@app.get("/api/health", tags=["System"])
async def health():
    return {"status": "ok", "system": "UTC", "version": "1.0.0"}


@app.get("/api/info", tags=["System"])
async def info():
    settings = get_settings()
    srv = settings.get("server", {})
    mods = settings.get("network_monitor", {})
    # Detect demo mode
    try:
        from app.modules.network_monitor import _scapy_available
        demo_mode = not _scapy_available
    except Exception:
        demo_mode = True

    return {
        "system": "Unified Threat Console",
        "version": "1.0.0",
        "host": srv.get("host", "127.0.0.1"),
        "port": srv.get("port", 8000),
        "demo_mode": demo_mode,
        "capture_mode": "demo" if demo_mode else "live",
        "modules": {
            "network_monitor": mods.get("enabled", True),
            "ids":             settings.get("ids", {}).get("enabled", True),
            "log_monitor":     settings.get("log_monitor", {}).get("enabled", True),
            "vuln_scanner":    True,
            "file_transfer":   True,
        },
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    client_id = await ws_manager.connect(websocket)
    log.info(f"WS connected: {client_id}")
    try:
        await ws_manager.send_personal_json(
            {"type": "connected", "client_id": client_id,
             "message": "Connected to UTC real-time feed"},
            websocket,
        )
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=25)
                await _handle_ws_message(data, websocket, client_id)
            except asyncio.TimeoutError:
                await ws_manager.send_personal_json({"type": "ping"}, websocket)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
        log.info(f"WS disconnected: {client_id}")
    except Exception as exc:
        log.error(f"WS error ({client_id}): {exc}")
        ws_manager.disconnect(websocket)


async def _handle_ws_message(data: dict, websocket: WebSocket, client_id: str):
    t = data.get("type", "")
    if t == "pong":
        pass
    elif t == "subscribe":
        channel = data.get("channel", "all")
        await ws_manager.send_personal_json({"type": "subscribed", "channel": channel}, websocket)
    elif t == "request_snapshot":
        from app.database import get_network_stats, get_alert_counts
        snap = {"network": get_network_stats(), "alerts": get_alert_counts()}
        await ws_manager.send_personal_json({"type": "snapshot", "data": snap}, websocket)
    else:
        log.debug(f"Unknown WS msg from {client_id}: {t}")


# ── Static files — must be mounted AFTER all route definitions ────────────────
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        return FileResponse(str(DASHBOARD_DIR / "index.html"))
else:
    @app.get("/", include_in_schema=False)
    async def dashboard_not_ready():
        return JSONResponse(
            {"error": "Dashboard directory missing. Check installation."},
            status_code=503,
        )
