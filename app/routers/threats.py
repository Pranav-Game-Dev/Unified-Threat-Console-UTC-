"""
UTC — Threats / IDS Router
app/routers/threats.py
"""
import logging
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel

from app.database import get_ids_alerts, get_alert_counts, acknowledge_alert

log = logging.getLogger("utc.threats.router")
router = APIRouter()


@router.get("/alerts")
async def get_alerts(
    limit:    int = Query(100, le=500),
    severity: str = Query(None),
):
    return get_ids_alerts(limit=limit, severity=severity)


@router.get("/counts")
async def alert_counts():
    return get_alert_counts()


@router.post("/alerts/{alert_id}/acknowledge")
async def ack_alert(alert_id: int):
    rows = acknowledge_alert(alert_id)
    return {"acknowledged": rows > 0, "id": alert_id}


class SimRequest(BaseModel):
    attack_type: str


@router.post("/simulate")
async def simulate_attack(req: SimRequest):
    from app.modules.ids_engine import get_ids
    ids = get_ids()
    if not ids:
        raise HTTPException(status_code=503, detail="IDS engine not running")
    try:
        result = await ids.simulate_attack(req.attack_type)
        return {"status": "ok", "result": result}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/status")
async def get_status():
    from app.modules.ids_engine import get_ids
    ids = get_ids()
    return {
        "active":      ids is not None and ids._running,
        "rules_active": 5,
        "dedup_window": ids._dedup_window if ids else 10,
    }
