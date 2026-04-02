"""
UTC — Log Monitor Router  (Part 5 — Full Implementation)
app/routers/logs.py
"""
import logging
from fastapi import APIRouter, Query

from app.database import get_logs, get_log_stats

log = logging.getLogger("utc.logs.router")
router = APIRouter()


@router.get("/")
async def list_logs(
    limit:   int  = Query(200, le=1000),
    source:  str  = Query(None),
    level:   str  = Query(None),
    flagged: bool = Query(False),
):
    return get_logs(limit=limit, source=source, level=level, flagged_only=flagged)


@router.get("/stats")
async def log_stats():
    return get_log_stats()


@router.get("/status")
async def get_status():
    from app.modules.log_monitor import get_log_monitor
    lm = get_log_monitor()
    stats = lm.get_stats() if lm else {}
    return {"active": lm is not None and lm._running, **stats}
