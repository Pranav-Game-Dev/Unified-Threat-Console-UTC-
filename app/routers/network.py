"""
UTC — Network Monitor Router
app/routers/network.py
"""
from fastapi import APIRouter, Query
from app.database import get_network_events, get_network_stats

router = APIRouter()


@router.get("/events")
async def get_events(
    limit:      int  = Query(100, le=500),
    suspicious: bool = Query(False),
):
    return get_network_events(limit=limit, suspicious_only=suspicious)


@router.get("/stats")
async def get_stats():
    return get_network_stats()


@router.get("/status")
async def get_status():
    from app.modules.network_monitor import get_monitor
    m = get_monitor()
    return {
        "active":        m is not None and m._running,
        "scapy_mode":    m is not None and not m._running is False,
        "total_packets": m._pkt_total if m else 0,
        "protocols":     dict(m._protocol_counts) if m else {},
    }
