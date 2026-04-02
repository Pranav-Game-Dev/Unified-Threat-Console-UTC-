"""
UTC — Vulnerability Scanner Router  (Part 4 — Full Implementation)
app/routers/scanner.py
"""

import asyncio
import json
import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.database import (
    get_vuln_reports, get_vuln_report, insert_vuln_report, insert_log, update_vuln_report
)
from app.ws_manager import ws_manager

log = logging.getLogger("utc.scanner.router")
router = APIRouter()


class ScanRequest(BaseModel):
    target_url: str
    scan_type:  str = "full"


@router.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    url = req.target_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if len(url) > 1024:
        raise HTTPException(status_code=400, detail="URL too long")

    from app.modules.vuln_scanner import get_scanner, create_scanner
    scanner = get_scanner()
    if scanner is None:
        scanner = create_scanner(ws_manager)

    report_id = insert_vuln_report(url, req.scan_type)
    if report_id < 0:
        raise HTTPException(status_code=500, detail="Failed to create scan record")

    insert_log("system", "info", f"Scan queued: {url} [{req.scan_type}]")
    log.info(f"Scan queued report_id={report_id} target={url}")

    background_tasks.add_task(_run_scan, scanner, report_id, url, req.scan_type)
    return {"status": "started", "report_id": report_id, "target": url, "scan_type": req.scan_type}


async def _run_scan(scanner, report_id, url, scan_type):
    try:
        await scanner.scan(report_id, url, scan_type)
    except Exception as exc:
        log.error(f"Background scan error: {exc}", exc_info=True)
        update_vuln_report(report_id, "failed", 0, 0, "[]")
        await ws_manager.emit_scanner_update(
            {"status": "failed", "progress": 100, "summary": f"Error: {exc}"}
        )


@router.get("/reports")
async def list_reports(limit: int = 50):
    return get_vuln_reports(limit=limit)


@router.get("/reports/{report_id}")
async def get_report(report_id: int):
    report = get_vuln_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.get("findings"):
        try:
            report["findings"] = json.loads(report["findings"])
        except (json.JSONDecodeError, TypeError):
            report["findings"] = []
    return report


@router.get("/status")
async def get_status():
    from app.modules.vuln_scanner import get_scanner
    s = get_scanner()
    return {"active": s is not None, "module": "vuln_scanner"}
