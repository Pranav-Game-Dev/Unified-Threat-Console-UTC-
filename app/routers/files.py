"""
UTC — Secure File Transfer Router  (Upgraded)
app/routers/files.py

Changelog v2:
  - POST /upload: accepts optional expiry_hours and password form fields
  - GET /download/{token}: token-based (not stored_name), accepts ?password=
  - GET /files: returns full metadata list (disk-verified, DB-joined)
  - GET /info/{token}: metadata for a single file
  - DELETE /delete/{token}: token-based secure delete
  - GET /transfers: transfer history (unchanged)
"""

import logging
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import Response
from typing import Optional

from app.database import get_file_transfers
from app.modules.file_transfer import (
    encrypt_and_store, decrypt_and_read, list_files_with_metadata,
    get_file_info, delete_stored_file, FileTransferError
)
from app.ws_manager import ws_manager

log    = logging.getLogger("utc.files.router")
router = APIRouter()


@router.post("/upload")
async def upload_file(
    file:           UploadFile      = File(...),
    expiry_hours:   Optional[int]   = Form(None),
    expiry_minutes: Optional[int]   = Form(None),
    password:       Optional[str]   = Form(None),
):
    """Encrypt and store an uploaded file. Returns token for shareable link."""
    from app.config import get_settings
    cfg       = get_settings().get("file_transfer", {})
    max_bytes = int(cfg.get("max_file_size_mb", 100)) * 1024 * 1024

    data = await file.read()
    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > max_bytes:
        max_mb = max_bytes // (1024 * 1024)
        raise HTTPException(status_code=413, detail=f"File too large — max {max_mb} MB")

    try:
        meta = encrypt_and_store(
            data,
            file.filename or "unnamed",
            expiry_hours=expiry_hours,
            expiry_minutes=expiry_minutes,
            password=password or None,
        )
    except FileTransferError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    # Notify dashboard
    await ws_manager.emit_file_event({
        "direction":          "upload",
        "original_name":      meta["original_name"],
        "stored_name":        meta["stored_name"],
        "token":              meta["token"],
        "file_size_bytes":    meta["file_size_bytes"],
        "encryption_alg":     meta["encryption_alg"],
        "expiry_time":        meta.get("expiry_time"),
        "password_protected": meta["password_protected"],
        "status":             "ok",
        "download_link":      meta["download_link"],
    })

    return {
        "status":             "ok",
        "token":              meta["token"],
        "stored_name":        meta["stored_name"],
        "original_name":      meta["original_name"],
        "file_size_bytes":    meta["file_size_bytes"],
        "encryption_alg":     meta["encryption_alg"],
        "checksum_sha256":    meta["checksum_sha256"],
        "upload_time":        meta["upload_time"],
        "expiry_time":        meta.get("expiry_time"),
        "password_protected": meta["password_protected"],
        "download_link":      meta["download_link"],
    }


@router.get("/download/{token}")
async def download_file(
    token:    str,
    password: Optional[str] = Query(None),
):
    """
    Decrypt and stream a file for download.
    Accepts token (preferred) or stored_name for backward compatibility.
    If password-protected, pass ?password=<pw> in query string.
    """
    try:
        plaintext, original_name, meta = decrypt_and_read(token, password=password)
    except FileTransferError as exc:
        msg = str(exc)
        if msg == "PASSWORD_REQUIRED":
            raise HTTPException(status_code=401, detail="This file is password-protected. "
                                "Provide ?password=<password> in the URL.")
        if "expired" in msg.lower():
            raise HTTPException(status_code=410, detail=msg)
        if "Incorrect password" in msg:
            raise HTTPException(status_code=403, detail="Incorrect password")
        raise HTTPException(status_code=404, detail=msg)

    # WS notify
    await ws_manager.emit_file_event({
        "direction":       "download",
        "original_name":   original_name,
        "token":           meta.get("token", token),
        "file_size_bytes": len(plaintext),
        "status":          "ok",
    })

    ct = _guess_content_type(original_name)
    return Response(
        content=plaintext,
        media_type=ct,
        headers={
            "Content-Disposition": f'attachment; filename="{original_name}"',
            "Content-Length":      str(len(plaintext)),
            "X-Encryption":        "AES-256-GCM",
        },
    )


@router.get("/files")
async def list_files():
    """
    List all stored files with full metadata.
    Only returns files that still exist on disk (stale DB entries filtered out).
    """
    return list_files_with_metadata()


@router.get("/info/{token}")
async def file_info(token: str):
    """Return metadata for a single file by token."""
    info = get_file_info(token)
    if not info:
        raise HTTPException(status_code=404, detail="File not found")
    return info


@router.delete("/delete/{token}")
async def delete_file(token: str):
    """Securely delete a file (zero-overwrite + metadata removal)."""
    ok = delete_stored_file(token)
    if not ok:
        raise HTTPException(status_code=404, detail="File not found or already deleted")
    await ws_manager.emit_file_event({
        "direction": "delete",
        "token":     token,
        "status":    "deleted",
    })
    return {"status": "deleted", "token": token}


@router.get("/transfers")
async def list_transfers(limit: int = Query(100, le=500)):
    """Return file transfer history from DB."""
    return get_file_transfers(limit=limit)


@router.get("/status")
async def get_status():
    files = list_files_with_metadata()
    return {
        "active":        True,
        "module":        "file_transfer",
        "encryption":    "AES-256-GCM",
        "stored_files":  len(files),
        "total_size_mb": round(sum(f.get("file_size_bytes", 0) for f in files) / (1024*1024), 2),
    }


def _guess_content_type(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return {
        "pdf":  "application/pdf",
        "txt":  "text/plain",
        "png":  "image/png",
        "jpg":  "image/jpeg",
        "jpeg": "image/jpeg",
        "gif":  "image/gif",
        "zip":  "application/zip",
        "json": "application/json",
        "csv":  "text/csv",
        "html": "text/html",
        "xml":  "application/xml",
        "mp4":  "video/mp4",
        "mp3":  "audio/mpeg",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }.get(ext, "application/octet-stream")
