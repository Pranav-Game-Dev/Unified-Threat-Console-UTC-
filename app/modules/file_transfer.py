"""
UTC — Secure File Transfer Module  (Upgraded)
app/modules/file_transfer.py

Changelog v2:
  - File metadata stored in DB with: token, original name, size, upload time,
    expiry timestamp, password hash (optional), download count
  - `list_files_with_metadata()` joins disk + DB so deleted files don't linger
  - `encrypt_and_store()` returns token (short ID) usable in shareable links
  - `decrypt_and_read()` enforces expiry and optional password check
  - `get_file_info()` returns full metadata for a single file by token
  - All envelope format unchanged (AES-256-GCM, self-contained key)
"""

import hashlib
import hmac
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.database import (
    insert_file_transfer, insert_log, execute_write, execute_read, now_utc
)

log = logging.getLogger("utc.file_transfer")

BASE_DIR    = Path(__file__).parent.parent.parent.resolve()
UPLOADS_DIR = BASE_DIR / "uploads"

MAGIC      = b"UTC1"
KEY_SIZE   = 32    # AES-256
NONCE_SIZE = 12    # GCM standard


class FileTransferError(Exception):
    pass


def _ensure_uploads_dir():
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def _init_file_meta_table():
    """Create extended file metadata table if not present."""
    execute_write("""
        CREATE TABLE IF NOT EXISTS file_metadata (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            token           TEXT    NOT NULL UNIQUE,
            stored_name     TEXT    NOT NULL UNIQUE,
            original_name   TEXT    NOT NULL,
            file_size_bytes INTEGER NOT NULL DEFAULT 0,
            checksum_sha256 TEXT,
            upload_time     TEXT    NOT NULL,
            expiry_time     TEXT,
            password_hash   TEXT,
            download_count  INTEGER NOT NULL DEFAULT 0,
            encryption_alg  TEXT    NOT NULL DEFAULT 'AES-256-GCM'
        )
    """)


# Ensure table exists at module import
try:
    _init_file_meta_table()
except Exception:
    pass


# ── Encryption helpers ─────────────────────────────────────────────────────────
def _make_envelope(file_data: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt bytes with AES-256-GCM. Returns (envelope, key, nonce)."""
    key    = os.urandom(KEY_SIZE)
    nonce  = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct     = aesgcm.encrypt(nonce, file_data, None)
    return MAGIC + key + nonce + ct, key, nonce


def _open_envelope(envelope: bytes) -> bytes:
    """Decrypt a UTC envelope. Raises FileTransferError on any failure."""
    min_size = len(MAGIC) + KEY_SIZE + NONCE_SIZE + 16  # 16 = GCM auth tag
    if len(envelope) < min_size:
        raise FileTransferError("Envelope too short — file may be corrupted")
    if envelope[:4] != MAGIC:
        raise FileTransferError("Invalid magic bytes — not a UTC encrypted file")
    offset    = 4
    key       = envelope[offset: offset + KEY_SIZE];   offset += KEY_SIZE
    nonce     = envelope[offset: offset + NONCE_SIZE]; offset += NONCE_SIZE
    ct        = envelope[offset:]
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as exc:
        raise FileTransferError(f"Decryption failed (integrity error): {exc}") from exc


def _hash_password(password: str) -> str:
    """Return a salted SHA-256 hex digest for password storage."""
    salt = secrets.token_hex(16)
    h    = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"{salt}:{h}"


def _check_password(stored_hash: str, provided: str) -> bool:
    """Verify a password against its stored hash."""
    try:
        salt, h = stored_hash.split(":", 1)
        expected = hashlib.sha256(f"{salt}:{provided}".encode()).hexdigest()
        return hmac.compare_digest(expected, h)
    except Exception:
        return False


# ── Public API ─────────────────────────────────────────────────────────────────
def encrypt_and_store(
    file_data:      bytes,
    original_name:  str,
    expiry_hours:   Optional[int] = None,
    expiry_minutes: Optional[int] = None,
    password:       Optional[str] = None,
) -> dict:
    """
    Encrypt file_data and write to uploads directory.
    Returns metadata dict including `token` (shareable short ID).
    """
    _ensure_uploads_dir()
    _init_file_meta_table()

    envelope, _, _ = _make_envelope(file_data)

    stored_name = f"{uuid.uuid4().hex}.utcenc"
    token       = secrets.token_urlsafe(12)   # ~16 chars, URL-safe
    stored_path = UPLOADS_DIR / stored_name

    try:
        stored_path.write_bytes(envelope)
    except OSError as exc:
        raise FileTransferError(f"Write failed: {exc}") from exc

    checksum    = hashlib.sha256(file_data).hexdigest()
    size        = len(file_data)
    upload_time = now_utc()
    expiry_time = None
    total_minutes = (expiry_hours or 0) * 60 + (expiry_minutes or 0)
    if total_minutes > 0:
        expiry_dt   = datetime.now(timezone.utc) + timedelta(minutes=total_minutes)
        expiry_time = expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    pw_hash = _hash_password(password) if password else None

    # Write to extended metadata table
    execute_write(
        """INSERT INTO file_metadata
           (token, stored_name, original_name, file_size_bytes, checksum_sha256,
            upload_time, expiry_time, password_hash, encryption_alg)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (token, stored_name, original_name, size, checksum,
         upload_time, expiry_time, pw_hash, "AES-256-GCM"),
    )

    # Also write to base file_transfers table (for history view)
    insert_file_transfer(
        direction="upload",
        original_name=original_name,
        stored_name=stored_name,
        file_size_bytes=size,
        checksum_sha256=checksum,
        status="ok",
    )

    insert_log("transfer", "info",
        f"UPLOAD: {original_name} ({_fmt_bytes(size)}) → {stored_name} [token={token}]")

    log.info(f"File stored: {original_name} → {stored_name} ({size} bytes, token={token})")

    return {
        "token":           token,
        "stored_name":     stored_name,
        "original_name":   original_name,
        "file_size_bytes": size,
        "checksum_sha256": checksum,
        "encryption_alg":  "AES-256-GCM",
        "upload_time":     upload_time,
        "expiry_time":     expiry_time,
        "password_protected": pw_hash is not None,
        "download_link":   f"/api/files/download/{token}",
    }


def decrypt_and_read(
    identifier: str,       # token (preferred) or stored_name
    password:   Optional[str] = None,
) -> tuple[bytes, str, dict]:
    """
    Decrypt and return file contents.
    Returns (plaintext, original_name, metadata_dict).
    Raises FileTransferError on expiry, wrong password, or integrity failure.
    """
    _ensure_uploads_dir()
    _init_file_meta_table()

    # Look up by token first, fall back to stored_name
    meta = execute_read(
        "SELECT * FROM file_metadata WHERE token=? OR stored_name=? LIMIT 1",
        (identifier, identifier), one=True,
    )

    if not meta:
        raise FileTransferError(f"File not found: {identifier}")

    # Check expiry
    if meta.get("expiry_time"):
        expiry = datetime.fromisoformat(meta["expiry_time"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expiry:
            raise FileTransferError("File has expired and is no longer available")

    # Check password
    if meta.get("password_hash"):
        if not password:
            raise FileTransferError("PASSWORD_REQUIRED")
        if not _check_password(meta["password_hash"], password):
            raise FileTransferError("Incorrect password")

    stored_path = UPLOADS_DIR / Path(meta["stored_name"]).name
    if not stored_path.exists():
        raise FileTransferError("File data not found on disk — may have been deleted")

    try:
        envelope = stored_path.read_bytes()
    except OSError as exc:
        raise FileTransferError(f"Cannot read file: {exc}") from exc

    plaintext = _open_envelope(envelope)

    # Increment download counter
    execute_write(
        "UPDATE file_metadata SET download_count = download_count + 1 WHERE token=?",
        (meta["token"],),
    )

    # Record download in transfer history
    insert_file_transfer(
        direction="download",
        original_name=meta["original_name"],
        stored_name=meta["stored_name"],
        file_size_bytes=len(plaintext),
        status="ok",
    )
    insert_log("transfer", "info",
        f"DOWNLOAD: {meta['original_name']} ({_fmt_bytes(len(plaintext))}) [token={meta['token']}]")

    return plaintext, meta["original_name"], dict(meta)


def get_file_info(identifier: str) -> Optional[dict]:
    """Return metadata for a file by token or stored_name. None if not found."""
    _init_file_meta_table()
    meta = execute_read(
        "SELECT token, original_name, file_size_bytes, upload_time, expiry_time, "
        "download_count, encryption_alg, "
        "CASE WHEN password_hash IS NOT NULL THEN 1 ELSE 0 END as password_protected "
        "FROM file_metadata WHERE token=? OR stored_name=? LIMIT 1",
        (identifier, identifier), one=True,
    )
    if not meta:
        return None
    m = dict(meta)
    m["download_link"] = f"/api/files/download/{m['token']}"
    # Check expiry status
    if m.get("expiry_time"):
        expiry = datetime.fromisoformat(m["expiry_time"].replace("Z", "+00:00"))
        m["expired"] = datetime.now(timezone.utc) > expiry
    else:
        m["expired"] = False
    return m


def list_files_with_metadata() -> list[dict]:
    """
    Return all stored files with full metadata from DB.
    Only includes files that still exist on disk.
    """
    _ensure_uploads_dir()
    _init_file_meta_table()

    # Get all records from metadata table
    rows = execute_read(
        "SELECT token, original_name, file_size_bytes, upload_time, expiry_time, "
        "download_count, encryption_alg, stored_name, "
        "CASE WHEN password_hash IS NOT NULL THEN 1 ELSE 0 END as password_protected "
        "FROM file_metadata ORDER BY upload_time DESC"
    )

    result = []
    now    = datetime.now(timezone.utc)
    for row in rows:
        stored_path = UPLOADS_DIR / Path(row["stored_name"]).name
        if not stored_path.exists():
            continue   # File was deleted from disk — skip

        m = dict(row)
        m["download_link"] = f"/api/files/download/{m['token']}"
        # Expiry status
        if m.get("expiry_time"):
            expiry    = datetime.fromisoformat(m["expiry_time"].replace("Z", "+00:00"))
            m["expired"] = now > expiry
        else:
            m["expired"] = False
        result.append(m)

    return result


def delete_stored_file(identifier: str) -> bool:
    """Securely erase a file (zero-overwrite) and remove its metadata."""
    _init_file_meta_table()

    meta = execute_read(
        "SELECT stored_name FROM file_metadata WHERE token=? OR stored_name=? LIMIT 1",
        (identifier, identifier), one=True,
    )
    # Fallback: old files stored without metadata entry
    if not meta:
        safe_name   = Path(identifier).name
        stored_path = UPLOADS_DIR / safe_name
    else:
        safe_name   = meta["stored_name"]
        stored_path = UPLOADS_DIR / Path(safe_name).name

    deleted = False
    if stored_path.exists():
        try:
            size = stored_path.stat().st_size
            with open(stored_path, "wb") as fh:
                fh.write(b"\x00" * size)
            stored_path.unlink()
            deleted = True
        except OSError as exc:
            log.error(f"Delete failed ({safe_name}): {exc}")
            return False

    if meta:
        execute_write("DELETE FROM file_metadata WHERE stored_name=?", (safe_name,))

    if deleted:
        insert_log("transfer", "info", f"DELETED: {safe_name}")
    return deleted


def _fmt_bytes(b: int) -> str:
    if b >= 1_048_576: return f"{b/1_048_576:.1f} MB"
    if b >= 1024:      return f"{b/1024:.1f} KB"
    return f"{b} B"
