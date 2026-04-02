"""
UTC — Log Monitor
app/modules/log_monitor.py

Monitors all UTC log files in real time by:
  1. Tailing each log file for new lines
  2. Checking each line against alert keywords
  3. Persisting flagged entries to DB
  4. Broadcasting new entries to dashboard via WebSocket

Runs as a daemon thread. Thread-safe and auto-recovers from file errors.
"""

import asyncio
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings
from app.database import insert_log, get_log_stats
from app.ws_manager import WebSocketManager

log = logging.getLogger("utc.log_monitor")

BASE_DIR  = Path(__file__).parent.parent.parent.resolve()
LOGS_DIR  = BASE_DIR / "logs"

# Log files to tail — (path, source_label)
LOG_FILES = [
    (LOGS_DIR / "network.log",  "network"),
    (LOGS_DIR / "ids.log",      "ids"),
    (LOGS_DIR / "system.log",   "system"),
    (LOGS_DIR / "transfer.log", "transfer"),
]

# Level detection patterns
LEVEL_RE = re.compile(
    r"\b(DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL)\b", re.IGNORECASE
)


class LogMonitor:
    """
    Tails multiple log files and streams new entries to the dashboard.
    """

    def __init__(self, ws_manager: WebSocketManager):
        self.ws       = ws_manager
        self._running = False
        self._thread: threading.Thread | None = None
        self._loop:   asyncio.AbstractEventLoop | None = None
        self._cfg:    dict = {}
        # file path → current seek position
        self._positions: dict[Path, int] = {}
        # Stats
        self._total_lines = 0
        self._flagged_lines = 0

    def start(self, loop: asyncio.AbstractEventLoop):
        self._loop   = loop
        self._cfg    = get_settings().get("log_monitor", {})
        self._running = True

        # Ensure all log files exist
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        for path, _ in LOG_FILES:
            path.touch(exist_ok=True)

        # Seek to end of each file (don't re-read history on startup)
        for path, _ in LOG_FILES:
            try:
                self._positions[path] = path.stat().st_size
            except OSError:
                self._positions[path] = 0

        self._thread = threading.Thread(
            target=self._tail_loop,
            name="log-monitor",
            daemon=True,
        )
        self._thread.start()
        log.info("Log monitor started — tailing %d files.", len(LOG_FILES))

    def stop(self):
        self._running = False
        log.info("Log monitor stopped.")

    # ── File-tail Loop ────────────────────────────────────────────────────────
    def _tail_loop(self):
        interval = float(self._cfg.get("check_interval_sec", 2))
        keywords = [k.lower() for k in self._cfg.get(
            "alert_keywords",
            ["error", "critical", "unauthorized", "failed", "denied", "attack", "blocked"]
        )]

        while self._running:
            for path, source in LOG_FILES:
                self._tail_file(path, source, keywords)
            time.sleep(interval)

    def _tail_file(self, path: Path, source: str, keywords: list):
        try:
            current_size = path.stat().st_size
        except OSError:
            return

        prev_pos = self._positions.get(path, 0)

        # File was truncated / rotated
        if current_size < prev_pos:
            self._positions[path] = 0
            prev_pos = 0

        if current_size == prev_pos:
            return  # nothing new

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(prev_pos)
                new_content = fh.read()
                self._positions[path] = fh.tell()
        except OSError as exc:
            log.debug(f"Log tail error ({path.name}): {exc}")
            return

        for raw_line in new_content.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            self._process_line(line, source, keywords)

    def _process_line(self, line: str, source: str, keywords: list):
        self._total_lines += 1
        level   = self._detect_level(line)
        flagged = any(kw in line.lower() for kw in keywords)

        if flagged:
            self._flagged_lines += 1

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Persist to DB
        try:
            insert_log(source, level, line[:500], flagged=flagged)
        except Exception as exc:
            log.debug(f"Log DB insert error: {exc}")

        # Broadcast via WebSocket
        entry = {
            "timestamp": ts,
            "source":    source,
            "level":     level,
            "message":   line[:500],
            "flagged":   flagged,
        }
        if self._loop and not self._loop.is_closed():
            asyncio.run_coroutine_threadsafe(
                self.ws.emit_log_entry(entry),
                self._loop,
            )

    @staticmethod
    def _detect_level(line: str) -> str:
        m = LEVEL_RE.search(line)
        if not m:
            return "info"
        raw = m.group(1).upper()
        if raw in ("WARNING", "WARN"):    return "warning"
        if raw in ("CRITICAL", "FATAL"):  return "critical"
        return raw.lower()

    def get_stats(self) -> dict:
        db_stats = get_log_stats()
        return {
            "total_lines":   self._total_lines,
            "flagged_lines": self._flagged_lines,
            "db_stats":      db_stats,
            "files_watched": len(LOG_FILES),
        }

    # ── Public helper: write a line to a specific log file ───────────────────
    @staticmethod
    def write(log_file: str, message: str):
        """Write a formatted log line to the specified UTC log file."""
        path = LOGS_DIR / f"{log_file}.log"
        ts   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(f"{ts} {message}\n")
        except OSError as exc:
            log.debug(f"Log write error ({path.name}): {exc}")


# ── Singleton ─────────────────────────────────────────────────────────────────
_log_monitor: LogMonitor | None = None


def get_log_monitor() -> LogMonitor | None:
    return _log_monitor


def create_log_monitor(ws_manager: WebSocketManager) -> LogMonitor:
    global _log_monitor
    _log_monitor = LogMonitor(ws_manager)
    return _log_monitor
