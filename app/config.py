"""
UTC — Configuration Manager
app/config.py

Provides a thread-safe singleton for reading and writing settings.json.
All modules import get_settings() to access the live config dict.
Changes written via save_settings() are immediately reflected in memory.
"""

import json
import logging
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger("utc.config")

BASE_DIR    = Path(__file__).parent.parent.resolve()
CONFIG_FILE = BASE_DIR / "config" / "settings.json"

# ── Thread-safe singleton ──────────────────────────────────────────────────────
_lock:     threading.RLock = threading.RLock()
_settings: dict | None     = None


def get_settings() -> dict:
    """
    Return the current settings dict (loaded from disk on first call).
    Subsequent calls return the cached in-memory copy.
    """
    global _settings
    with _lock:
        if _settings is None:
            _settings = _load()
        return _settings


def save_settings(new_settings: dict) -> bool:
    """
    Persist new_settings to disk and update the in-memory cache.
    Returns True on success, False on error.
    """
    global _settings
    with _lock:
        try:
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(new_settings, f, indent=2)
            _settings = new_settings
            log.info("Settings saved.")
            return True
        except Exception as exc:
            log.error(f"Failed to save settings: {exc}")
            return False


def update_setting(key_path: str, value: Any) -> bool:
    """
    Update a single nested key using dot notation.
    Example: update_setting("ids.dos_threshold", 300)

    Returns True on success.
    """
    settings = get_settings()
    with _lock:
        keys = key_path.split(".")
        target = settings
        try:
            for k in keys[:-1]:
                target = target[k]
            target[keys[-1]] = value
            return save_settings(settings)
        except (KeyError, TypeError) as exc:
            log.error(f"Invalid key path '{key_path}': {exc}")
            return False


def reload_settings() -> dict:
    """Force reload settings from disk (discards in-memory cache)."""
    global _settings
    with _lock:
        _settings = None
        return get_settings()


# ── Internal loader ────────────────────────────────────────────────────────────
def _load() -> dict:
    """Load settings from disk. Falls back to empty dict on error."""
    if not CONFIG_FILE.exists():
        log.warning(f"Config file not found: {CONFIG_FILE}. Using empty config.")
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        log.info(f"Config loaded from {CONFIG_FILE}")
        return data
    except json.JSONDecodeError as exc:
        log.error(f"Invalid JSON in config file: {exc}. Using empty config.")
        return {}
    except Exception as exc:
        log.error(f"Unexpected error loading config: {exc}. Using empty config.")
        return {}
