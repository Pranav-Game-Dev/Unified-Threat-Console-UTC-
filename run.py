"""
UTC - Unified Threat Console
Master Launcher

Handles:
  1. Auto-request admin privileges (Windows UAC)
  2. Bootstrap folders, config, and database
  3. Start FastAPI backend via uvicorn
  4. Open web dashboard in default browser
"""

import sys
import os
import time
import subprocess
import threading
import webbrowser
import ctypes
import json
import logging
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()
CONFIG_DIR  = BASE_DIR / "config"
LOGS_DIR    = BASE_DIR / "logs"
UPLOADS_DIR = BASE_DIR / "uploads"
DATA_DIR    = BASE_DIR / "data"

REQUIRED_DIRS = [CONFIG_DIR, LOGS_DIR, UPLOADS_DIR, DATA_DIR]

CONFIG_FILE = CONFIG_DIR / "settings.json"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DASHBOARD_URL = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"

# ── Logging Setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [LAUNCHER] %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("utc.launcher")


# ── Admin Privilege Check / Escalation (Windows) ──────────────────────────────
def is_admin() -> bool:
    """Return True if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        # Non-Windows or ctypes unavailable — assume elevated (Linux/macOS)
        return os.getuid() == 0 if hasattr(os, "getuid") else True


def request_admin_elevation():
    """
    Re-launch this script with UAC elevation on Windows.
    Uses ShellExecuteW with 'runas' verb to trigger the UAC prompt.
    """
    log.info("Requesting administrator privileges via UAC...")
    try:
        script = str(Path(sys.argv[0]).resolve())
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,       # hwnd
            "runas",    # verb — triggers UAC
            sys.executable,
            f'"{script}" {params}',
            str(BASE_DIR),
            1,          # SW_SHOWNORMAL
        )
        if ret <= 32:
            log.error(f"UAC elevation failed (ShellExecuteW returned {ret}).")
            sys.exit(1)
        log.info("UAC prompt accepted. New elevated process started.")
        sys.exit(0)     # original (non-elevated) process exits cleanly
    except Exception as exc:
        log.error(f"Could not request elevation: {exc}")
        sys.exit(1)


def ensure_admin():
    """
    Ensure the process is running as admin.
    On Windows: prompt via UAC if not already elevated.
    On Linux/macOS: warn but continue (user may run with sudo manually).
    """
    if sys.platform == "win32":
        if not is_admin():
            print("\n" + "═" * 60)
            print("  UTC requires Administrator privileges for:")
            print("  • Network packet capture (Scapy / Npcap)")
            print("  • Raw socket access for IDS engine")
            print("  A UAC prompt will appear. Please click [Yes].")
            print("═" * 60 + "\n")
            request_admin_elevation()
        else:
            log.info("Running with Administrator privileges. ✓")
    else:
        if not is_admin():
            log.warning(
                "Not running as root. Some features (packet capture) may be "
                "limited. Consider: sudo python run.py"
            )
        else:
            log.info("Running as root. ✓")


# ── Bootstrap Directories & Default Config ────────────────────────────────────
DEFAULT_SETTINGS = {
    "server": {
        "host": DEFAULT_HOST,
        "port": DEFAULT_PORT,
        "debug": False,
        "log_level": "info",
    },
    "network_monitor": {
        "enabled": True,
        "interface": None,          # None = auto-select
        "packet_buffer": 500,
        "capture_filter": "",       # BPF filter string
        "traffic_spike_threshold": 100,   # packets/sec
        "suspicious_ports": [22, 23, 3389, 4444, 5900, 6666, 8080],
    },
    "ids": {
        "enabled": True,
        "port_scan_threshold": 15,      # distinct ports in window
        "port_scan_window_sec": 5,
        "dos_threshold": 150,           # packets/5s from single IP (rolling)
        "brute_force_threshold": 10,    # failed auths in window
        "brute_force_window_sec": 30,
        "syn_flood_threshold": 50,      # SYN packets in 3s window
        "dns_tunnel_threshold": 25,     # DNS queries in 10s window
    },
    "vuln_scanner": {
        "timeout_sec": 10,
        "max_redirects": 3,
        "user_agent": "UTC-VulnScanner/1.0",
    },
    "log_monitor": {
        "enabled": True,
        "check_interval_sec": 5,
        "max_log_lines": 1000,
        "alert_keywords": ["error", "critical", "unauthorized", "failed", "denied"],
    },
    "file_transfer": {
        "max_file_size_mb": 100,
        "allowed_extensions": [],   # empty = all allowed
        "encryption": "AES-256-GCM",
    },
    "alerts": {
        "console": True,
        "email": False,
        "email_smtp": "",
        "email_port": 587,
        "email_user": "",
        "email_password": "",
        "email_to": "",
    },
}


def bootstrap_directories():
    """Create all required directories if they don't exist."""
    for d in REQUIRED_DIRS:
        d.mkdir(parents=True, exist_ok=True)
    log.info(f"Directories verified: {', '.join(d.name for d in REQUIRED_DIRS)}")


def bootstrap_config():
    """Create default settings.json if it doesn't exist."""
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_SETTINGS, f, indent=2)
        log.info(f"Default config created: {CONFIG_FILE}")
    else:
        # Merge any missing keys from defaults without overwriting user settings
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
            merged = _deep_merge(DEFAULT_SETTINGS, existing)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(merged, f, indent=2)
        except Exception as exc:
            log.warning(f"Could not merge config (will use existing): {exc}")
        log.info(f"Config loaded: {CONFIG_FILE}")


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, preserving existing user values."""
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def bootstrap_app_modules():
    """Create __init__.py files so app/ is a proper Python package."""
    for pkg_dir in [BASE_DIR / "app", BASE_DIR / "app" / "modules", BASE_DIR / "app" / "routers"]:
        init = pkg_dir / "__init__.py"
        if not init.exists():
            init.write_text('"""UTC package."""\n')


# ── Server Startup ────────────────────────────────────────────────────────────
_server_ready = threading.Event()


def _check_server_ready(host: str, port: int, timeout: float = 30.0):
    """
    Poll the server health endpoint until it responds or timeout is reached.
    Sets _server_ready event when the server is up.
    """
    import urllib.request
    import urllib.error

    deadline = time.time() + timeout
    url = f"http://{host}:{port}/api/health"

    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    _server_ready.set()
                    return
        except Exception:
            pass
        time.sleep(0.4)

    log.warning("Server health check timed out. Opening browser anyway...")
    _server_ready.set()


def start_server(host: str, port: int):
    """Launch uvicorn in a subprocess."""
    cmd = [
        sys.executable, "-m", "uvicorn",
        "app.main:app",
        "--host", host,
        "--port", str(port),
        "--log-level", "info",
        "--no-access-log",
    ]
    log.info(f"Starting FastAPI server → http://{host}:{port}")
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(BASE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        # Stream server logs to our console
        def _stream():
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    print(f"  [SERVER] {line}")

        threading.Thread(target=_stream, daemon=True).start()
        return proc

    except FileNotFoundError:
        log.error(
            "uvicorn not found. Install dependencies first:\n"
            "  pip install -r requirements.txt"
        )
        sys.exit(1)


def open_browser(url: str):
    """Open the dashboard URL in the default browser after server is ready."""
    log.info("Waiting for server to be ready...")
    _server_ready.wait()
    time.sleep(0.3)     # small buffer for routing to initialise
    log.info(f"Opening dashboard → {url}")
    webbrowser.open(url)


# ── Entry Point ───────────────────────────────────────────────────────────────
def main():
    print("\n" + "═" * 60)
    print("  UTC — Unified Threat Console")
    print("  Integrated Cyber Security Monitoring Platform")
    print("═" * 60)

    # Step 1: Admin check
    ensure_admin()

    # Step 2: Bootstrap
    bootstrap_directories()
    bootstrap_config()
    bootstrap_app_modules()

    # Step 3: Read port from config
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        host = cfg["server"]["host"]
        port = cfg["server"]["port"]
    except Exception:
        host, port = DEFAULT_HOST, DEFAULT_PORT

    dashboard_url = f"http://{host}:{port}"

    # Step 4: Start health-check watcher (background)
    threading.Thread(
        target=_check_server_ready,
        args=(host, port),
        daemon=True,
    ).start()

    # Step 5: Open browser (background — waits for server ready)
    threading.Thread(
        target=open_browser,
        args=(dashboard_url,),
        daemon=True,
    ).start()

    # Step 6: Start server (blocking — keeps process alive)
    proc = start_server(host, port)

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[UTC] Shutting down...")
        proc.terminate()
        proc.wait()
        print("[UTC] Server stopped. Goodbye.\n")


if __name__ == "__main__":
    main()
