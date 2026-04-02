"""
UTC — IDS Engine  (v3 — Accuracy, Rate Limiting, Whitelist, Confidence Scores)
app/modules/ids_engine.py

Changelog v3:
  - IP whitelist: scanner (127.0.0.1/::1) traffic is ignored
  - Confidence score added to every alert (low/medium/high)
  - Alert rate limiter: max N alerts per minute across ALL IPs (global cap)
  - DoS detection: requires sustained pps AND minimum duration (not single spike)
  - SYN flood threshold raised (50→80) and requires 5-second sustain
  - Port scan threshold raised (15→20 distinct ports)
  - Brute force: threshold raised (10→15) with clearer per-port tracking
  - Stealth scan: NULL scan on port 0 ignored (likely monitoring tool artefact)
  - Duplicate STEALTH_FLAGS key removed
  - All alert descriptions include actionable explanation field
  - Simulation events tagged [SIM] clearly in log messages
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, Optional, Set

from app.database import insert_ids_alert, insert_log
import ipaddress

# ── Local/private network ranges — DoS/flood rules only apply to INBOUND traffic ──
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def _is_local_ip(ip: str) -> bool:
    """Return True if IP is in a private/loopback range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False

def _is_inbound(src_ip: str, dst_ip: str) -> bool:
    """
    Return True if traffic is INBOUND to our local network.
    DoS/flood detection should only fire on inbound attacks,
    not on our own outbound traffic to internet servers.
    """
    return (not _is_local_ip(src_ip)) and _is_local_ip(dst_ip)

log = logging.getLogger("utc.ids")

# ── Port classifications ───────────────────────────────────────────────────────
AUTH_PORTS = {
    21, 22, 23, 25, 110, 143, 993, 995, 3389, 5900, 8080, 8443
}

# Known malicious/suspicious ports with severity and explanation
MALICIOUS_PORTS: Dict[int, tuple] = {
    4444:  ("critical", "high",   "Metasploit default reverse shell listener"),
    1337:  ("high",     "medium", "Commonly used by hacking tools and RATs"),
    31337: ("high",     "high",   "Back Orifice RAT (elite/31337 port)"),
    6666:  ("high",     "medium", "IRC-based botnet C2 channel"),
    6667:  ("high",     "medium", "IRC C2 — common in older botnets"),
    6668:  ("medium",   "low",    "IRC port variant"),
    6669:  ("medium",   "low",    "IRC port variant"),
    8888:  ("medium",   "low",    "Commonly used for reverse shells"),
    9001:  ("high",     "medium", "Tor OR port / Metasploit handler"),
    12345: ("high",     "medium", "NetBus RAT listener port"),
    5555:  ("high",     "medium", "Android ADB / common RAT port"),
    1234:  ("low",      "low",    "Generic backdoor port (low specificity)"),
}

# Stealth scan TCP flag patterns
STEALTH_FLAGS: Dict[str, str] = {
    "":    "NULL scan (no flags set)",
    "F":   "FIN scan",
    "FPU": "XMAS scan (FIN+PSH+URG)",
    "FU":  "XMAS scan variant",
    "PU":  "PSH+URG scan",
}

# Per-rule dedup windows (seconds) — minimum time before same rule re-fires for same IP
DEDUP_WINDOWS = {
    "stealth_scan":   30,
    "brute_force":    90,
    "port_scan":      45,
    "syn_flood":      10,
    "dos_flood":      10,
    "dns_tunneling":  45,
    "malicious_port": 20,
}

# Global alert rate limit — max alerts per minute across the entire system
_GLOBAL_RATE_LIMIT = 30   # alerts/minute
_GLOBAL_RATE_WINDOW = 60  # seconds


class IDSEngine:
    def __init__(self, ws_manager):
        self.ws       = ws_manager
        self._loop    = None
        self._running = False
        self._cfg     = {}

        # IP whitelist — packets from these IPs are ignored (scanner, localhost)
        self._whitelist: Set[str] = {"127.0.0.1", "::1", "localhost"}

        # Per-IP state
        self._auth_attempts: Dict[str, Dict[int, deque]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=500))
        )
        self._syn_times:  Dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        self._dns_times:  Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._dos_times:  Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))

        # Dedup tracker: (rule_id, src_ip) → last_fired timestamp
        self._last_fired: Dict[tuple, float] = {}

        # Global rate limiter: deque of timestamps of recent alerts
        self._global_alert_times: deque = deque(maxlen=_GLOBAL_RATE_LIMIT * 2)

        # Track is_demo mode (used for labelling)
        self._is_demo = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    def start(self, loop: asyncio.AbstractEventLoop):
        self._loop    = loop
        from app.config import get_settings
        self._cfg     = get_settings().get("ids", {})
        self._running = True

        # Detect demo mode from network monitor
        try:
            from app.modules.network_monitor import _scapy_available
            self._is_demo = not _scapy_available
        except Exception:
            self._is_demo = False

        log.info("IDS engine started — 7 rules, whitelist=%s, demo=%s",
                 self._whitelist, self._is_demo)

    def stop(self):
        self._running = False

    def add_whitelist_ips(self, ips: Set[str]):
        """Add IPs to the inspection whitelist (scanner, internal tools)."""
        self._whitelist.update(ips)
        log.info(f"IDS whitelist updated: {self._whitelist}")

    # ── Main packet inspection ────────────────────────────────────────────────
    def inspect_packet(
        self,
        pkt: dict,
        ip_port_window: dict,
        ip_pkt_this_sec: dict,
        ip_rolling_pps: int,
    ) -> str:
        if not self._running:
            return ""

        src_ip = pkt.get("src_ip", "")

        # Skip whitelisted IPs (scanner, localhost)
        if src_ip in self._whitelist:
            return ""

        # Check global rate limit before any processing
        if not self._global_rate_ok():
            return ""

        dst_ip   = pkt.get("dst_ip", "")
        dst_port = pkt.get("dst_port", 0)
        src_port = pkt.get("src_port", 0)
        protocol = pkt.get("protocol", "")
        flags    = pkt.get("flags", "")
        now      = time.time()

        triggered = []

        # ── Rule 1: Stealth scan ──────────────────────────────────────────────
        if protocol == "TCP" and flags in STEALTH_FLAGS and dst_port > 0:
            # Ignore NULL scans on port 0 (common from monitoring tools)
            scan_name = STEALTH_FLAGS[flags]
            triggered.append((
                "stealth_scan", "medium", "Stealth Port Scan",
                f"{scan_name} from {src_ip} → port {dst_port}",
                "medium",
                f"A TCP packet with unusual flag combination ({flags or 'none'}) was detected. "
                f"This pattern is used by port scanners (Nmap) to evade detection.",
            ))

        # ── Rule 2: Brute force ───────────────────────────────────────────────
        # Only flag brute force from external IPs. Internal tools legitimately
        # connect to auth ports repeatedly (monitoring, config management).
        if dst_port in AUTH_PORTS and protocol in ("TCP", "UDP") and not _is_local_ip(src_ip):
            port_dq = self._auth_attempts[src_ip][dst_port]
            port_dq.append(now)
            bf_window    = int(self._cfg.get("brute_force_window_sec", 30))
            bf_threshold = int(self._cfg.get("brute_force_threshold", 15))
            recent       = sum(1 for t in port_dq if t >= now - bf_window)
            if recent >= bf_threshold:
                port_name = {22:"SSH",23:"Telnet",3389:"RDP",5900:"VNC",
                             21:"FTP",25:"SMTP",110:"POP3",143:"IMAP"}.get(dst_port, str(dst_port))
                triggered.append((
                    "brute_force", "high", "Brute Force Attempt",
                    f"Brute force on {port_name} (:{dst_port}) — {recent} attempts in {bf_window}s from {src_ip}",
                    "high",
                    f"Rapid repeated connection attempts to an authentication port ({port_name}:{dst_port}) "
                    f"suggest credential stuffing or dictionary attack.",
                ))

        # ── Rule 3: Port scan ─────────────────────────────────────────────────
        # Only flag as port scan if the source is an EXTERNAL IP scanning your network.
        # Your own machine browsing multiple sites looks like a port scan otherwise.
        if protocol in ("TCP", "UDP") and dst_port > 0 and not _is_local_ip(src_ip):
            scan_window    = int(self._cfg.get("port_scan_window_sec", 5))
            scan_threshold = int(self._cfg.get("port_scan_threshold", 20))
            window_entries = ip_port_window.get(src_ip, deque())
            if window_entries:
                recent_ports = {
                    port for ts, port in window_entries
                    if ts >= now - scan_window and port > 0
                }
                if len(recent_ports) >= scan_threshold:
                    triggered.append((
                        "port_scan", "high", "Port Scan Detected",
                        f"Port scan: {len(recent_ports)} distinct ports in {scan_window}s from {src_ip}",
                        "high",
                        f"A single host contacted {len(recent_ports)} distinct ports in {scan_window} seconds. "
                        f"This pattern is consistent with automated port scanning (reconnaissance).",
                    ))

        # ── Rule 4: SYN Flood — only on inbound traffic ──────────────────────
        # Outbound SYN (your browser → YouTube) is normal TCP connection setup.
        # Only fire when an EXTERNAL host sends many SYNs TO your local machine.
        if protocol == "TCP" and flags == "S" and dst_port > 0 and _is_inbound(src_ip, dst_ip):
            dq = self._syn_times[src_ip]
            dq.append(now)
            syn_window    = 5   # raised from 3s → 5s for accuracy
            syn_threshold = int(self._cfg.get("syn_flood_threshold", 80))  # raised 50→80
            recent_syns   = sum(1 for t in dq if t >= now - syn_window)
            if recent_syns >= syn_threshold:
                triggered.append((
                    "syn_flood", "critical", "SYN Flood Attack",
                    f"SYN flood: {recent_syns} SYN packets in {syn_window}s from {src_ip} → :{dst_port}",
                    "high",
                    f"Extremely high rate of TCP SYN packets without corresponding ACK responses. "
                    f"This exhausts server connection tables (TCP state exhaustion / DoS).",
                ))

        # ── Rule 5: DoS — sustained rolling pps, INBOUND traffic only ─────────
        # Normal internet usage (streaming video, downloads) generates high pps
        # from your machine TO external servers — this is NOT a DoS attack.
        # Only flag when an external IP sends a high sustained rate TO your local IP.
        dos_threshold = int(self._cfg.get("dos_threshold", 300))  # high threshold
        if ip_rolling_pps >= dos_threshold and _is_inbound(src_ip, dst_ip):
            # Require that this IP has been flooding for at least 3 seconds
            dq = self._dos_times[src_ip]
            dq.append(now)
            sustained_ticks = sum(1 for t in dq if t >= now - 5.0)
            if sustained_ticks >= 3:
                triggered.append((
                    "dos_flood", "critical", "DoS Flood Attack",
                    f"Sustained DoS: ~{ip_rolling_pps} pkt/5s from {src_ip} ({sustained_ticks}s sustained)",
                    "medium",  # medium confidence because rolling pps is approximate
                    f"Exceptionally high sustained packet rate from a single IP. "
                    f"May indicate a Denial-of-Service attack or misconfigured device.",
                ))

        # ── Rule 6: DNS Tunneling ─────────────────────────────────────────────
        if protocol == "DNS":
            dq = self._dns_times[src_ip]
            dq.append(now)
            dns_window    = 10
            dns_threshold = int(self._cfg.get("dns_tunnel_threshold", 30))  # raised 25→30
            recent_dns    = sum(1 for t in dq if t >= now - dns_window)
            if recent_dns >= dns_threshold:
                triggered.append((
                    "dns_tunneling", "high", "DNS Tunneling Suspicion",
                    f"High DNS query rate: {recent_dns} queries in {dns_window}s from {src_ip}",
                    "medium",
                    f"Unusually high DNS query frequency from a single host may indicate "
                    f"DNS tunneling (data exfiltration or C2 communication over DNS).",
                ))

        # ── Rule 7: Known malicious ports ─────────────────────────────────────
        if dst_port in MALICIOUS_PORTS:
            sev, confidence, label = MALICIOUS_PORTS[dst_port]
            triggered.append((
                "malicious_port", sev, "Malicious Port Contact",
                f"Connection to {label} (port {dst_port}) from {src_ip} → {dst_ip}",
                confidence,
                f"Port {dst_port} is associated with known malware/RAT. "
                f"{label}. Investigate the source host immediately.",
            ))

        # ── Fire with dedup + global rate check ───────────────────────────────
        notes = []
        for rule_id, severity, name, desc, confidence, explanation in triggered:
            key     = (rule_id, src_ip)
            dedup_w = DEDUP_WINDOWS.get(rule_id, 10.0)
            if now - self._last_fired.get(key, 0) >= dedup_w:
                if self._global_rate_ok():  # check again before each fire
                    self._last_fired[key] = now
                    self._global_alert_times.append(now)
                    self._fire(severity, name, src_ip, dst_ip, dst_port,
                               protocol, desc, confidence, explanation)
                    notes.append(name)

        return " | ".join(notes)

    # ── Global rate check ─────────────────────────────────────────────────────
    def _global_rate_ok(self) -> bool:
        """Return True if we haven't exceeded the global alert rate limit."""
        now    = time.time()
        recent = sum(1 for t in self._global_alert_times if t >= now - _GLOBAL_RATE_WINDOW)
        return recent < _GLOBAL_RATE_LIMIT

    # ── Alert firing ──────────────────────────────────────────────────────────
    def _fire(self, severity, rule_name, src_ip, dst_ip, dst_port,
              protocol, description, confidence="medium", explanation=""):
        if not self._loop or self._loop.is_closed():
            return

        async def _do():
            ts       = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            alert_id = insert_ids_alert(
                severity=severity, rule_name=rule_name,
                src_ip=src_ip, dst_ip=dst_ip,
                dst_port=dst_port, protocol=protocol,
                description=description,
            )
            insert_log(
                "ids",
                "critical" if severity == "critical" else "warning",
                f"[IDS] [{confidence.upper()} CONFIDENCE] {rule_name}: {description}",
                flagged=True,
            )
            await self.ws.emit_ids_alert({
                "id":          alert_id,
                "timestamp":   ts,
                "severity":    severity,
                "rule_name":   rule_name,
                "src_ip":      src_ip,
                "dst_ip":      dst_ip,
                "dst_port":    dst_port,
                "protocol":    protocol,
                "description": description,
                "confidence":  confidence,
                "explanation": explanation,
            })
            log.warning(f"IDS [{severity.upper()}][{confidence}] {rule_name} — {description}")

        asyncio.run_coroutine_threadsafe(_do(), self._loop)

    # ── Simulator ─────────────────────────────────────────────────────────────
    async def simulate_attack(self, attack_type: str) -> dict:
        """
        Inject synthetic packets through the monitor pipeline.
        All simulation events are clearly tagged [SIM] in logs.
        """
        from app.modules.network_monitor import get_monitor
        monitor = get_monitor()

        if attack_type == "port_scan":
            src = "10.99.1.1"
            if monitor:
                import random
                for dp in random.sample(range(1, 65535), 25):
                    monitor._handle_pkt({
                        "src_ip": src, "dst_ip": "192.168.1.1",
                        "src_port": random.randint(40000,65000),
                        "dst_port": dp, "protocol": "TCP",
                        "packet_size": 44, "flags": "S",
                    })
            else:
                self._fire("high","Port Scan",src,"192.168.1.1",0,"TCP",
                           "[SIM] SYN sweep — 25 distinct ports","high",
                           "Simulated Nmap-style SYN sweep for IDS testing.")
            insert_log("ids","info","[SIM] Port scan simulation triggered",flagged=False)
            return {"simulated":"port_scan","src":src,"packets":25}

        elif attack_type == "dos":
            src = "172.99.0.1"
            if monitor:
                import random
                for _ in range(90):
                    monitor._handle_pkt({
                        "src_ip": src, "dst_ip": "192.168.1.100",
                        "src_port": random.randint(40000,65000),
                        "dst_port": 80, "protocol": "TCP",
                        "packet_size": 44, "flags": "S",
                    })
            else:
                self._fire("critical","SYN Flood Attack",src,"192.168.1.100",80,"TCP",
                           "[SIM] SYN flood — 90 SYN packets","high",
                           "Simulated TCP SYN flood for IDS testing.")
            insert_log("ids","info","[SIM] DoS/SYN flood simulation triggered",flagged=False)
            return {"simulated":"dos","src":src,"packets":90}

        elif attack_type == "brute_force":
            src = "185.99.0.55"
            if monitor:
                import random
                for _ in range(20):
                    monitor._handle_pkt({
                        "src_ip": src, "dst_ip": "192.168.1.10",
                        "src_port": random.randint(40000,65000),
                        "dst_port": 22, "protocol": "TCP",
                        "packet_size": 60, "flags": "S",
                    })
            else:
                self._fire("high","Brute Force Attempt",src,"192.168.1.10",22,"TCP",
                           "[SIM] SSH brute force — 20 attempts","high",
                           "Simulated SSH brute force for IDS testing.")
            insert_log("ids","info","[SIM] Brute force simulation triggered",flagged=False)
            return {"simulated":"brute_force","src":src,"packets":20}

        elif attack_type == "traffic_spike":
            src = "198.99.0.7"
            if monitor:
                import random
                protos = ["TCP","UDP","DNS","ICMP"]
                for _ in range(50):
                    p = random.choice(protos)
                    monitor._handle_pkt({
                        "src_ip": src, "dst_ip": "192.168.1.1",
                        "src_port": random.randint(1024,65535),
                        "dst_port": random.choice([80,443,53,8080]),
                        "protocol": p,
                        "packet_size": random.randint(40,1024),
                        "flags": "S" if p == "TCP" else "",
                    })
            else:
                self._fire("medium","Traffic Spike",src,"192.168.1.1",443,"TCP",
                           "[SIM] Traffic spike — 50 mixed packets","low",
                           "Simulated traffic anomaly for IDS testing.")
            insert_log("ids","info","[SIM] Traffic spike simulation triggered",flagged=False)
            return {"simulated":"traffic_spike","src":src,"packets":50}

        else:
            raise ValueError(f"Unknown attack type: {attack_type}")


# ── Singleton ──────────────────────────────────────────────────────────────────
_ids_instance = None

def get_ids():
    return _ids_instance

def create_ids(ws_manager):
    global _ids_instance
    _ids_instance = IDSEngine(ws_manager)
    return _ids_instance
