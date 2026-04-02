"""
UTC — Network Traffic Monitor  (Upgraded)
app/modules/network_monitor.py

Changelog v2:
  - Full protocol classification: TCP, UDP, DNS, ICMP, ARP, OTHER
  - Per-protocol pps counters broadcast every second (multi-line chart support)
  - Per-protocol cumulative totals for donut chart
  - Fixed: ip_pkt_count not cleared mid-inspection; IDS receives stable snapshot
  - Fixed: DNS correctly detected on both TCP/53 and UDP/53
  - Fixed: IPv6 packets handled (no crash on non-IPv4 capture)
  - Added: sustained 5-second rolling pps per IP for DoS/flood detection
  - Demo mode: realistic protocol mix with periodic suspicious burst
"""

import asyncio
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from app.config import get_settings
from app.database import insert_network_event

log = logging.getLogger("utc.network_monitor")

_scapy_available = False
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, conf as scapy_conf
    scapy_conf.verb = 0
    _scapy_available = True
except Exception as _e:
    log.warning(f"Scapy unavailable ({_e}) — demo mode active.")

DEFAULT_SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 135, 139, 445, 1433,
    3306, 3389, 4444, 5900, 6666, 8080, 9001, 1337, 31337
}

_DB_WRITE_EVERY = 8

# Colour map sent to frontend so JS chart always matches backend labels
PROTO_COLORS = {
    "TCP":   "#00d4ff",
    "UDP":   "#00ff9d",
    "DNS":   "#9b59ff",
    "ICMP":  "#ffb300",
    "ARP":   "#00bfa5",
    "OTHER": "#3d5068",
}


class NetworkMonitor:
    def __init__(self, ws_manager):
        self.ws  = ws_manager
        self._cfg = {}
        self._running = False
        self._thread  = None
        self._loop    = None
        self._pps_timer = None

        self._pkt_total          = 0
        self._pkt_count_this_sec = 0
        self._pkt_since_db_write = 0

        # Per-protocol counters
        self._protocol_totals: dict[str, int]   = defaultdict(int)
        self._protocol_this_sec: dict[str, int] = defaultdict(int)

        # Per-IP structures
        self._ip_port_window: dict[str, deque]   = defaultdict(lambda: deque(maxlen=1000))
        self._ip_pkt_this_sec: dict[str, int]    = defaultdict(int)
        self._ip_pkt_rolling: dict[str, deque]   = defaultdict(lambda: deque(maxlen=500))
        self._top_ips: dict[str, int]            = defaultdict(int)

        self._ids_callback = None

    def set_ids_callback(self, cb):
        self._ids_callback = cb

    def start(self, loop: asyncio.AbstractEventLoop):
        self._loop    = loop
        self._cfg     = get_settings().get("network_monitor", {})
        self._running = True
        self._thread  = threading.Thread(
            target=self._capture_loop, name="net-capture", daemon=True
        )
        self._thread.start()
        self._schedule_pps()
        log.info("Network monitor started (scapy=%s)", _scapy_available)

    def stop(self):
        self._running = False
        if self._pps_timer:
            self._pps_timer.cancel()
        log.info("Network monitor stopped.")

    def _capture_loop(self):
        if _scapy_available:
            self._scapy_capture()
        else:
            self._demo_capture()

    def _scapy_capture(self):
        iface = self._cfg.get("interface") or None
        flt   = self._cfg.get("capture_filter") or ""
        try:
            sniff(
                iface=iface,
                filter=flt or None,
                prn=self._process_scapy_packet,
                store=False,
                stop_filter=lambda _: not self._running,
                count=0,
            )
        except PermissionError:
            log.error("Admin required for packet capture. Switching to demo mode.")
            self._demo_capture()
        except Exception as exc:
            log.error(f"Scapy error: {exc}. Switching to demo mode.")
            self._demo_capture()

    def _demo_capture(self):
        """
        Realistic synthetic traffic generator.
        Protocol distribution: TCP 40%, UDP 18%, DNS 22%, ICMP 12%, ARP 8%
        Injects suspicious bursts every 30 s to exercise IDS rules.
        """
        import random
        log.info("Demo packet generator active.")

        src_ips = [
            "192.168.1.10", "192.168.1.25", "10.0.0.5", "172.16.0.3",
            "203.0.113.42", "198.51.100.7", "185.220.101.15", "45.33.32.156",
        ]
        dst_ips    = ["192.168.1.1", "8.8.8.8", "1.1.1.1", "192.168.1.100", "10.0.0.1"]
        tcp_ports  = [80, 443, 22, 8080, 3306, 3389, 445, 25, 21, 8443]
        udp_ports  = [123, 161, 500, 5353, 67, 68, 514]
        proto_pool = (
            ["TCP"] * 40 + ["UDP"] * 18 + ["DNS"] * 22 + ["ICMP"] * 12 + ["ARP"] * 8
        )

        tick = 0
        while self._running:
            tick += 1

            # Periodic suspicious port scan burst (exercises IDS port-scan rule)
            if tick % 30 == 0:
                attacker = random.choice(["203.0.113.42", "185.220.101.15"])
                for dp in random.sample(range(1, 65535), 25):
                    if not self._running:
                        return
                    self._handle_pkt({
                        "src_ip": attacker, "dst_ip": "192.168.1.1",
                        "src_port": random.randint(40000, 65000), "dst_port": dp,
                        "protocol": "TCP", "packet_size": 44, "flags": "S",
                    })

            # DNS flood burst (exercises DNS tunneling rule)
            if tick % 45 == 0:
                tunneler = "198.51.100.7"
                for _ in range(30):
                    if not self._running:
                        return
                    self._handle_pkt({
                        "src_ip": tunneler, "dst_ip": "8.8.8.8",
                        "src_port": random.randint(1024, 65535), "dst_port": 53,
                        "protocol": "DNS", "packet_size": random.randint(80, 512), "flags": "",
                    })

            n = random.randint(4, 14)
            for _ in range(n):
                if not self._running:
                    return
                proto  = random.choice(proto_pool)
                src_ip = random.choice(src_ips)
                dst_ip = random.choice(dst_ips)

                if proto == "TCP":
                    dp    = random.choice(tcp_ports)
                    flags = random.choices(
                        ["S", "SA", "A", "PA", "FA", "R"],
                        weights=[25, 20, 35, 10, 5, 5]
                    )[0]
                    self._handle_pkt({
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "src_port": random.randint(1024, 65535), "dst_port": dp,
                        "protocol": "TCP", "packet_size": random.randint(44, 1460),
                        "flags": flags,
                    })
                elif proto == "UDP":
                    self._handle_pkt({
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "src_port": random.randint(1024, 65535),
                        "dst_port": random.choice(udp_ports),
                        "protocol": "UDP", "packet_size": random.randint(28, 512),
                        "flags": "",
                    })
                elif proto == "DNS":
                    self._handle_pkt({
                        "src_ip": src_ip,
                        "dst_ip": random.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9"]),
                        "src_port": random.randint(1024, 65535), "dst_port": 53,
                        "protocol": "DNS", "packet_size": random.randint(28, 256),
                        "flags": "",
                    })
                elif proto == "ICMP":
                    self._handle_pkt({
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "src_port": 0, "dst_port": 0,
                        "protocol": "ICMP", "packet_size": random.randint(28, 84),
                        "flags": "",
                    })
                elif proto == "ARP":
                    self._handle_pkt({
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "src_port": 0, "dst_port": 0,
                        "protocol": "ARP", "packet_size": 42, "flags": "",
                    })

            time.sleep(1)

    def _process_scapy_packet(self, pkt):
        """Classify a Scapy packet and extract fields into our standard dict."""
        if not self._running:
            return

        src_ip = dst_ip = ""
        sp = dp = 0
        flags  = ""
        proto  = "OTHER"
        size   = len(pkt)

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if TCP in pkt:
                sp, dp = pkt[TCP].sport, pkt[TCP].dport
                flag_map = {0x01:"F", 0x02:"S", 0x04:"R", 0x08:"P", 0x10:"A", 0x20:"U"}
                rf = int(pkt[TCP].flags)
                flags = "".join(v for k, v in sorted(flag_map.items()) if rf & k)
                # DNS can run over TCP (zone transfers, responses > 512 bytes)
                proto = "DNS" if dp == 53 or sp == 53 else "TCP"

            elif UDP in pkt:
                sp, dp = pkt[UDP].sport, pkt[UDP].dport
                proto = "DNS" if dp == 53 or sp == 53 else "UDP"

            elif ICMP in pkt:
                proto = "ICMP"

            else:
                # Other IP protocols (OSPF=89, GRE=47, ESP=50, etc.)
                ip_proto = getattr(pkt[IP], 'proto', 0)
                proto = f"OTHER({ip_proto})"[:10]

        elif _scapy_available and ARP in pkt:
            proto  = "ARP"
            src_ip = pkt[ARP].psrc if hasattr(pkt[ARP], 'psrc') else ""
            dst_ip = pkt[ARP].pdst if hasattr(pkt[ARP], 'pdst') else ""

        elif _scapy_available and IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            if TCP in pkt:
                sp, dp = pkt[TCP].sport, pkt[TCP].dport
                flag_map = {0x01:"F", 0x02:"S", 0x04:"R", 0x08:"P", 0x10:"A", 0x20:"U"}
                rf = int(pkt[TCP].flags)
                flags = "".join(v for k, v in sorted(flag_map.items()) if rf & k)
                proto = "DNS" if dp == 53 or sp == 53 else "TCP"
            elif UDP in pkt:
                sp, dp = pkt[UDP].sport, pkt[UDP].dport
                proto = "DNS" if dp == 53 or sp == 53 else "UDP"
            else:
                proto = "OTHER"
        else:
            return  # Skip unknown frame types

        if not src_ip:
            return

        self._handle_pkt({
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "src_port":    sp,
            "dst_port":    dp,
            "protocol":    proto,
            "packet_size": size,
            "flags":       flags,
        })

    def _handle_pkt(self, info: dict):
        """Central packet processor — updates all counters and fires WS/DB writes."""
        self._pkt_total          += 1
        self._pkt_count_this_sec += 1
        self._pkt_since_db_write += 1

        proto  = info["protocol"]
        src_ip = info["src_ip"]

        self._protocol_totals[proto]   += 1
        self._protocol_this_sec[proto] += 1
        self._top_ips[src_ip]           += 1
        self._ip_pkt_this_sec[src_ip]   += 1

        # Rolling timestamp window for sustained-pps calculation
        ts_now = time.time()
        self._ip_pkt_rolling[src_ip].append(ts_now)
        # 5-second sustained pps per IP (IDS uses this for DoS detection)
        window_5s     = [t for t in self._ip_pkt_rolling[src_ip] if t >= ts_now - 5.0]
        ip_rolling_pps = len(window_5s)

        # Suspicious port flag
        sp_set     = set(self._cfg.get("suspicious_ports", list(DEFAULT_SUSPICIOUS_PORTS)))
        suspicious = info["dst_port"] in sp_set or info["src_port"] in sp_set
        note       = f"Suspicious port {info['dst_port']}" if suspicious else ""

        # IDS callback — pass both per-second count AND rolling 5s pps
        if self._ids_callback:
            try:
                ids_note = self._ids_callback(
                    info,
                    self._ip_port_window,
                    self._ip_pkt_this_sec,   # per-second snapshot (IDS reads this)
                    ip_rolling_pps,          # sustained 5s pps for flood detection
                )
                if ids_note:
                    note = ids_note
                    suspicious = True
            except Exception as exc:
                log.debug(f"IDS callback error: {exc}")

        # Append to port window AFTER IDS call so window state is consistent
        self._ip_port_window[src_ip].append((ts_now, info["dst_port"]))

        event = {**info, "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "suspicious": suspicious, "note": note}

        # Throttled DB write
        if self._pkt_since_db_write >= _DB_WRITE_EVERY:
            self._pkt_since_db_write = 0
            try:
                insert_network_event(
                    src_ip=src_ip, dst_ip=info["dst_ip"],
                    src_port=info["src_port"], dst_port=info["dst_port"],
                    protocol=proto, packet_size=info["packet_size"],
                    flags=info["flags"], suspicious=suspicious, note=note,
                )
            except Exception as exc:
                log.debug(f"DB insert error: {exc}")

        if self._loop and not self._loop.is_closed():
            asyncio.run_coroutine_threadsafe(
                self.ws.emit_network_event(event), self._loop
            )

    def _schedule_pps(self):
        if not self._running:
            return

        total_pps = self._pkt_count_this_sec
        proto_pps = dict(self._protocol_this_sec)
        ip_snap   = dict(self._ip_pkt_this_sec)
        top_ips   = sorted(self._top_ips.items(), key=lambda x: x[1], reverse=True)[:8]

        # Reset per-second counters
        self._pkt_count_this_sec = 0
        self._protocol_this_sec.clear()
        self._ip_pkt_this_sec.clear()

        stats = {
            "pps":           total_pps,
            "proto_pps":     proto_pps,
            "total":         self._pkt_total,
            "proto_totals":  dict(self._protocol_totals),
            "proto_colors":  PROTO_COLORS,
            "_scapy_live":   _scapy_available,  # tells dashboard real vs demo mode
            "top_ips": [
                {"src_ip": ip, "cnt": cnt, "pps": ip_snap.get(ip, 0)}
                for ip, cnt in top_ips
            ],
        }

        if self._loop and not self._loop.is_closed():
            asyncio.run_coroutine_threadsafe(
                self.ws.emit_stats_update(stats), self._loop
            )

        self._pps_timer = threading.Timer(1.0, self._schedule_pps)
        self._pps_timer.daemon = True
        self._pps_timer.start()


_monitor_instance = None

def get_monitor():
    return _monitor_instance

def create_monitor(ws_manager):
    global _monitor_instance
    _monitor_instance = NetworkMonitor(ws_manager)
    return _monitor_instance
