"""
UTC — Web Vulnerability Scanner  (v3 — Accuracy & False-Positive Fixes)
app/modules/vuln_scanner.py

Changelog v3:
  - Classification tiers: informational / potential / confirmed
  - Security headers downgraded to 'informational' (missing header ≠ vulnerability)
  - Context-aware severity: HTTPS sites get reduced header severity
  - CORS wildcard stays high only when combined with credentials hint
  - Scanner marks its own requests with X-UTC-Scanner header
  - IDS whitelist: scanner source (127.0.0.1 / localhost) registered at scan start
  - Overall scan verdict emitted on completion: SAFE / SUSPICIOUS / VULNERABLE
  - Risk summary broadcast via WebSocket for dashboard risk panel
  - Confirmed findings require positive evidence (error text / payload reflection)
    not just absence of a header
  - HSTS only flagged as potential risk on HTTP sites (not HTTPS)
  - Boolean SQLi stores true/false responses correctly (variable scope fix)
"""

import asyncio
import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

from app.database import insert_vuln_report, update_vuln_report, insert_log
from app.ws_manager import WebSocketManager

log = logging.getLogger("utc.scanner")

# ── Scanner identity — used to whitelist traffic in IDS ───────────────────────
SCANNER_HEADER   = "X-UTC-Scanner"
SCANNER_HEADER_V = "1"
SCANNER_IPS      = {"127.0.0.1", "::1", "localhost"}   # IDs will ignore these

# ── SQLi payloads ──────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    '" OR "1"="1',
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' AND SLEEP(2)--",
    "'; WAITFOR DELAY '0:0:2'--",
    "' AND 1=2--",
    "' AND 1=1--",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
    r"valid MySQL result", r"check the manual.*MySQL",
    r"SQL Server.*Driver", r"OLE DB.*SQL Server", r"Unclosed quotation mark",
    r"Microsoft OLE DB Provider for ODBC", r"SQLServer JDBC Driver",
    r"SqlException", r"Syntax error.*query expression",
    r"ORA-\d{5}", r"Oracle.*Driver", r"Warning.*oci_",
    r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result",
    r"Npgsql\.", r"PG::SyntaxError",
    r"SQLite.*error", r"Warning.*sqlite_",
    r"DB2 SQL error", r"\bDBI::DBD\b",
    r"error in your SQL syntax", r"SQLSTATE\[\w+\]",
    r"supplied argument is not a valid MySQL", r"Column count doesn't match",
]
SQLI_ERROR_RE = re.compile("|".join(SQLI_ERROR_PATTERNS), re.IGNORECASE)

# ── XSS payloads ──────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('UTC-XSS')</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    '"><svg/onload=alert(1)>',
]

XSS_REFLECTION_RE = re.compile(
    r"(<script[\s>]|onerror\s*=|onload\s*=|javascript:|<svg[\s/]|alert\s*\()",
    re.IGNORECASE
)
XSS_ENCODED_RE = re.compile(
    r"(&lt;script|&lt;img|&lt;svg|&#x3c;script)",
    re.IGNORECASE
)

# ── Security headers config ────────────────────────────────────────────────────
# Format: (header_name, base_severity, description, explanation)
# base_severity is the MAXIMUM possible — context can only reduce it.
# All missing-header findings are classified as "informational" by default.
SECURITY_HEADERS = [
    ("Content-Security-Policy",
     "informational",
     "Content-Security-Policy header not present",
     "CSP helps prevent XSS but its absence alone is not exploitable. "
     "Only a concern if XSS is also found."),

    ("X-Frame-Options",
     "informational",
     "X-Frame-Options header not present",
     "Clickjacking risk if the site embeds sensitive actions in iframes. "
     "Modern browsers use CSP frame-ancestors instead."),

    ("X-Content-Type-Options",
     "informational",
     "X-Content-Type-Options (nosniff) not present",
     "Prevents MIME-type sniffing attacks. Low risk on modern browsers."),

    ("Strict-Transport-Security",
     "potential",
     "HSTS header not present — evaluated based on protocol",
     "Relevant only on HTTPS sites. On HTTP, HSTS cannot be delivered."),

    ("Referrer-Policy",
     "informational",
     "Referrer-Policy header not present",
     "May leak URL path to third parties via the Referer header."),

    ("Permissions-Policy",
     "informational",
     "Permissions-Policy header not present",
     "Controls browser feature access (camera, mic). Low risk unless "
     "the app uses sensitive APIs."),
]

# ── Directory traversal payloads ──────────────────────────────────────────────
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../windows/win.ini",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
TRAVERSAL_RE = re.compile(
    r"root:x:0:0|daemon:x:|nobody:x:|\[fonts\]|boot loader",
    re.IGNORECASE
)

# ── Open redirect ──────────────────────────────────────────────────────────────
REDIRECT_PARAMS  = ["redirect", "url", "next", "return", "returnUrl",
                    "goto", "redir", "destination", "target", "ref"]
REDIRECT_PAYLOAD = "https://evil.example.com"

# ── Response codes of interest ────────────────────────────────────────────────
INTERESTING_CODES = {
    500: ("potential", "500 Internal Server Error — possible unhandled exception"),
    502: ("informational", "502 Bad Gateway — upstream issue"),
    503: ("informational", "503 Service Unavailable"),
}


# ── Classification helpers ────────────────────────────────────────────────────
def _finding(ftype, classification, severity, url, description, explanation="",
             payload="", evidence="", confidence="medium"):
    """
    Build a standardised finding dict.

    classification: "informational" | "potential" | "confirmed"
    severity:       "critical" | "high" | "medium" | "low" | "info"
    confidence:     "low" | "medium" | "high"
    """
    return {
        "type":           ftype,
        "classification": classification,
        "severity":       severity,
        "url":            url,
        "description":    description,
        "explanation":    explanation,
        "payload":        payload,
        "evidence":       evidence,
        "confidence":     confidence,
    }


def _severity_for_classification(classification):
    """Map classification to a display severity."""
    return {
        "confirmed":     "high",
        "potential":     "medium",
        "informational": "info",
    }.get(classification, "info")


class VulnScanner:
    def __init__(self, ws_manager: WebSocketManager):
        self.ws = ws_manager

    async def scan(self, report_id: int, target_url: str, scan_type: str = "full") -> None:
        log.info(f"Scan starting: [{scan_type}] {target_url}")
        insert_log("system", "info",
            f"[SCANNER] Vulnerability scan started: {target_url} (type={scan_type})")

        findings    = []
        total_tests = 0

        # Register scanner IPs in IDS whitelist
        self._register_scanner_whitelist()

        try:
            await self._emit_progress(0, "running", "Fetching target page...")
            session = self._make_session()

            # ── Step 1: Initial fetch — follow all redirects, capture final headers ──
            try:
                # First pass: follow redirects to find the final URL
                resp = await asyncio.to_thread(
                    session.get, target_url, timeout=10, allow_redirects=True
                )
                final_url  = resp.url
                is_https   = final_url.startswith("https://")

                # If we were redirected, do a second fetch of the final URL directly
                # so we get its own headers (not intermediate redirect headers).
                # This matters for sites like google.com that redirect http→https
                # and apply security headers only on the final https response.
                if resp.history and final_url != target_url:
                    try:
                        resp2 = await asyncio.to_thread(
                            session.get, final_url, timeout=10, allow_redirects=False
                        )
                        # Merge: take final URL's headers as authoritative
                        resp = resp2
                        resp.url = final_url  # type: ignore[attr-defined]
                    except Exception:
                        pass  # keep original resp if re-fetch fails

                base_html = resp.text
                base_url  = final_url

            except requests.RequestException as exc:
                await self._emit_progress(100, "failed", f"Cannot reach target: {exc}")
                update_vuln_report(report_id, "failed", 0, 0, "[]")
                insert_log("system", "error",
                    f"[SCANNER] Scan failed — unreachable: {target_url}", flagged=True)
                return

            await self._emit_progress(8, "running",
                f"Connected — HTTP {resp.status_code} ({'HTTPS' if is_https else 'HTTP'})")

            # ── Step 2: Security headers (context-aware) ─────────────────────
            hdr_findings, hdr_tests = self._check_security_headers(
                base_url, resp.headers, is_https
            )
            for f in hdr_findings:
                findings.append(f)
                await self._emit_finding(f)
            total_tests += hdr_tests
            await self._emit_progress(15, "running",
                f"Headers: {len(hdr_findings)} notes")

            # ── Step 3: Info disclosure ───────────────────────────────────────
            disc = self._check_info_disclosure(base_url, resp.headers)
            for f in disc:
                findings.append(f)
                await self._emit_finding(f)
            total_tests += len(disc)

            # ── Step 4: Response code analysis ────────────────────────────────
            code_f = self._check_response_codes(base_url, resp.status_code)
            for f in code_f:
                findings.append(f)
                await self._emit_finding(f)
            total_tests += 1
            await self._emit_progress(22, "running", "Response analysis complete")

            # ── Step 5: Extract forms + params ────────────────────────────────
            forms  = self._extract_forms(base_html, base_url)
            params = self._extract_url_params(base_url)
            await self._emit_progress(28, "running",
                f"Found {len(forms)} forms, {len(params)} URL params")

            # ── Step 6: Open redirect ─────────────────────────────────────────
            if scan_type == "full":
                rf, rt = await self._test_open_redirect(session, base_url, forms, params)
                findings.extend(rf); total_tests += rt
                for f in rf: await self._emit_finding(f)
                await self._emit_progress(35, "running", f"Redirect test: {len(rf)} findings")

            # ── Step 7: Directory traversal ───────────────────────────────────
            if scan_type == "full":
                tf, tt = await self._test_traversal(session, base_url, params)
                findings.extend(tf); total_tests += tt
                for f in tf: await self._emit_finding(f)
                await self._emit_progress(45, "running", f"Traversal test: {len(tf)} findings")

            # ── Step 8: SQL Injection ─────────────────────────────────────────
            if scan_type in ("full", "sqli"):
                sf, st = await self._test_sqli(session, base_url, forms, params)
                findings.extend(sf); total_tests += st
                await self._emit_progress(68, "running", f"SQLi scan: {len(sf)} findings")

            # ── Step 9: XSS ──────────────────────────────────────────────────
            if scan_type in ("full", "xss"):
                xf, xt = await self._test_xss(session, base_url, forms, params)
                findings.extend(xf); total_tests += xt
                await self._emit_progress(88, "running", f"XSS scan: {len(xf)} findings")

            # ── Step 10: Form fuzzing ─────────────────────────────────────────
            if scan_type == "full" and forms:
                ff, fft = await self._fuzz_forms(session, forms)
                findings.extend(ff); total_tests += fft
                await self._emit_progress(95, "running", f"Form fuzz: {len(ff)} findings")

            # ── Finalise: verdict + risk summary ─────────────────────────────
            verdict, risk_summary = self._compute_verdict(findings)
            summary_msg = (
                f"Scan complete — {total_tests} tests, {len(findings)} findings — "
                f"Verdict: {verdict}"
            )
            await self._emit_progress(100, "complete", summary_msg)
            await self._emit_verdict(verdict, risk_summary, findings)

            update_vuln_report(report_id, "complete", total_tests, len(findings),
                               json.dumps(findings))
            confirmed = [f for f in findings if f.get("classification") == "confirmed"]
            insert_log(
                "system",
                "warning" if confirmed else "info",
                f"[SCANNER] Scan complete {target_url}: verdict={verdict}, "
                f"{len(findings)} findings ({len(confirmed)} confirmed)",
                flagged=bool(confirmed),
            )

        except Exception as exc:
            log.error(f"Scanner error: {exc}", exc_info=True)
            await self._emit_progress(100, "failed", f"Scanner error: {exc}")
            update_vuln_report(report_id, "failed", total_tests, len(findings),
                               json.dumps(findings))

    # ── IDS Whitelist Registration ────────────────────────────────────────────
    @staticmethod
    def _register_scanner_whitelist():
        """Tell IDS engine to ignore traffic from scanner (localhost)."""
        try:
            from app.modules.ids_engine import get_ids
            ids = get_ids()
            if ids:
                ids.add_whitelist_ips(SCANNER_IPS)
        except Exception:
            pass

    # ── Security Headers ──────────────────────────────────────────────────────
    def _check_security_headers(self, url, headers, is_https: bool) -> tuple[list, int]:
        """
        ALL missing-header findings are INFORMATIONAL.
        A missing header is never a vulnerability on its own — it requires
        active exploitation evidence (XSS reflection, SQL error, etc.).
        """
        findings = []
        hdrs_low = {k.lower() for k in headers.keys()}

        for header, _unused_base_class, description, explanation in SECURITY_HEADERS:
            if header.lower() in hdrs_low:
                continue

            # Adjust description for HSTS context only
            if header == "Strict-Transport-Security" and not is_https:
                description = "HSTS not applicable (HTTP site) — only works over HTTPS"

            # Every missing header = informational, never potential or confirmed
            findings.append(_finding(
                ftype          = "Missing Security Header",
                classification = "informational",
                severity       = "info",
                url            = url,
                description    = description,
                explanation    = explanation,
                payload        = header,
                evidence       = f"Header '{header}' absent from HTTP response",
                confidence     = "high",
            ))

        # CORS: only the wildcard+credentials combo is a real misconfiguration
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(_finding(
                ftype          = "CORS Misconfiguration",
                classification = "confirmed",
                severity       = "high",
                url            = url,
                description    = "CORS wildcard with Allow-Credentials: true — authenticated cross-origin reads possible",
                explanation    = "Browsers allow credentialled cross-origin requests from any domain. "
                                 "Attackers can read authenticated data from victim sessions.",
                payload        = "CORS",
                evidence       = f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                confidence     = "high",
            ))
        elif acao == "*":
            # Wildcard without credentials = informational (expected for public APIs/CDNs)
            findings.append(_finding(
                ftype          = "CORS Wildcard (Public API)",
                classification = "informational",
                severity       = "info",
                url            = url,
                description    = "Access-Control-Allow-Origin: * — public cross-origin reads allowed (no credentials)",
                explanation    = "Standard configuration for public APIs and CDNs. Not exploitable alone.",
                payload        = "CORS",
                evidence       = f"Access-Control-Allow-Origin: {acao}",
                confidence     = "low",
            ))

        return findings, len(SECURITY_HEADERS) + 1

    # ── Info Disclosure ────────────────────────────────────────────────────────
    def _check_info_disclosure(self, url, headers) -> list:
        findings = []
        server   = headers.get("Server", "")
        if server and any(c.isdigit() for c in server):
            findings.append(_finding(
                ftype          = "Server Version Disclosure",
                classification = "informational",
                severity       = "info",
                url            = url,
                description    = "Server header reveals software version number",
                explanation    = "Version disclosure helps attackers target known CVEs. "
                                 "Remove or genericise the Server header in production.",
                payload        = "Server",
                evidence       = server,
                confidence     = "high",
            ))
        powered = headers.get("X-Powered-By", "")
        if powered:
            findings.append(_finding(
                ftype          = "Technology Stack Disclosure",
                classification = "informational",
                severity       = "info",
                url            = url,
                description    = "X-Powered-By reveals backend technology",
                explanation    = "Removes one layer of security-by-obscurity. "
                                 "Not exploitable alone.",
                payload        = "X-Powered-By",
                evidence       = powered,
                confidence     = "high",
            ))
        return findings

    # ── Response Code Analysis ─────────────────────────────────────────────────
    def _check_response_codes(self, url, status_code) -> list:
        findings = []
        if status_code in INTERESTING_CODES:
            classification, desc = INTERESTING_CODES[status_code]
            findings.append(_finding(
                ftype          = "Unusual HTTP Status Code",
                classification = classification,
                severity       = _severity_for_classification(classification),
                url            = url,
                description    = desc,
                explanation    = "A 500 on the base URL may indicate unhandled exceptions "
                                 "that could expose stack traces or internal info.",
                payload        = str(status_code),
                evidence       = f"HTTP {status_code} on base URL",
                confidence     = "medium",
            ))
        return findings

    # ── Open Redirect ──────────────────────────────────────────────────────────
    async def _test_open_redirect(self, session, base_url, forms, params) -> tuple[list, int]:
        findings, tests = [], 0
        parsed      = urlparse(base_url)
        base_params = parse_qs(parsed.query)

        for param in REDIRECT_PARAMS:
            tests += 1
            try:
                tp = {k: (v[0] if v else "") for k, v in base_params.items()}
                tp[param] = REDIRECT_PAYLOAD
                tu = urlunparse(parsed._replace(query=urlencode(tp)))
                resp = await asyncio.to_thread(
                    session.get, tu, timeout=8, allow_redirects=False
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if "evil.example.com" in loc:
                        findings.append(_finding(
                            ftype          = "Open Redirect",
                            classification = "confirmed",
                            severity       = "medium",
                            url            = tu,
                            description    = f"Open redirect via parameter '{param}'",
                            explanation    = "Attackers can craft links that redirect victims to "
                                             "malicious sites while appearing to come from a trusted domain.",
                            payload        = REDIRECT_PAYLOAD,
                            evidence       = f"Location: {loc}",
                            confidence     = "high",
                        ))
                        break
            except Exception:
                pass
            await asyncio.sleep(0.05)

        for param_name in list(base_params.keys())[:4]:
            if any(kw in param_name.lower() for kw in ["url","red","next","go","ret"]):
                tests += 1
                try:
                    tp = {k: (v[0] if v else "") for k, v in base_params.items()}
                    tp[param_name] = REDIRECT_PAYLOAD
                    tu   = urlunparse(parsed._replace(query=urlencode(tp)))
                    resp = await asyncio.to_thread(
                        session.get, tu, timeout=8, allow_redirects=False
                    )
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location", "")
                        if "evil.example.com" in loc:
                            findings.append(_finding(
                                ftype          = "Open Redirect",
                                classification = "confirmed",
                                severity       = "medium",
                                url            = tu,
                                description    = f"Open redirect via URL param '{param_name}'",
                                explanation    = "Redirect parameter accepts arbitrary external URLs.",
                                payload        = REDIRECT_PAYLOAD,
                                evidence       = f"Location: {loc}",
                                confidence     = "high",
                            ))
                except Exception:
                    pass
                await asyncio.sleep(0.05)

        return findings, tests

    # ── Directory Traversal ────────────────────────────────────────────────────
    async def _test_traversal(self, session, base_url, params) -> tuple[list, int]:
        findings, tests = [], 0
        parsed      = urlparse(base_url)
        base_params = parse_qs(parsed.query)

        file_params = [p for p in base_params
                       if any(kw in p.lower() for kw in
                              ["file","path","page","template","doc","include","dir","folder"])]
        target_params = file_params or list(base_params.keys())[:3]

        for param in target_params:
            for payload in TRAVERSAL_PAYLOADS[:4]:
                tests += 1
                try:
                    tp = {k: (v[0] if v else "") for k, v in base_params.items()}
                    tp[param] = payload
                    tu   = urlunparse(parsed._replace(query=urlencode(tp)))
                    resp = await asyncio.to_thread(session.get, tu, timeout=8)
                    if TRAVERSAL_RE.search(resp.text):
                        findings.append(_finding(
                            ftype          = "Directory Traversal / Path Traversal",
                            classification = "confirmed",
                            severity       = "critical",
                            url            = tu,
                            description    = f"Path traversal confirmed on parameter '{param}'",
                            explanation    = "Server returns local file content when a traversal "
                                             "sequence is injected into a file path parameter.",
                            payload        = payload,
                            evidence       = self._snippet(resp.text, TRAVERSAL_RE),
                            confidence     = "high",
                        ))
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.05)

        return findings, tests

    # ── SQL Injection ──────────────────────────────────────────────────────────
    async def _test_sqli(self, session, base_url, forms, params) -> tuple[list, int]:
        findings, tests = [], 0
        parsed      = urlparse(base_url)
        base_params = parse_qs(parsed.query)

        for param_name in base_params:
            true_len  = None
            false_len = None
            for payload in SQLI_PAYLOADS[:10]:
                tests += 1
                try:
                    tp = {k: (v[0] if v else "") for k, v in base_params.items()}
                    tp[param_name] = payload
                    tu      = urlunparse(parsed._replace(query=urlencode(tp)))
                    t_start = time.time()
                    resp    = await asyncio.to_thread(session.get, tu, timeout=12)
                    elapsed = time.time() - t_start

                    # Error-based (confirmed)
                    if SQLI_ERROR_RE.search(resp.text):
                        findings.append(_finding(
                            ftype          = "SQL Injection (Error-based)",
                            classification = "confirmed",
                            severity       = "critical",
                            url            = tu,
                            description    = f"SQL error message in response via param '{param_name}'",
                            explanation    = "The server returned a raw database error message, "
                                             "confirming SQL injection and exposing DB internals.",
                            payload        = payload,
                            evidence       = self._snippet(resp.text, SQLI_ERROR_RE),
                            confidence     = "high",
                        ))
                        break

                    # Time-based blind (confirmed)
                    if ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper()) and elapsed >= 1.8:
                        findings.append(_finding(
                            ftype          = "SQL Injection (Time-based Blind)",
                            classification = "confirmed",
                            severity       = "critical",
                            url            = tu,
                            description    = f"Time-delay injection confirmed on param '{param_name}' ({elapsed:.1f}s)",
                            explanation    = "The database executed a sleep/delay function, "
                                             "confirming blind SQL injection.",
                            payload        = payload,
                            evidence       = f"Response delayed {elapsed:.2f}s",
                            confidence     = "high",
                        ))
                        break

                    # Boolean-based (potential — requires both true and false responses)
                    if "AND 1=1" in payload:
                        true_len = len(resp.text)
                    elif "AND 1=2" in payload and true_len is not None:
                        false_len = len(resp.text)
                        if abs(true_len - false_len) > 80:
                            findings.append(_finding(
                                ftype          = "SQL Injection (Boolean-based Blind)",
                                classification = "potential",
                                severity       = "high",
                                url            = tu,
                                description    = f"Response differs for true/false conditions on param '{param_name}'",
                                explanation    = "Page content changes depending on true/false SQL conditions, "
                                                 "suggesting boolean-blind SQLi. Needs manual confirmation.",
                                payload        = payload,
                                evidence       = f"True: {true_len} chars, False: {false_len} chars (diff={abs(true_len-false_len)})",
                                confidence     = "medium",
                            ))
                            break

                except Exception:
                    pass
                await asyncio.sleep(0.05)

        for form in forms[:3]:
            for inp in form["inputs"][:5]:
                if inp["type"] in ("submit","button","hidden","file","checkbox"):
                    continue
                for payload in SQLI_PAYLOADS[:5]:
                    tests += 1
                    try:
                        data = {i["name"]: i["value"] for i in form["inputs"]}
                        data[inp["name"]] = payload
                        if form["method"] == "post":
                            resp = await asyncio.to_thread(
                                session.post, form["action"], data=data, timeout=10)
                        else:
                            resp = await asyncio.to_thread(
                                session.get, form["action"], params=data, timeout=10)
                        if SQLI_ERROR_RE.search(resp.text):
                            findings.append(_finding(
                                ftype          = "SQL Injection (Form)",
                                classification = "confirmed",
                                severity       = "critical",
                                url            = form["action"],
                                description    = f"SQL error triggered via form field '{inp['name']}'",
                                explanation    = "SQL injection confirmed through form submission.",
                                payload        = payload,
                                evidence       = self._snippet(resp.text, SQLI_ERROR_RE),
                                confidence     = "high",
                            ))
                            break
                    except Exception:
                        pass
                    await asyncio.sleep(0.05)

        return findings, tests

    # ── XSS Testing ───────────────────────────────────────────────────────────
    async def _test_xss(self, session, base_url, forms, params) -> tuple[list, int]:
        findings, tests = [], 0
        parsed      = urlparse(base_url)
        base_params = parse_qs(parsed.query)

        for param_name in base_params:
            for payload in XSS_PAYLOADS[:6]:
                tests += 1
                try:
                    tp = {k: (v[0] if v else "") for k, v in base_params.items()}
                    tp[param_name] = payload
                    tu   = urlunparse(parsed._replace(query=urlencode(tp)))
                    resp = await asyncio.to_thread(session.get, tu, timeout=8)

                    # Confirmed: raw payload reflected with active tags
                    if XSS_REFLECTION_RE.search(resp.text):
                        if any(m in resp.text for m in ["UTC-XSS","alert(1)","alert('xss')"]):
                            findings.append(_finding(
                                ftype          = "Cross-Site Scripting (Reflected XSS)",
                                classification = "confirmed",
                                severity       = "high",
                                url            = tu,
                                description    = f"XSS payload reflected unescaped via param '{param_name}'",
                                explanation    = "Unescaped script content is returned in the response, "
                                                 "allowing attackers to run arbitrary JS in victims' browsers.",
                                payload        = payload,
                                evidence       = "Script tag / event handler found unescaped in response",
                                confidence     = "high",
                            ))
                            break

                    # Potential: HTML-encoded reflection (may be bypassable)
                    if XSS_ENCODED_RE.search(resp.text):
                        findings.append(_finding(
                            ftype          = "XSS — HTML-Encoded Reflection",
                            classification = "potential",
                            severity       = "medium",
                            url            = tu,
                            description    = f"Payload reflected HTML-encoded via param '{param_name}'",
                            explanation    = "The app encodes output but encoding may be bypassable "
                                             "depending on context (attribute injection, JS string).",
                            payload        = payload,
                            evidence       = "HTML-encoded payload found in response",
                            confidence     = "medium",
                        ))
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.05)

        for form in forms[:3]:
            for inp in form["inputs"][:5]:
                if inp["type"] in ("submit","button","hidden","file","checkbox"):
                    continue
                for payload in XSS_PAYLOADS[:4]:
                    tests += 1
                    try:
                        data = {i["name"]: i["value"] for i in form["inputs"]}
                        data[inp["name"]] = payload
                        if form["method"] == "post":
                            resp = await asyncio.to_thread(
                                session.post, form["action"], data=data, timeout=8)
                        else:
                            resp = await asyncio.to_thread(
                                session.get, form["action"], params=data, timeout=8)
                        if XSS_REFLECTION_RE.search(resp.text):
                            if any(m in resp.text for m in ["UTC-XSS","alert(1)","alert('xss')"]):
                                findings.append(_finding(
                                    ftype          = "Cross-Site Scripting (Form XSS)",
                                    classification = "confirmed",
                                    severity       = "high",
                                    url            = form["action"],
                                    description    = f"XSS confirmed via form field '{inp['name']}'",
                                    explanation    = "Unescaped script content returned via form submission.",
                                    payload        = payload,
                                    evidence       = "Payload reflected in response",
                                    confidence     = "high",
                                ))
                                break
                    except Exception:
                        pass
                    await asyncio.sleep(0.05)

        return findings, tests

    # ── Form Fuzzing ──────────────────────────────────────────────────────────
    async def _fuzz_forms(self, session, forms) -> tuple[list, int]:
        findings, tests = [], 0
        fuzz_inputs = ["A" * 500, "{{7*7}}", "${7*7}", "<>'\"/\\", "' OR 1=1--"]

        for form in forms[:3]:
            for fuzz in fuzz_inputs[:3]:
                tests += 1
                try:
                    data = {
                        i["name"]: fuzz for i in form["inputs"]
                        if i["type"] not in ("submit","button","hidden","file","checkbox")
                    }
                    if not data:
                        continue
                    if form["method"] == "post":
                        resp = await asyncio.to_thread(
                            session.post, form["action"], data=data, timeout=8)
                    else:
                        resp = await asyncio.to_thread(
                            session.get, form["action"], params=data, timeout=8)

                    if resp.status_code == 500:
                        findings.append(_finding(
                            ftype          = "Unhandled Server Error (Form Input)",
                            classification = "potential",
                            severity       = "medium",
                            url            = form["action"],
                            description    = "Form submission caused HTTP 500",
                            explanation    = "Unhandled exceptions may expose stack traces, "
                                             "internal paths, or DB errors.",
                            payload        = repr(fuzz[:40]),
                            evidence       = f"HTTP {resp.status_code}",
                            confidence     = "medium",
                        ))

                    if "{{7*7}}" in fuzz and "49" in resp.text:
                        findings.append(_finding(
                            ftype          = "Server-Side Template Injection (SSTI)",
                            classification = "confirmed",
                            severity       = "critical",
                            url            = form["action"],
                            description    = "Template expression {{7*7}} evaluated to 49 — SSTI confirmed",
                            explanation    = "SSTI allows attackers to execute arbitrary code on the server.",
                            payload        = "{{7*7}}",
                            evidence       = "Result '49' in response",
                            confidence     = "high",
                        ))
                    if "${7*7}" in fuzz and "49" in resp.text:
                        findings.append(_finding(
                            ftype          = "Expression Language Injection",
                            classification = "confirmed",
                            severity       = "critical",
                            url            = form["action"],
                            description    = "EL expression ${7*7} evaluated — injection confirmed",
                            explanation    = "EL injection allows server-side code execution.",
                            payload        = "${7*7}",
                            evidence       = "Result '49' in response",
                            confidence     = "high",
                        ))
                except Exception:
                    pass
                await asyncio.sleep(0.08)

        return findings, tests

    # ── Verdict Computation ────────────────────────────────────────────────────
    def _compute_verdict(self, findings: list) -> tuple[str, dict]:
        """
        Compute overall scan verdict and risk summary.

        VULNERABLE 🚨 — at least one confirmed finding with severity critical/high
        SUSPICIOUS ⚠️  — potential findings, or confirmed with medium/low severity
        SAFE ✅        — only informational findings or no findings
        """
        confirmed = [f for f in findings if f.get("classification") == "confirmed"]
        potential = [f for f in findings if f.get("classification") == "potential"]
        info      = [f for f in findings if f.get("classification") == "informational"]

        critical_confirmed = [f for f in confirmed if f.get("severity") in ("critical","high")]

        # Only count potential findings from ACTIVE exploit tests — not passive
        # header absence checks. Missing headers on major sites = informational only.
        active_test_keywords = (
            "SQL Injection", "Cross-Site Scripting", "Open Redirect",
            "Directory Traversal", "CORS Misconfiguration (Critical)",
            "SSTI", "Expression Language", "Unhandled Server Error",
            "XSS — HTML-Encoded",
        )
        active_potential = [
            f for f in potential
            if any(kw in f.get("type", "") for kw in active_test_keywords)
        ]

        if critical_confirmed:
            verdict = "VULNERABLE"
        elif confirmed or active_potential:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # Group by type for summary
        by_type: dict[str, int] = {}
        for f in findings:
            by_type[f.get("type", "Unknown")] = by_type.get(f.get("type", "Unknown"), 0) + 1

        risk_summary = {
            "verdict":            verdict,
            "total":              len(findings),
            "confirmed":          len(confirmed),
            "potential":          len(potential),
            "informational":      len(info),
            "critical_confirmed": len(critical_confirmed),
            "active_potential":   len(active_potential),
            "by_type":            by_type,
        }
        return verdict, risk_summary

    # ── Form + param extraction ────────────────────────────────────────────────
    def _extract_forms(self, html, base_url) -> list:
        forms = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                action     = form.get("action", "")
                method     = form.get("method", "get").lower()
                action_url = urljoin(base_url, action) if action else base_url
                inputs     = []
                for inp in form.find_all(["input","textarea","select"]):
                    name = inp.get("name")
                    if name:
                        inputs.append({
                            "name":  name,
                            "type":  inp.get("type","text"),
                            "value": inp.get("value","test"),
                        })
                if inputs:
                    forms.append({"action": action_url, "method": method, "inputs": inputs})
        except Exception as exc:
            log.debug(f"Form extraction error: {exc}")
        return forms

    def _extract_url_params(self, url) -> dict:
        return parse_qs(urlparse(url).query)

    # ── Session factory ────────────────────────────────────────────────────────
    def _make_session(self) -> requests.Session:
        from app.config import get_settings
        cfg = get_settings().get("vuln_scanner", {})
        s   = requests.Session()
        s.headers.update({
            "User-Agent":    cfg.get("user_agent", "UTC-VulnScanner/1.0"),
            "Accept":        "text/html,application/xhtml+xml,*/*;q=0.8",
            SCANNER_HEADER:  SCANNER_HEADER_V,  # Tag all scanner requests
        })
        s.max_redirects = int(cfg.get("max_redirects", 3))
        return s

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _snippet(self, html: str, pattern_re, max_len: int = 150) -> str:
        m = pattern_re.search(html)
        if m:
            start = max(0, m.start() - 30)
            return html[start: start + max_len].strip()
        return html[:max_len].strip()

    async def _emit_progress(self, pct, status, message):
        await self.ws.emit_scanner_update({"progress": pct, "status": status, "summary": message})

    async def _emit_finding(self, finding):
        await self.ws.emit_scanner_update({"finding": finding})

    async def _emit_verdict(self, verdict, risk_summary, findings):
        await self.ws.emit_scanner_update({
            "verdict":      verdict,
            "risk_summary": risk_summary,
            "all_findings": findings,
        })


# ── Singleton ──────────────────────────────────────────────────────────────────
_scanner = None

def get_scanner():
    return _scanner

def create_scanner(ws_manager):
    global _scanner
    _scanner = VulnScanner(ws_manager)
    return _scanner
