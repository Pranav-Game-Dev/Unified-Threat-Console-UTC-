/* ═══════════════════════════════════════════════════════════════════════════
   UTC — Dashboard App  (Upgraded v2)
   Changelog:
   - Multi-protocol traffic chart (stacked line per protocol)
   - proto_pps / proto_totals from stats_update drive the chart live
   - File manager rebuilt: token-based, shows expiry, password badge, delete
   - Upload form supports optional expiry + password fields
   - runSimulation gives per-packet feedback via IDS alert stream
   - onStatsUpdate: top IPs now shows per-IP pps column
   - loadFileTransfers → loadFiles (uses /api/files/files endpoint)
   - All API paths audited and consistent
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
const state = {
  ws: null,
  wsReconnectTimer: null,
  currentSection: 'overview',
  isDark: true,

  totalPackets: 0,
  totalAlerts:  0,
  criticalAlerts: 0,
  suspiciousIPs: new Set(),
  ppsCount: 0,     // incremented per WS network_event, reset each second

  packets:   [],   // max 500
  alerts:    [],   // max 200
  logs:      [],   // max 500
  transfers: [],
  files:     [],   // stored file metadata

  charts: {},

  protocols: {},               // cumulative totals  {TCP: 1234, UDP: 456 …}
  protoPps:  {},               // per-protocol pps this second
  protoColors: {               // fallback until server sends colours
    TCP:'#00d4ff', UDP:'#00ff9d', DNS:'#9b59ff',
    ICMP:'#ffb300', ARP:'#00bfa5', OTHER:'#3d5068',
  },

  severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
  attackTypes:    {},

  // Rolling 60-second traffic histories (one entry per second, per protocol)
  trafficHistory: new Array(60).fill(0),  // total pps
  protoHistory: {},   // {TCP: [0,0,…], UDP: [0,0,…]} 60-item arrays

  alertHistory: new Array(20).fill(0),
};

// ── Section navigation ─────────────────────────────────────────────────────────
const sectionTitles = {
  overview:  'Overview',
  network:   'Network Monitor',
  threats:   'Threat Detection — IDS',
  scanner:   'Web Vulnerability Scanner',
  logs:      'Logs & Alerts',
  files:     'Secure File Transfer',
  simulator: 'Attack Simulator',
};

function navigate(section) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const el = document.getElementById('section-' + section);
  if (el) el.classList.add('active');
  const navEl = document.querySelector(`[data-section="${section}"]`);
  if (navEl) navEl.classList.add('active');
  document.getElementById('page-title').textContent = sectionTitles[section] || section;
  state.currentSection = section;

  if (section === 'network')   loadNetworkData();
  if (section === 'threats')   loadAlerts();
  if (section === 'scanner')   loadScanHistory();
  if (section === 'logs')      loadLogs();
  if (section === 'files')     loadFiles();
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function startClock() {
  const tick = () => {
    document.getElementById('clock').textContent =
      new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  };
  tick();
  setInterval(tick, 1000);
}

// ── Theme ─────────────────────────────────────────────────────────────────────
function toggleTheme() {
  state.isDark = !state.isDark;
  document.documentElement.setAttribute('data-theme', state.isDark ? 'dark' : 'light');
  document.getElementById('theme-track').classList.toggle('on', !state.isDark);
  document.getElementById('theme-label').textContent = state.isDark ? 'Dark' : 'Light';
  setTimeout(rebuildCharts, 50);
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
function connectWS() {
  const dot   = document.getElementById('ws-dot');
  const label = document.getElementById('ws-label');
  if (state.ws) { try { state.ws.close(); } catch(e){} }

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws    = new WebSocket(`${proto}//${location.host}/ws`);
  state.ws    = ws;

  ws.onopen = () => {
    dot.className   = 'ws-dot live';
    label.textContent = 'Live';
    clearTimeout(state.wsReconnectTimer);
    ws.send(JSON.stringify({ type: 'subscribe', channel: 'all' }));
  };

  ws.onmessage = (e) => {
    try { handleWSMessage(JSON.parse(e.data)); }
    catch(err) { console.warn('WS parse error:', err); }
  };

  ws.onclose = () => {
    dot.className   = 'ws-dot error';
    label.textContent = 'Reconnecting…';
    state.wsReconnectTimer = setTimeout(connectWS, 3000);
  };

  ws.onerror = () => ws.close();
}

function handleWSMessage(msg) {
  switch (msg.type) {
    case 'ping':          state.ws.send(JSON.stringify({type:'pong'})); break;
    case 'network_event': onNetworkEvent(msg.data);  break;
    case 'ids_alert':     onIDSAlert(msg.data);      break;
    case 'log_entry':     onLogEntry(msg.data);      break;
    case 'stats_update':  onStatsUpdate(msg.data);   break;
    case 'scanner_update':onScannerUpdate(msg.data); break;
    case 'file_event':    onFileEvent(msg.data);     break;
    case 'server_shutdown':
      showToast('Server stopping', msg.message || '', 'high'); break;
  }
}

// ── Network Event ─────────────────────────────────────────────────────────────
function onNetworkEvent(pkt) {
  state.totalPackets++;
  state.ppsCount++;

  if (pkt.suspicious) state.suspiciousIPs.add(pkt.src_ip);

  // Track protocol locally as well
  const proto = pkt.protocol || 'OTHER';
  state.protocols[proto] = (state.protocols[proto] || 0) + 1;

  state.packets.unshift(pkt);
  if (state.packets.length > 500) state.packets.pop();

  // Update counters
  qs('#ov-packets').textContent    = fmtNum(state.totalPackets);
  qs('#ov-suspicious').textContent = state.suspiciousIPs.size;
  qs('#net-total').textContent     = fmtNum(state.totalPackets);
  qs('#net-suspicious').textContent= state.suspiciousIPs.size;
  qs('#feed-count').textContent    = `${fmtNum(state.totalPackets)} packets`;

  // Active badge
  ['#capture-badge','#net-capture-status'].forEach(sel => {
    const el = qs(sel);
    if (el) { el.className = 'badge badge-ok'; el.textContent = 'ACTIVE'; }
  });

  prependFeedEntry(pkt);
  prependNetworkRow(pkt);
  updateProtoPills();
}

function prependFeedEntry(pkt) {
  const feed  = qs('#packet-feed');
  const empty = feed.querySelector('.empty-state');
  if (empty) empty.remove();

  const proto     = (pkt.protocol || 'OTHER').toLowerCase();
  const protoClass = `proto-${['tcp','udp','dns','icmp','arp'].includes(proto) ? proto : 'other'}`;

  const div = document.createElement('div');
  div.className = `feed-entry ${protoClass}` + (pkt.suspicious ? ' suspicious' : '');
  div.innerHTML = `
    <span class="feed-col ts">${fmtTime(pkt.timestamp)}</span>
    <span class="feed-col proto" style="color:${state.protoColors[pkt.protocol]||'#6b85a3'}">${pkt.protocol||'?'}</span>
    <span class="feed-col ip">${pkt.src_ip||'—'}</span>
    <span class="feed-col ip">${pkt.dst_ip||'—'}</span>
    <span class="feed-col port">${pkt.dst_port||'—'}</span>
    <span class="feed-col note">${escHtml(pkt.note||(pkt.suspicious?'⚠ suspicious':''))}</span>
  `;
  feed.appendChild(div);
  while (feed.children.length > 200) feed.removeChild(feed.firstChild);
}

function prependNetworkRow(pkt) {
  const tbody = qs('#net-packet-tbody');
  const empty = tbody.querySelector('.empty-state');
  if (empty) empty.closest('tr').remove();

  const color = state.protoColors[pkt.protocol] || '#6b85a3';
  const tr = document.createElement('tr');
  tr.className = 'new-row';
  tr.innerHTML = `
    <td class="cell-ts">${fmtTime(pkt.timestamp)}</td>
    <td style="color:${color};font-weight:500">${pkt.protocol||'?'}</td>
    <td class="cell-ip">${pkt.src_ip||'—'}</td>
    <td class="cell-ip">${pkt.dst_ip||'—'}</td>
    <td class="cell-port">${pkt.src_port||'—'}</td>
    <td class="cell-port">${pkt.dst_port||'—'}</td>
    <td class="cell-dim">${pkt.packet_size?fmtBytes(pkt.packet_size):'—'}</td>
    <td class="cell-dim">${pkt.flags||'—'}</td>
    <td>${pkt.suspicious
      ? '<span class="badge badge-medium">SUSPICIOUS</span>'
      : '<span class="badge badge-ok">OK</span>'}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > 300) tbody.removeChild(tbody.lastChild);
}

// ── IDS Alert ─────────────────────────────────────────────────────────────────
function onIDSAlert(alert) {
  state.totalAlerts++;
  const sev = alert.severity || 'medium';
  state.severityCounts[sev] = (state.severityCounts[sev] || 0) + 1;
  if (sev === 'critical') state.criticalAlerts++;

  const rule = alert.rule_name || 'unknown';
  state.attackTypes[rule] = (state.attackTypes[rule] || 0) + 1;

  state.alertHistory.push(1);
  if (state.alertHistory.length > 20) state.alertHistory.shift();

  state.alerts.unshift(alert);
  if (state.alerts.length > 200) state.alerts.pop();

  updateSeverityCounts();
  updateAlertBadge();
  prependAlertRow(alert);
  prependOverviewAlertRow(alert);
  updateAlertCharts();

  if (sev === 'critical' || sev === 'high') {
    showToast(
      `${sev.toUpperCase()}: ${alert.rule_name}`,
      alert.description || `Source: ${alert.src_ip || 'unknown'}`,
      sev
    );
  }

  // Mirror to log section
  onLogEntry({
    timestamp: alert.timestamp,
    source: 'ids',
    level: sev === 'critical' ? 'critical' : sev === 'high' ? 'error' : 'warning',
    message: `[${alert.rule_name}] ${alert.description || ''}`,
    flagged: true,
  });
}

function prependAlertRow(alert) {
  const tbody = qs('#alert-tbody');
  const empty = tbody.querySelector('.empty-state');
  if (empty) empty.closest('tr').remove();

  const sev = alert.severity || 'medium';
  const tr  = document.createElement('tr');
  tr.className = `new-row sev-${sev}`;
  const confColor = {high:'var(--accent-green)',medium:'var(--accent-amber)',low:'var(--text-muted)'};
  const conf = alert.confidence || 'medium';
  tr.innerHTML = `
    <td class="cell-ts">${fmtTime(alert.timestamp)}</td>
    <td><span class="badge badge-${sev}">${sev.toUpperCase()}</span></td>
    <td style="color:var(--text-primary);font-weight:500">${escHtml(alert.rule_name||'—')}</td>
    <td class="cell-ip">${alert.src_ip||'—'}</td>
    <td class="cell-port">${alert.dst_ip?`${alert.dst_ip}:${alert.dst_port||'?'}`:'—'}</td>
    <td class="cell-dim" style="max-width:180px" title="${escHtml(alert.explanation||'')}">${escHtml(alert.description||'—')}</td>
    <td style="font-size:0.6rem;color:${confColor[conf]||confColor.medium};white-space:nowrap">${conf.toUpperCase()}</td>
    <td><button class="btn btn-ghost" style="padding:2px 8px;font-size:0.6rem"
        onclick="ackAlert(${alert.id})">Ack</button></td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > 150) tbody.removeChild(tbody.lastChild);
}

function prependOverviewAlertRow(alert) {
  const tbody = qs('#ov-alert-table');
  const empty = tbody.querySelector('.empty-state');
  if (empty) empty.closest('tr').remove();

  const sev = alert.severity || 'medium';
  const tr  = document.createElement('tr');
  tr.className = 'new-row';
  tr.innerHTML = `
    <td class="cell-ts">${fmtTime(alert.timestamp)}</td>
    <td><span class="badge badge-${sev}">${sev.toUpperCase()}</span></td>
    <td>${escHtml(alert.rule_name||'—')}</td>
    <td class="cell-ip">${alert.src_ip||'—'}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > 10) tbody.removeChild(tbody.lastChild);
}

// ── Log Entry ─────────────────────────────────────────────────────────────────
function onLogEntry(entry) {
  state.logs.unshift(entry);
  if (state.logs.length > 500) state.logs.pop();
  prependLogLine(entry);
  updateLogStats();
}

function prependLogLine(entry) {
  const stream = qs('#log-stream');
  const empty  = stream.querySelector('.empty-state');
  if (empty) empty.remove();

  const lvl = entry.level || 'info';
  const div = document.createElement('div');
  div.className = 'log-line' + (entry.flagged ? ' flagged' : '') + ' new';
  div.innerHTML = `
    <span class="log-col ts">${fmtTime(entry.timestamp)}</span>
    <span class="log-col src">${entry.source||'sys'}</span>
    <span class="log-col lvl lvl-${lvl}">${lvl}</span>
    <span class="log-col msg">${escHtml(entry.message||'')}</span>
  `;
  stream.insertBefore(div, stream.firstChild);
  setTimeout(() => div.classList.remove('new'), 2000);
  while (stream.children.length > 400) stream.removeChild(stream.lastChild);
}

function updateLogStats() {
  const flagged  = state.logs.filter(l => l.flagged).length;
  const warnings = state.logs.filter(l =>
    ['warning','error','critical'].includes(l.level)).length;
  setInner('#log-flagged',  flagged);
  setInner('#log-warnings', warnings);
  setInner('#log-total',    state.logs.length);
}

// ── Stats Update (per second from server) ─────────────────────────────────────
function onStatsUpdate(data) {
  // Update proto colours map if server sends it
  if (data.proto_colors) {
    Object.assign(state.protoColors, data.proto_colors);
  }

  // Per-protocol pps snapshot
  if (data.proto_pps) {
    state.protoPps = data.proto_pps;
    // Advance each protocol's history array
    for (const [proto, pps] of Object.entries(data.proto_pps)) {
      if (!state.protoHistory[proto]) {
        state.protoHistory[proto] = new Array(60).fill(0);
      }
      state.protoHistory[proto].push(pps);
      if (state.protoHistory[proto].length > 60) state.protoHistory[proto].shift();
    }
    // Protocols that had 0 pps this second still need their arrays advanced
    for (const proto of Object.keys(state.protoHistory)) {
      if (!(proto in data.proto_pps)) {
        state.protoHistory[proto].push(0);
        if (state.protoHistory[proto].length > 60) state.protoHistory[proto].shift();
      }
    }
    // Update multi-protocol traffic chart
    updateMultiProtoChart();
  }

  // Cumulative protocol totals
  if (data.proto_totals) {
    Object.assign(state.protocols, data.proto_totals);
    updateProtoDonut();
  }

  // Total pps
  if (data.pps !== undefined) {
    const pps = data.pps;
    setInner('#ov-pps',        pps);
    setInner('#net-pps',       pps);
    setInner('#packets-live', `PKT/S: ${pps}`);
    // Update system health indicator
    updateSystemHealth(data);
  }

  // Top IPs with per-IP pps
  if (data.top_ips && data.top_ips.length) {
    renderTopIPs(data.top_ips);
  }
}

function renderTopIPs(ips) {
  const tbody = qs('#top-ips-tbody');
  if (!ips.length) return;
  tbody.innerHTML = ips.map(ip => `
    <tr>
      <td class="cell-ip">${ip.src_ip}</td>
      <td>${fmtNum(ip.cnt)}</td>
      <td style="color:var(--accent-amber)">${ip.pps||0} /s</td>
      <td>${ip.suspicious ? '<span class="badge badge-medium">YES</span>' : '—'}</td>
    </tr>
  `).join('');
}

// ── Scanner Events ─────────────────────────────────────────────────────────────
function onScannerUpdate(data) {
  if (data.progress !== undefined) {
    const bar = qs('#scan-progress-bar');
    if (bar) bar.style.width = data.progress + '%';
  }
  if (data.status) {
    const badge = qs('#scan-status-badge');
    if (badge) {
      badge.textContent = data.status.toUpperCase();
      badge.className   = 'badge badge-' +
        (data.status === 'running' ? 'active' : data.status === 'complete' ? 'ok' : 'inactive');
    }
  }
  if (data.finding) renderFinding(data.finding);
  if (data.summary) {
    const el = qs('#scan-summary');
    if (el) { el.textContent = data.summary; el.style.display = 'block'; }
  }
  if (data.verdict) renderVerdict(data.verdict, data.risk_summary);
  if (data.status === 'complete' || data.status === 'failed') {
    const btn = qs('#scan-btn');
    if (btn) btn.disabled = false;
    qs('#scan-progress-wrap').style.display = 'none';
    loadScanHistory();
  }
}

// Classification visual config
const CLASS_CONFIG = {
  confirmed:     { label: 'CONFIRMED',     color: 'var(--accent-red)',    icon: '🚨' },
  potential:     { label: 'POTENTIAL',     color: 'var(--accent-amber)',  icon: '⚠️' },
  informational: { label: 'INFO',          color: 'var(--text-secondary)', icon: 'ℹ️' },
};
const CONF_CONFIG = {
  high:   { label: 'HIGH CONFIDENCE',   color: 'var(--accent-green)' },
  medium: { label: 'MEDIUM CONFIDENCE', color: 'var(--accent-amber)' },
  low:    { label: 'LOW CONFIDENCE',    color: 'var(--text-muted)'  },
};

function renderFinding(finding) {
  const body  = qs('#findings-body');
  const empty = body.querySelector('.empty-state');
  if (empty) empty.remove();

  const cls   = finding.classification || 'informational';
  const conf  = finding.confidence     || 'medium';
  const sev   = finding.severity       || 'info';
  const cc    = CLASS_CONFIG[cls]  || CLASS_CONFIG.informational;
  const cfc   = CONF_CONFIG[conf]  || CONF_CONFIG.medium;

  const div = document.createElement('div');
  div.className = 'scan-finding';
  div.style.borderLeft = `3px solid ${cc.color}`;
  div.innerHTML = `
    <div class="scan-finding-title" style="gap:6px;flex-wrap:wrap">
      <span style="font-size:0.85rem">${cc.icon}</span>
      <span class="badge badge-${sev}">${sev.toUpperCase()}</span>
      <span style="font-size:0.6rem;padding:2px 6px;border-radius:2px;border:1px solid ${cc.color};color:${cc.color};font-weight:600">${cc.label}</span>
      <span style="font-size:0.6rem;color:${cfc.color};margin-left:auto">${cfc.label}</span>
      <span>${escHtml(finding.type||'—')}</span>
    </div>
    <div class="scan-finding-detail">${escHtml(finding.description||'')}</div>
    ${finding.explanation ? `<div class="scan-finding-detail" style="color:var(--text-muted);font-style:italic;margin-top:2px">${escHtml(finding.explanation)}</div>` : ''}
    <div class="scan-finding-url">${escHtml(finding.url||'')}</div>
    ${finding.payload ? `<div class="scan-finding-url" style="color:var(--accent-amber)">Payload: ${escHtml(finding.payload)}</div>` : ''}
    ${finding.evidence ? `<div class="scan-finding-url" style="color:var(--text-muted)">Evidence: ${escHtml(finding.evidence.slice(0,120))}</div>` : ''}
  `;
  body.insertBefore(div, body.firstChild);

  const countEl = qs('#finding-count');
  if (countEl) {
    const n = body.querySelectorAll('.scan-finding').length;
    countEl.textContent = `${n} found`;
  }
}

// ── File Events ────────────────────────────────────────────────────────────────
function onFileEvent(evt) {
  if (evt.direction === 'upload') {
    setInner('#file-uploads', (parseInt(qs('#file-uploads').textContent)||0)+1);
    setInner('#file-total',   (parseInt(qs('#file-total').textContent)||0)+1);
    // Refresh the file list so new file appears immediately
    loadFiles();
  } else if (evt.direction === 'download') {
    setInner('#file-downloads', (parseInt(qs('#file-downloads').textContent)||0)+1);
  } else if (evt.direction === 'delete') {
    loadFiles();
  }
  prependTransferRow(evt);
}

function prependTransferRow(t) {
  const tbody = qs('#transfer-tbody');
  if (!tbody) return;
  const empty = tbody.querySelector('.empty-state');
  if (empty) empty.closest('tr').remove();

  const tr = document.createElement('tr');
  tr.className = 'new-row';
  tr.innerHTML = `
    <td class="cell-ts">${fmtTime(t.timestamp || new Date().toISOString())}</td>
    <td><span class="badge ${
      t.direction==='upload'   ? 'badge-ok'       :
      t.direction==='download' ? 'badge-active'   : 'badge-critical'
    }">${(t.direction||'').toUpperCase()}</span></td>
    <td style="max-width:140px;overflow:hidden;text-overflow:ellipsis">${escHtml(t.original_name||'—')}</td>
    <td class="cell-dim">${t.file_size_bytes ? fmtBytes(t.file_size_bytes) : '—'}</td>
    <td class="file-enc">${t.encryption_alg||'AES-256-GCM'}</td>
    <td><span class="badge ${t.status==='ok'?'badge-ok':'badge-critical'}">${(t.status||'ok').toUpperCase()}</span></td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
}

// ── Charts ────────────────────────────────────────────────────────────────────
function chartDefaults() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 150 },
    plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
  };
}

// Multi-protocol stacked line chart (replaces single-line traffic chart)
function buildMultiProtoChart(canvasId) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  if (state.charts[canvasId]) state.charts[canvasId].destroy();

  const labels   = Array.from({ length: 60 }, (_, i) => `-${60-i}s`);
  const datasets = Object.entries(state.protoColors).map(([proto, color]) => ({
    label: proto,
    data:  state.protoHistory[proto] ? [...state.protoHistory[proto]] : new Array(60).fill(0),
    borderColor: color,
    backgroundColor: color + '18',
    borderWidth: 1.5,
    fill: false,
    tension: 0.4,
    pointRadius: 0,
  }));

  const chart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets },
    options: {
      ...chartDefaults(),
      plugins: {
        legend: {
          display: true,
          position: 'bottom',
          labels: {
            color:    state.isDark ? '#6b85a3' : '#4a637d',
            font:     { size: 9, family: 'JetBrains Mono' },
            boxWidth: 8,
            padding:  6,
          },
        },
        tooltip: { mode: 'index', intersect: false },
      },
      scales: {
        x: { display: false },
        y: {
          min: 0,
          stacked: false,
          grid:  { color: state.isDark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.04)' },
          ticks: { color: state.isDark ? '#3d5068' : '#8fa4b8',
                   maxTicksLimit: 4, font: { size: 9, family: 'JetBrains Mono' } },
        },
      },
    },
  });
  state.charts[canvasId] = chart;
  return chart;
}

function updateMultiProtoChart() {
  ['traffic-chart', 'net-traffic-chart'].forEach(id => {
    const c = state.charts[id];
    if (!c) return;
    // Update existing datasets or add new ones
    const existingLabels = c.data.datasets.map(d => d.label);
    for (const [proto, history] of Object.entries(state.protoHistory)) {
      const idx = existingLabels.indexOf(proto);
      if (idx >= 0) {
        c.data.datasets[idx].data = [...history];
      } else {
        const color = state.protoColors[proto] || '#6b85a3';
        c.data.datasets.push({
          label: proto,
          data:  [...history],
          borderColor: color,
          backgroundColor: color + '18',
          borderWidth: 1.5,
          fill: false,
          tension: 0.4,
          pointRadius: 0,
        });
        c.options.plugins.legend.display = true;
      }
    }
    c.update('none');
  });
}

function buildDonutChart(canvasId, labels, data, colors) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  if (state.charts[canvasId]) state.charts[canvasId].destroy();

  const chart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0, hoverOffset: 4 }] },
    options: {
      ...chartDefaults(),
      cutout: '68%',
      plugins: {
        legend: {
          display: true,
          position: 'right',
          labels: {
            color: state.isDark ? '#6b85a3' : '#4a637d',
            font:  { size: 9, family: 'JetBrains Mono' },
            boxWidth: 8, padding: 6,
          },
        },
      },
    },
  });
  state.charts[canvasId] = chart;
  return chart;
}

function buildBarChart(canvasId, labels, data, color) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  if (state.charts[canvasId]) state.charts[canvasId].destroy();

  const chart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: color || (state.isDark ? 'rgba(255,59,92,0.5)' : 'rgba(196,0,46,0.4)'),
        borderColor:     color || (state.isDark ? '#ff3b5c' : '#c4002e'),
        borderWidth: 1,
        borderRadius: 1,
      }],
    },
    options: {
      ...chartDefaults(),
      scales: {
        x: { ticks: { color: state.isDark?'#3d5068':'#8fa4b8', font:{size:8,family:'JetBrains Mono'} }, grid:{display:false} },
        y: { min:0, ticks:{maxTicksLimit:4,color:state.isDark?'#3d5068':'#8fa4b8',font:{size:8,family:'JetBrains Mono'}}, grid:{color:state.isDark?'rgba(255,255,255,0.04)':'rgba(0,0,0,0.04)'} },
      },
    },
  });
  state.charts[canvasId] = chart;
  return chart;
}

function updateProtoDonut() {
  const c = state.charts['proto-chart'];
  if (!c) return;
  const protos = Object.keys(state.protocols);
  if (!protos.length) return;
  c.data.labels = protos;
  c.data.datasets[0].data = protos.map(p => state.protocols[p]);
  c.data.datasets[0].backgroundColor = protos.map(p => state.protoColors[p] || '#3d5068');
  c.update('none');
  // Top proto label
  const top = Object.entries(state.protocols).sort((a,b) => b[1]-a[1])[0];
  if (top) setInner('#net-top-proto', top[0]);
}

function updateAlertCharts() {
  const tc = state.charts['alert-timeline-chart'];
  if (tc) { tc.data.datasets[0].data = [...state.alertHistory]; tc.update('none'); }

  const ac = state.charts['attack-type-chart'];
  if (ac) {
    const types      = Object.keys(state.attackTypes);
    const typeColors = ['#ff3b5c','#ff6b35','#ffb300','#9b59ff','#00d4ff','#00bfa5'];
    ac.data.labels = types;
    ac.data.datasets[0].data = types.map(t => state.attackTypes[t]);
    ac.data.datasets[0].backgroundColor = types.map((_,i) => typeColors[i % typeColors.length]);
    ac.update('none');
  }
}

function initCharts() {
  buildMultiProtoChart('traffic-chart');
  buildMultiProtoChart('net-traffic-chart');
  buildDonutChart('proto-chart',       ['—'], [1], ['#3d5068']);
  buildDonutChart('attack-type-chart', ['—'], [1], ['#3d5068']);
  buildBarChart('alert-timeline-chart',
    Array.from({length:20},(_,i)=>'-'+(20-i)+'m'),
    state.alertHistory
  );
}

function rebuildCharts() {
  Object.keys(state.charts).forEach(id => {
    if (state.charts[id]) { state.charts[id].destroy(); delete state.charts[id]; }
  });
  initCharts();
}

// Per-second tick — local ppsCount drives traffic history fallback
function tickTrafficChart() {
  const pps = state.ppsCount;
  state.ppsCount = 0;

  state.trafficHistory.push(pps);
  if (state.trafficHistory.length > 60) state.trafficHistory.shift();
  // If no proto data yet, show total in first protocol slot
  if (!Object.keys(state.protoHistory).length && pps > 0) {
    if (!state.protoHistory['ALL']) state.protoHistory['ALL'] = new Array(60).fill(0);
    state.protoHistory['ALL'].push(pps);
    if (state.protoHistory['ALL'].length > 60) state.protoHistory['ALL'].shift();
    updateMultiProtoChart();
  }
}

// ── Protocol Pills ─────────────────────────────────────────────────────────────
function updateProtoPills() {
  const el = qs('#proto-pills');
  if (!el) return;
  const top = Object.entries(state.protocols).sort((a,b) => b[1]-a[1]).slice(0, 6);
  el.innerHTML = top.map(([p, cnt]) => `
    <span class="proto-pill">
      <span class="dot" style="background:${state.protoColors[p]||'#6b85a3'}"></span>
      ${p} <span style="color:var(--text-muted)">${fmtNum(cnt)}</span>
    </span>
  `).join('');
}

// ── Alert Counts ───────────────────────────────────────────────────────────────
function updateSeverityCounts() {
  const sc = state.severityCounts;
  setInner('#sev-critical', sc.critical||0);
  setInner('#sev-high',     sc.high    ||0);
  setInner('#sev-medium',   sc.medium  ||0);
  setInner('#sev-low',      sc.low     ||0);
  setInner('#ov-alerts',    state.totalAlerts);
  setInner('#ov-critical',  sc.critical||0);
  updateThreatLevel();
}

function updateAlertBadge() {
  const badge = qs('#threat-badge');
  const pip   = qs('#alert-pip');
  if (!badge) return;
  if (state.totalAlerts > 0) {
    badge.textContent    = state.totalAlerts > 99 ? '99+' : state.totalAlerts;
    badge.style.display  = 'inline-block';
    if (pip) pip.classList.add('visible');
  } else {
    badge.style.display  = 'none';
    if (pip) pip.classList.remove('visible');
  }
}

// ── API Loaders ────────────────────────────────────────────────────────────────
async function loadNetworkData() {
  try {
    const [stats, events] = await Promise.all([
      api('/api/network/stats'),
      api('/api/network/events?limit=100'),
    ]);
    if (stats) {
      setInner('#net-total',      fmtNum(stats.total_packets||0));
      setInner('#net-suspicious', fmtNum(stats.suspicious_packets||0));
      if (stats.top_sources) renderTopIPs(stats.top_sources);
    }
    if (events && events.length) {
      const tbody = qs('#net-packet-tbody');
      tbody.innerHTML = '';
      events.slice(0, 100).forEach(pkt => prependNetworkRow(pkt));
    }
  } catch(e) { console.warn('loadNetworkData:', e); }
}

async function loadAlerts() {
  try {
    const sev = qs('#threat-filter-sev')?.value || '';
    const url = '/api/threats/alerts?limit=100' + (sev ? `&severity=${sev}` : '');
    const [alerts, counts] = await Promise.all([api(url), api('/api/threats/counts')]);

    if (counts) { state.severityCounts = counts; updateSeverityCounts(); }

    if (alerts && alerts.length) {
      const tbody = qs('#alert-tbody');
      tbody.innerHTML = '';
      // Merge severity counts from fetched data
      state.totalAlerts = alerts.length;
      alerts.forEach(a => {
        const sev = a.severity || 'medium';
        state.severityCounts[sev] = (state.severityCounts[sev] || 0) + 1;
        prependAlertRow(a);
      });
      updateAlertBadge();
      updateThreatLevel();
    }
  } catch(e) { console.warn('loadAlerts:', e); }
}

async function loadScanHistory() {
  try {
    const reports = await api('/api/scanner/reports?limit=20');
    if (!reports || !reports.length) return;
    qs('#scan-history-tbody').innerHTML = reports.map(r => `
      <tr>
        <td class="cell-ts">${fmtTime(r.timestamp)}</td>
        <td class="cell-dim" style="max-width:120px;overflow:hidden;text-overflow:ellipsis">
          ${escHtml(r.target_url)}</td>
        <td><span class="badge badge-inactive">${r.scan_type||'full'}</span></td>
        <td style="color:${r.vulns_found>0?'var(--accent-red)':'var(--accent-green)'}">
          ${r.vulns_found||0}</td>
        <td><span class="badge ${r.status==='complete'?'badge-ok':r.status==='running'?'badge-active':'badge-inactive'}">
          ${r.status}</span></td>
      </tr>
    `).join('');
  } catch(e) { console.warn('loadScanHistory:', e); }
}

async function loadLogs() {
  try {
    const src     = qs('#log-filter-source')?.value  || '';
    const lvl     = qs('#log-filter-level')?.value   || '';
    const flagged = qs('#log-filter-flagged')?.checked || false;
    let url = '/api/logs/?limit=200';
    if (src)     url += `&source=${src}`;
    if (lvl)     url += `&level=${lvl}`;
    if (flagged) url += `&flagged=true`;

    const logs = await api(url);
    if (!logs) return;
    const stream = qs('#log-stream');
    stream.innerHTML = '';
    if (!logs.length) {
      stream.innerHTML = '<div class="empty-state">No log entries match filter</div>';
      return;
    }
    logs.forEach(l => prependLogLine(l));
    state.logs = logs;
    updateLogStats();
  } catch(e) { console.warn('loadLogs:', e); }
}

// ── File Manager (Upgraded) ────────────────────────────────────────────────────
async function loadFiles() {
  try {
    // Use the new /files endpoint which returns disk-verified metadata
    const files = await api('/api/files/files');
    if (!files) return;
    state.files = files;

    const fileBody = qs('#file-list-body');
    if (!files.length) {
      fileBody.innerHTML = '<div class="empty-state">No files stored yet</div>';
      setInner('#file-total', 0);
      return;
    }

    setInner('#file-total', files.length);

    fileBody.innerHTML = files.map(f => `
      <div class="file-item" id="fi-${f.token}">
        <div style="display:flex;flex-direction:column;flex:1;min-width:0;gap:2px">
          <span class="file-name">${escHtml(f.original_name)}</span>
          <span style="font-size:0.6rem;color:var(--text-muted)">
            ${fmtBytes(f.file_size_bytes||0)} &nbsp;·&nbsp;
            ${fmtTime(f.upload_time)} &nbsp;·&nbsp;
            ${f.download_count||0} downloads
            ${f.expiry_time ? ` &nbsp;·&nbsp; expires ${fmtTime(f.expiry_time)}` : ''}
            ${f.expired ? ' <span class="badge badge-critical">EXPIRED</span>' : ''}
          </span>
        </div>
        <div style="display:flex;gap:4px;align-items:center;flex-shrink:0">
          ${f.password_protected ? '<span class="badge badge-medium">🔒</span>' : ''}
          <span class="file-enc">AES-256</span>
          <button class="btn btn-ghost" style="padding:2px 8px;font-size:0.6rem"
            onclick="downloadFileByToken('${escAttr(f.token)}','${escAttr(f.original_name)}',${!!f.password_protected})">
            ↓ Download
          </button>
          <button class="btn btn-danger" style="padding:2px 8px;font-size:0.6rem"
            onclick="deleteFile('${escAttr(f.token)}')">
            Delete
          </button>
        </div>
      </div>
    `).join('');

    // Also refresh transfer history
    const transfers = await api('/api/files/transfers?limit=50');
    if (transfers && transfers.length) {
      const tbody = qs('#transfer-tbody');
      tbody.innerHTML = '';
      transfers.forEach(t => prependTransferRow(t));
      const ups  = transfers.filter(t => t.direction==='upload').length;
      const dnls = transfers.filter(t => t.direction==='download').length;
      setInner('#file-uploads',   ups);
      setInner('#file-downloads', dnls);
    }
  } catch(e) { console.warn('loadFiles:', e); }
}

async function downloadFileByToken(token, originalName, passwordProtected) {
  let url = `/api/files/download/${encodeURIComponent(token)}`;
  if (passwordProtected) {
    const pw = prompt(`"${originalName}" is password protected.\nEnter password:`);
    if (pw === null) return;   // user cancelled
    url += `?password=${encodeURIComponent(pw)}`;
  }
  try {
    const res = await fetch(url);
    if (res.status === 401) { showToast('Password Required', 'Incorrect or missing password', 'medium'); return; }
    if (res.status === 410) { showToast('Expired', 'This file has expired', 'high'); return; }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Download failed');
    }
    const blob = await res.blob();
    const burl = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = burl; a.download = originalName || token;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(burl);
    showToast('Download complete', originalName, 'info');
  } catch(e) {
    showToast('Download failed', e.message, 'high');
  }
}

async function deleteFile(token) {
  if (!confirm('Permanently delete this file? This cannot be undone.')) return;
  try {
    await api(`/api/files/delete/${encodeURIComponent(token)}`, 'DELETE');
    // Remove from DOM immediately
    const el = document.getElementById(`fi-${token}`);
    if (el) el.remove();
    showToast('Deleted', 'File securely erased', 'info');
    loadFiles();
  } catch(e) {
    showToast('Delete failed', e.message, 'high');
  }
}

// ── Actions ────────────────────────────────────────────────────────────────────
async function startScan() {
  const target = qs('#scan-target')?.value?.trim();
  const type   = qs('#scan-type')?.value || 'full';
  if (!target) { showToast('Missing target', 'Enter a URL to scan', 'medium'); return; }

  qs('#scan-btn').disabled = true;
  qs('#scan-progress-wrap').style.display = 'block';
  qs('#scan-progress-bar').style.width    = '0%';
  qs('#findings-body').innerHTML          = '';
  qs('#finding-count').textContent        = '0 found';
  qs('#scan-summary').style.display       = 'none';

  const badge  = qs('#scan-status-badge');
  badge.textContent = 'RUNNING';
  badge.className   = 'badge badge-active';

  try {
    const res = await api('/api/scanner/scan', 'POST', { target_url: target, scan_type: type });
    if (!res) throw new Error('No response from scan API');
  } catch(e) {
    qs('#scan-btn').disabled = false;
    qs('#scan-progress-wrap').style.display = 'none';
    badge.textContent = 'ERROR';
    badge.className   = 'badge badge-critical';
    showToast('Scan failed', String(e), 'high');
  }
}

async function ackAlert(id) {
  try {
    await api(`/api/threats/alerts/${id}/acknowledge`, 'POST');
    loadAlerts();
  } catch(e) { showToast('Error', 'Could not acknowledge alert', 'medium'); }
}

async function acknowledgeAll() {
  try {
    const btns = qs('#alert-tbody')?.querySelectorAll('button') || [];
    for (const btn of btns) btn.click();
    showToast('Acknowledged', 'All visible alerts acknowledged', 'info');
  } catch(e) { console.warn('acknowledgeAll:', e); }
}

function clearAlertList() {
  // Visually clears the alert table from the current view (does not delete from DB)
  const tbody = qs('#alert-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state">Alert list cleared — new alerts will appear here</div></td></tr>';
  // Reset local severity counts for display only
  state.severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  state.totalAlerts    = 0;
  state.criticalAlerts = 0;
  updateSeverityCounts();
  updateAlertBadge();
  // Hide the alert pip since list is cleared
  const pip = qs('#alert-pip');
  if (pip) pip.classList.remove('visible');
  const badge = qs('#threat-badge');
  if (badge) badge.style.display = 'none';
  showToast('List cleared', 'Alert list cleared from view. Use Refresh to reload from DB.', 'info');
}

function applyNetworkFilter() {
  const proto   = qs('#net-filter-proto')?.value   || '';
  const suspOnly = qs('#net-filter-suspicious')?.checked || false;
  qs('#net-packet-tbody')?.querySelectorAll('tr').forEach(tr => {
    const cells   = tr.querySelectorAll('td');
    if (cells.length < 2) return;
    const rowProto = cells[1]?.textContent?.trim() || '';
    const isSusp   = cells[8]?.textContent?.includes('SUSPICIOUS') || false;
    tr.style.display = ((!proto || rowProto === proto) && (!suspOnly || isSusp)) ? '' : 'none';
  });
}

async function runSimulation(type) {
  const logEl = qs('#sim-log');
  const ts    = new Date().toISOString().slice(11, 19);
  const label = '[SIM MODE]';
  logEl.innerHTML += `
    <div style="color:var(--accent-amber);border-top:1px solid var(--border-dim);padding-top:6px;margin-top:6px">
      <span style="color:var(--text-muted);font-size:0.6rem">${label}</span> [${ts}] ► Launching <strong>${type}</strong> simulation
    </div>
    <div style="color:var(--text-muted);font-size:0.65rem">${label} Synthetic packets only — all events tagged [SIM] in logs</div>
  `;
  logEl.scrollTop = logEl.scrollHeight;

  try {
    const res = await api('/api/threats/simulate', 'POST', { attack_type: type });
    if (res && res.result) {
      const r = res.result;
      logEl.innerHTML += `
        <div style="color:var(--text-secondary)">${label} [${ts}] Injected ${r.packets||'?'} packets from <span style="color:var(--accent-cyan)">${r.src||'?'}</span></div>
        <div style="color:var(--accent-green)">${label} [${ts}] ✓ Synthetic packets in IDS pipeline — alerts appear in Threats section</div>
      `;
    }
  } catch(e) {
    logEl.innerHTML += `<div style="color:var(--accent-red)">${label} [${ts}] ✗ ${e.message}</div>`;
  }
  logEl.scrollTop = logEl.scrollHeight;
}

function handleFileDrop(e) {
  e.preventDefault();
  qs('#drop-zone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) uploadFile(file);
}

async function uploadFile(file) {
  if (!file) return;
  const wrap  = qs('#upload-progress-wrap');
  const bar   = qs('#upload-progress-bar');
  const stat  = qs('#upload-status');

  wrap.style.display = 'block';
  bar.style.width    = '10%';
  stat.textContent   = 'Encrypting...';

  const expiryHours   = qs('#upload-expiry-hours')?.value   || '';
  const expiryMinutes = qs('#upload-expiry-minutes')?.value || '';
  const password      = qs('#upload-password')?.value || '';

  const form = new FormData();
  form.append('file', file);
  if (expiryHours)   form.append('expiry_hours',   expiryHours);
  if (expiryMinutes) form.append('expiry_minutes', expiryMinutes);

  try {
    bar.style.width  = '40%';
    stat.textContent = 'Uploading & encrypting...';
    const res = await fetch('/api/files/upload', { method: 'POST', body: form });
    bar.style.width  = '100%';

    if (res.ok) {
      const data = await res.json();
      stat.textContent = `Encrypted & stored. Token: ${data.token}`;
      stat.style.color = 'var(--accent-green)';
      // Clear optional fields
      if (qs('#upload-password'))       qs('#upload-password').value       = '';
      if (qs('#upload-expiry-hours'))   qs('#upload-expiry-hours').value   = '';
      if (qs('#upload-expiry-minutes')) qs('#upload-expiry-minutes').value = '';
      setTimeout(() => { wrap.style.display = 'none'; stat.style.color = ''; }, 3000);
      loadFiles();
    } else {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Upload failed');
    }
  } catch(e) {
    bar.style.background = 'var(--accent-red)';
    stat.textContent     = 'Error: ' + e.message;
    stat.style.color     = 'var(--accent-red)';
    setTimeout(() => {
      wrap.style.display    = 'none';
      bar.style.background  = '';
      stat.style.color      = '';
    }, 3500);
  }
}

// ── Toast Notifications ────────────────────────────────────────────────────────
const SEVERITY_ICONS = {critical:'🔴', high:'🟠', medium:'🟡', low:'🔵', info:'ℹ️'};

function showToast(title, message, severity = 'info') {
  const container = qs('#toast-container');
  const toast     = document.createElement('div');
  toast.className = `toast ${severity}`;
  toast.innerHTML = `
    <span class="toast-icon">${SEVERITY_ICONS[severity]||'ℹ️'}</span>
    <div class="toast-body">
      <div class="toast-title">${escHtml(title)}</div>
      <div class="toast-msg">${escHtml(String(message).slice(0,200))}</div>
    </div>
  `;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'toastOut 0.3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

// ── API Helper ─────────────────────────────────────────────────────────────────
async function api(url, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res  = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Utilities ──────────────────────────────────────────────────────────────────
const qs       = sel => document.querySelector(sel);
const setInner = (sel, val) => { const el = qs(sel); if (el) el.textContent = val; };

function fmtNum(n) {
  n = Number(n) || 0;
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return String(n);
}

function fmtBytes(b) {
  b = Number(b) || 0;
  if (b >= 1048576) return (b/1048576).toFixed(1) + ' MB';
  if (b >= 1024)    return (b/1024).toFixed(1)    + ' KB';
  return b + ' B';
}

function fmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toISOString().slice(11, 19); }
  catch(e) { return String(ts).slice(11, 19) || ts; }
}

function escHtml(s) {
  return String(s||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function escAttr(s) {
  return String(s||'').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}


// ── System Health Indicator ────────────────────────────────────────────────────
function updateSystemHealth(statsData) {
  const dot   = document.getElementById('health-dot');
  const label = document.getElementById('health-label');
  if (!dot || !label) return;

  // Determine mode: demo or real
  const isDemo = !statsData._scapy_live;  // server sets this flag
  const pps    = statsData.pps || 0;

  if (isDemo) {
    dot.style.background   = '#ffb300';
    label.style.color      = '#ffb300';
    label.textContent      = 'DEMO MODE';
    label.title            = 'Running synthetic packet generator — Scapy not available or no admin rights';
  } else if (pps > 0) {
    dot.style.background   = 'var(--accent-green)';
    label.style.color      = 'var(--accent-green)';
    label.textContent      = 'LIVE CAPTURE';
    label.title            = 'Real packet capture active via Scapy';
  } else {
    dot.style.background   = 'var(--accent-cyan)';
    label.style.color      = 'var(--accent-cyan)';
    label.textContent      = 'MONITORING';
    label.title            = 'System active — waiting for traffic';
  }
}

// ── Threat Level Indicator ─────────────────────────────────────────────────────
function updateThreatLevel() {
  const el = document.getElementById('threat-level');
  if (!el) return;

  const critical = state.severityCounts.critical || 0;
  const high     = state.severityCounts.high     || 0;
  const medium   = state.severityCounts.medium   || 0;

  let level, color;
  if (critical > 0) {
    level = 'CRITICAL';  color = 'var(--accent-red)';
  } else if (high > 0) {
    level = 'HIGH';      color = 'var(--severity-high)';
  } else if (medium > 0) {
    level = 'ELEVATED';  color = 'var(--accent-amber)';
  } else if (state.totalAlerts > 0) {
    level = 'GUARDED';   color = 'var(--accent-cyan)';
  } else {
    level = 'NONE';      color = 'var(--text-muted)';
  }

  el.textContent   = `THREAT: ${level}`;
  el.style.color   = color;
  el.title         = `${critical} critical, ${high} high, ${medium} medium alerts`;
}

// ── Scan Verdict Panel ─────────────────────────────────────────────────────────
function renderVerdict(verdict, summary) {
  const panel = document.getElementById('scan-verdict-panel');
  if (!panel) return;
  panel.style.display = 'block';

  const badge  = document.getElementById('verdict-badge');
  const expl   = document.getElementById('verdict-explanation');
  const tsEl   = document.getElementById('verdict-timestamp');
  const typeSu = document.getElementById('verdict-type-summary');

  const VERDICTS = {
    'VULNERABLE': {
      icon:  '🚨 VULNERABLE',
      color: 'var(--accent-red)',
      text:  'One or more confirmed vulnerabilities found. Review confirmed findings immediately.'
    },
    'SUSPICIOUS': {
      icon:  '⚠️ SUSPICIOUS',
      color: 'var(--accent-amber)',
      text:  'Potential issues found that need manual verification. No confirmed exploits detected.'
    },
    'SAFE': {
      icon:  '✅ SAFE',
      color: 'var(--accent-green)',
      text:  'No confirmed vulnerabilities detected. Informational notes may still be worth reviewing.'
    },
  };

  const cfg = VERDICTS[verdict] || VERDICTS['SAFE'];
  if (badge) { badge.textContent = cfg.icon; badge.style.color = cfg.color; }
  if (expl)  expl.textContent = cfg.text;
  if (tsEl)  tsEl.textContent = fmtTime(new Date().toISOString());

  if (summary) {
    setInner('#vs-confirmed', summary.confirmed || 0);
    setInner('#vs-potential', summary.potential || 0);
    setInner('#vs-info',      summary.informational || 0);

    // Type breakdown pills
    if (typeSu && summary.by_type) {
      typeSu.innerHTML = Object.entries(summary.by_type)
        .sort((a,b) => b[1]-a[1])
        .slice(0, 8)
        .map(([t, n]) =>
          `<span style="font-size:0.62rem;padding:2px 8px;border-radius:2px;background:var(--bg-elevated);border:1px solid var(--border-mid);color:var(--text-secondary)">
            ${escHtml(t)} <strong style="color:var(--text-primary)">${n}</strong>
          </span>`
        ).join('');
    }
  }
}

// ── Init ───────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  initCharts();
  connectWS();

  // Per-second chart tick
  setInterval(tickTrafficChart, 1000);

  // Periodic refresh fallback for sections that may miss WS events
  setInterval(() => {
    if (state.currentSection === 'threats') loadAlerts();
    if (state.currentSection === 'logs')    loadLogs();
    if (state.currentSection === 'files')   loadFiles();
  }, 20000);

  // Load initial topbar info + set initial health state
  api('/api/info').then(info => {
    if (!info) return;
    // Set initial health from server info
    const dot   = document.getElementById('health-dot');
    const label = document.getElementById('health-label');
    const isDemo = info.demo_mode !== false;  // server sets demo_mode flag
    if (dot && label) {
      if (isDemo) {
        dot.style.background = '#ffb300';
        label.style.color    = '#ffb300';
        label.textContent    = 'DEMO MODE';
        label.title          = 'Synthetic packet generator active';
      } else {
        dot.style.background = 'var(--accent-green)';
        label.style.color    = 'var(--accent-green)';
        label.textContent    = 'LIVE CAPTURE';
      }
    }
  }).catch(() => {
    const dot = document.getElementById('health-dot');
    const lbl = document.getElementById('health-label');
    if (dot) dot.style.background = 'var(--accent-red)';
    if (lbl) { lbl.style.color = 'var(--accent-red)'; lbl.textContent = 'OFFLINE'; }
  });

  console.log('%c UTC — Unified Threat Console v2 ', 'background:#00d4ff;color:#080b0f;font-weight:bold;padding:2px 6px');
  console.log('%c Multi-protocol · Upgraded IDS · Full file manager', 'color:#6b85a3');
});
