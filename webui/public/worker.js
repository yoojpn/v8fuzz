/**
 * Cloudflare Workers - v8fuzz API + Dashboard
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Secret',
};

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>v8fuzz / dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #080a0e;
    --surface: #0d1117;
    --border: #1c2230;
    --accent: #00ff88;
    --accent2: #ff3c6e;
    --accent3: #3c8eff;
    --text: #e2e8f0;
    --muted: #4a5568;
    --critical: #ff3c6e;
    --high: #ff8c42;
    --medium: #ffd166;
    --low: #06d6a0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    min-height: 100vh;
    overflow-x: hidden;
  }
  /* grid bg */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  header {
    position: relative;
    z-index: 10;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 32px;
    border-bottom: 1px solid var(--border);
    background: rgba(8,10,14,0.9);
    backdrop-filter: blur(12px);
  }
  .logo {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 22px;
    letter-spacing: -0.5px;
  }
  .logo span { color: var(--accent); }
  .status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent);
    animation: pulse 2s infinite;
    display: inline-block;
    margin-right: 8px;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; }
    50% { opacity: 0.3; }
  }
  .header-right {
    display: flex;
    align-items: center;
    gap: 24px;
    font-size: 12px;
    color: var(--muted);
  }
  .live-badge {
    background: rgba(0,255,136,0.1);
    border: 1px solid rgba(0,255,136,0.3);
    color: var(--accent);
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
  }

  main {
    position: relative;
    z-index: 1;
    padding: 32px;
    max-width: 1400px;
    margin: 0 auto;
  }

  /* KPI strip */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 32px;
  }
  .kpi {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 24px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }
  .kpi:hover { border-color: var(--accent); }
  .kpi::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent);
    opacity: 0.6;
  }
  .kpi.red::after { background: var(--accent2); }
  .kpi.blue::after { background: var(--accent3); }
  .kpi.orange::after { background: var(--high); }
  .kpi-label {
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 10px;
  }
  .kpi-value {
    font-family: 'Syne', sans-serif;
    font-size: 36px;
    font-weight: 800;
    line-height: 1;
    color: var(--text);
  }
  .kpi-sub {
    font-size: 11px;
    color: var(--muted);
    margin-top: 6px;
  }

  /* Two-col layout */
  .grid2 {
    display: grid;
    grid-template-columns: 1fr 380px;
    gap: 20px;
    margin-bottom: 20px;
  }

  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
  }
  .panel-header span { color: var(--accent); font-size: 10px; }

  /* Crash table */
  .crash-table { width: 100%; }
  .crash-row {
    display: grid;
    grid-template-columns: 80px 100px 1fr 80px 70px 90px;
    align-items: center;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
    transition: background 0.15s;
    cursor: pointer;
  }
  .crash-row:hover { background: rgba(255,255,255,0.03); }
  .crash-row.header {
    font-size: 10px;
    letter-spacing: 1px;
    color: var(--muted);
    cursor: default;
    background: transparent;
  }
  .crash-row.header:hover { background: transparent; }
  .sev {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
  }
  .sev.CRITICAL { background: rgba(255,60,110,0.15); color: var(--critical); border: 1px solid rgba(255,60,110,0.3); }
  .sev.HIGH     { background: rgba(255,140,66,0.15); color: var(--high);     border: 1px solid rgba(255,140,66,0.3); }
  .sev.MEDIUM   { background: rgba(255,209,102,0.15);color: var(--medium);   border: 1px solid rgba(255,209,102,0.3);}
  .sev.LOW      { background: rgba(6,214,160,0.15);  color: var(--low);      border: 1px solid rgba(6,214,160,0.3); }
  .crash-id { color: var(--accent); font-size: 11px; }
  .crash-type { color: var(--accent3); }
  .crash-title { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding-right: 12px; }
  .cvss-val { font-weight: 700; }
  .engine-badge {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 3px;
    background: rgba(60,142,255,0.1);
    color: var(--accent3);
    border: 1px solid rgba(60,142,255,0.2);
  }

  /* Log feed */
  .log-feed {
    padding: 12px 0;
    height: 320px;
    overflow-y: auto;
  }
  .log-feed::-webkit-scrollbar { width: 4px; }
  .log-feed::-webkit-scrollbar-track { background: transparent; }
  .log-feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
  .log-entry {
    display: flex;
    gap: 12px;
    padding: 6px 20px;
    font-size: 11px;
    line-height: 1.5;
    border-left: 2px solid transparent;
    transition: background 0.1s;
  }
  .log-entry:hover { background: rgba(255,255,255,0.02); }
  .log-entry.crash { border-left-color: var(--accent2); }
  .log-entry.info  { border-left-color: var(--accent3); }
  .log-entry.warn  { border-left-color: var(--high); }
  .log-time { color: var(--muted); flex-shrink: 0; width: 60px; }
  .log-msg { color: var(--text); }

  /* Stats bar */
  .stats-row {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
    margin-bottom: 20px;
  }
  .mini-stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .mini-label { font-size: 11px; color: var(--muted); }
  .mini-val { font-family: 'Syne', sans-serif; font-size: 22px; font-weight: 700; }

  /* empty state */
  .empty {
    padding: 48px 20px;
    text-align: center;
    color: var(--muted);
    font-size: 12px;
  }
  .empty-icon { font-size: 32px; margin-bottom: 12px; opacity: 0.4; }

  /* modal */
  .modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.8);
    z-index: 100;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(4px);
  }
  .modal-overlay.open { display: flex; }
  .modal {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    width: 90%;
    max-width: 720px;
    max-height: 80vh;
    overflow-y: auto;
    padding: 28px;
  }
  .modal-title {
    font-family: 'Syne', sans-serif;
    font-size: 20px;
    font-weight: 700;
    margin-bottom: 20px;
    color: var(--accent);
  }
  .modal-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-bottom: 20px;
  }
  .modal-field { }
  .modal-field label { font-size: 10px; letter-spacing: 1.5px; color: var(--muted); text-transform: uppercase; display: block; margin-bottom: 4px; }
  .modal-field p { font-size: 13px; color: var(--text); }
  .poc-block {
    background: #0a0e14;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
    margin-top: 12px;
  }
  .poc-block pre {
    font-size: 12px;
    color: var(--accent);
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
  }
  .modal-close {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 8px 16px;
    border-radius: 4px;
    cursor: pointer;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    margin-top: 20px;
    transition: all 0.2s;
  }
  .modal-close:hover { border-color: var(--accent2); color: var(--accent2); }

  @media (max-width: 900px) {
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
    .grid2 { grid-template-columns: 1fr; }
    .crash-row { grid-template-columns: 70px 90px 1fr 60px; }
    .crash-row > :nth-child(5),
    .crash-row > :nth-child(6) { display: none; }
  }
</style>
</head>
<body>
<header>
  <div class="logo">v8<span>fuzz</span></div>
  <div class="header-right">
    <span id="last-update">—</span>
    <span class="live-badge"><span class="status-dot"></span>LIVE</span>
  </div>
</header>

<main>
  <div class="kpi-grid">
    <div class="kpi">
      <div class="kpi-label">Total Executions</div>
      <div class="kpi-value" id="kpi-execs">—</div>
      <div class="kpi-sub" id="kpi-execs-rate">— exec/s</div>
    </div>
    <div class="kpi red">
      <div class="kpi-label">Crashes Found</div>
      <div class="kpi-value" id="kpi-crashes">—</div>
      <div class="kpi-sub" id="kpi-crashes-sub">— unique</div>
    </div>
    <div class="kpi blue">
      <div class="kpi-label">Seeds Generated</div>
      <div class="kpi-value" id="kpi-seeds">—</div>
      <div class="kpi-sub">corpus size</div>
    </div>
    <div class="kpi orange">
      <div class="kpi-label">Uptime</div>
      <div class="kpi-value" id="kpi-uptime">—</div>
      <div class="kpi-sub" id="kpi-uptime-sub">since start</div>
    </div>
  </div>

  <div class="grid2">
    <div class="panel">
      <div class="panel-header">
        Crash Log
        <span id="crash-count">0 entries</span>
      </div>
      <div class="crash-table">
        <div class="crash-row header">
          <div>ID</div>
          <div>TYPE</div>
          <div>TITLE</div>
          <div>CVSS</div>
          <div>ENGINE</div>
          <div>SEVERITY</div>
        </div>
        <div id="crash-list">
          <div class="empty"><div class="empty-icon">🔍</div>No crashes yet — fuzzer is running</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        Live Log
        <span id="log-count">—</span>
      </div>
      <div class="log-feed" id="log-feed">
        <div class="empty"><div class="empty-icon">📡</div>Waiting for events...</div>
      </div>
    </div>
  </div>

  <div class="stats-row">
    <div class="mini-stat">
      <div>
        <div class="mini-label">API Requests Today</div>
        <div class="mini-val" id="stat-api">—</div>
      </div>
      <div style="font-size:28px;opacity:0.3">⚡</div>
    </div>
    <div class="mini-stat">
      <div>
        <div class="mini-label">Active Workers</div>
        <div class="mini-val" id="stat-workers">—</div>
      </div>
      <div style="font-size:28px;opacity:0.3">⚙️</div>
    </div>
  </div>
</main>

<div class="modal-overlay" id="modal-overlay">
  <div class="modal">
    <div class="modal-title" id="modal-title">—</div>
    <div class="modal-grid" id="modal-grid"></div>
    <div id="modal-poc"></div>
    <button class="modal-close" onclick="closeModal()">✕ Close</button>
  </div>
</div>

<script>
const API = '';  // same origin
let crashes = [];

function fmt(n) {
  if (n === null || n === undefined) return '—';
  if (n >= 1e9) return (n/1e9).toFixed(2) + 'B';
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return String(n);
}

function severity(cvss) {
  if (!cvss) return 'LOW';
  if (cvss >= 9) return 'CRITICAL';
  if (cvss >= 7) return 'HIGH';
  if (cvss >= 4) return 'MEDIUM';
  return 'LOW';
}

async function fetchStats() {
  try {
    const r = await fetch(API + '/stats');
    if (!r.ok) return;
    const s = await r.json();
    document.getElementById('kpi-execs').textContent = fmt(s.total_execs);
    document.getElementById('kpi-execs-rate').textContent = fmt(s.exec_rate) + ' exec/s';
    document.getElementById('kpi-crashes').textContent = fmt(s.total_crashes);
    document.getElementById('kpi-crashes-sub').textContent = fmt(s.unique_crashes) + ' unique';
    document.getElementById('kpi-seeds').textContent = fmt(s.corpus_size);
    document.getElementById('stat-api').textContent = fmt(s.api_requests_today);
    document.getElementById('stat-workers').textContent = s.active_workers ?? '—';
    if (s.start_time) {
      const days = Math.floor((Date.now()/1000 - s.start_time) / 86400);
      document.getElementById('kpi-uptime').textContent = days + 'd';
      document.getElementById('kpi-uptime-sub').textContent = new Date(s.start_time*1000).toLocaleDateString('ja-JP');
    }
    document.getElementById('last-update').textContent = new Date().toLocaleTimeString('ja-JP');
  } catch(e) {}
}

async function fetchCrashes() {
  try {
    const r = await fetch(API + '/crashes');
    if (!r.ok) return;
    crashes = await r.json();
    renderCrashes();
    document.getElementById('crash-count').textContent = crashes.length + ' entries';
  } catch(e) {}
}

function renderCrashes() {
  const el = document.getElementById('crash-list');
  if (!crashes.length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">🔍</div>No crashes yet — fuzzer is running</div>';
    return;
  }
  el.innerHTML = crashes.slice(0, 50).map(c => {
    const sev = severity(c.cvss);
    return \`<div class="crash-row" onclick="showCrash('\${c.id}')">
      <div class="crash-id">\${c.id?.slice(0,8) ?? '—'}</div>
      <div class="crash-type">\${c.crash_type ?? '—'}</div>
      <div class="crash-title">\${c.title ?? '—'}</div>
      <div class="cvss-val" style="color:var(--\${sev==='CRITICAL'?'critical':sev==='HIGH'?'high':sev==='MEDIUM'?'medium':'low'})">\${c.cvss ?? '—'}</div>
      <div><span class="engine-badge">\${(c.engine??'v8').toUpperCase()}</span></div>
      <div><span class="sev \${sev}">\${sev}</span></div>
    </div>\`;
  }).join('');
}

async function fetchLogs() {
  try {
    const r = await fetch(API + '/logs');
    if (!r.ok) return;
    const logs = await r.json();
    const el = document.getElementById('log-feed');
    if (!logs.length) return;
    const wasBottom = el.scrollHeight - el.scrollTop <= el.clientHeight + 40;
    document.getElementById('log-count').textContent = logs.length + ' events';
    el.innerHTML = logs.slice(-80).reverse().map(l => {
      const cls = l.type === 'crash' ? 'crash' : l.type === 'warn' ? 'warn' : 'info';
      return \`<div class="log-entry \${cls}">
        <span class="log-time">\${l.t ?? ''}</span>
        <span class="log-msg">\${l.msg ?? ''}</span>
      </div>\`;
    }).join('');
    if (wasBottom) el.scrollTop = 0;
  } catch(e) {}
}

function showCrash(id) {
  const c = crashes.find(x => x.id === id);
  if (!c) return;
  const sev = severity(c.cvss);
  document.getElementById('modal-title').innerHTML =
    \`<span class="sev \${sev}" style="font-size:12px;margin-right:10px">\${sev}</span>\${c.title ?? id}\`;
  document.getElementById('modal-grid').innerHTML = [
    ['ID', c.id], ['Engine', c.engine?.toUpperCase()],
    ['Crash Type', c.crash_type], ['CVSS', c.cvss],
    ['Component', c.component], ['Exploitability', c.exploitability],
    ['Detected', c.detected_at ? new Date(c.detected_at*1000).toLocaleString('ja-JP') : '—'],
    ['Minimized', c.minimized ? '✅ Yes' : '—'],
  ].map(([l,v]) => \`<div class="modal-field"><label>\${l}</label><p>\${v??'—'}</p></div>\`).join('');
  const poc = c.poc_js || c.js_code;
  document.getElementById('modal-poc').innerHTML = poc
    ? \`<div style="font-size:10px;letter-spacing:1.5px;color:var(--muted);text-transform:uppercase;margin-bottom:6px">PoC</div>
       <div class="poc-block"><pre>\${poc.replace(/</g,'&lt;')}</pre></div>\`
    : '';
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
}
document.getElementById('modal-overlay').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeModal();
});

async function refresh() {
  await Promise.all([fetchStats(), fetchCrashes(), fetchLogs()]);
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>`;

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // ダッシュボード
    if (path === '/' || path === '/dashboard') {
      return new Response(DASHBOARD_HTML, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
      });
    }

    // 認証チェック（ダッシュボード以外）
    const secret = request.headers.get('X-API-Secret');
    const authorized = secret === env.API_SECRET;

    try {
      if (path === '/crashes' && request.method === 'GET') {
        return await getCrashes(env);
      }
      if (path.startsWith('/crashes/') && request.method === 'GET') {
        return await getCrash(env, path.split('/')[2]);
      }
      if (path === '/stats' && request.method === 'GET') {
        return await getStats(env);
      }
      if (path === '/logs' && request.method === 'GET') {
        return await getLogs(env);
      }
      if (path === '/targets' && request.method === 'GET') {
        return await getTargets(env);
      }

      // Dropletからのデータ受信（認証必須）
      if (!authorized) {
        return json({ error: 'Unauthorized' }, 401);
      }
      if (path === '/report/crash' && request.method === 'POST') {
        return await receiveCrash(request, env);
      }
      if (path === '/report/stats' && request.method === 'POST') {
        return await receiveStats(request, env);
      }
      if (path === '/report/log' && request.method === 'POST') {
        return await receiveLog(request, env);
      }

      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  }
};

async function getCrashes(env) {
  const data = await env.KV.get('crashes', 'json') || [];
  return json(data);
}
async function getCrash(env, id) {
  const crashes = await env.KV.get('crashes', 'json') || [];
  const crash = crashes.find(c => c.id === id);
  if (!crash) return json({ error: 'Not found' }, 404);
  return json(crash);
}
async function getTargets(env) {
  const data = await env.KV.get('targets', 'json') || [];
  return json(data);
}
async function getStats(env) {
  const data = await env.KV.get('stats', 'json') || {};
  return json(data);
}
async function getLogs(env) {
  const data = await env.KV.get('logs', 'json') || [];
  return json(data.slice(-100));
}
async function receiveCrash(request, env) {
  const crash = await request.json();
  const crashes = await env.KV.get('crashes', 'json') || [];
  crashes.unshift(crash);
  await env.KV.put('crashes', JSON.stringify(crashes.slice(0, 500)));
  await appendLog(env, {
    t: new Date().toISOString().slice(11, 19),
    type: 'crash',
    msg: `${crash.id} — ${crash.engine?.toUpperCase()} ${crash.crash_type} CVSS${crash.cvss}`
  });
  return json({ ok: true });
}
async function receiveStats(request, env) {
  const stats = await request.json();
  await env.KV.put('stats', JSON.stringify({ ...stats, updated_at: Date.now() }));
  return json({ ok: true });
}
async function receiveLog(request, env) {
  const entry = await request.json();
  await appendLog(env, entry);
  return json({ ok: true });
}
async function appendLog(env, entry) {
  const logs = await env.KV.get('logs', 'json') || [];
  logs.push(entry);
  await env.KV.put('logs', JSON.stringify(logs.slice(-1000)));
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}
