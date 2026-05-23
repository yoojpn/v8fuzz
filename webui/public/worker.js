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
<title>v8fuzz</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px}
button{font-family:inherit;cursor:pointer}
/* HEADER */
.header{height:48px;border-bottom:1px solid #30363d;display:flex;align-items:center;padding:0 20px;gap:24px;background:#161b22;position:sticky;top:0;z-index:50}
.logo{font-weight:600;font-size:14px;color:#e6edf3;margin-right:8px}
.logo span{color:#3fb950}
.nav-btn{font-size:13px;color:#8b949e;background:none;border:none;padding:4px 8px;border-radius:6px;font-family:inherit;font-weight:400;transition:background 0.1s,color 0.1s}
.nav-btn.active{color:#e6edf3;font-weight:500;background:#21262d}
.nav-btn:hover:not(.active){background:#21262d;color:#c9d1d9}
.live{margin-left:auto;display:flex;align-items:center;gap:6px;font-size:12px;color:#8b949e}
.live-dot{width:6px;height:6px;border-radius:50%;background:#3fb950;animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0.3}}
/* MAIN */
.main{padding:16px 20px;max-width:1400px;margin:0 auto}
/* KPI */
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.kpi{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;display:flex;flex-direction:column;gap:4px}
.kpi-label{font-size:12px;color:#8b949e}
.kpi-value{font-size:24px;font-weight:600;font-variant-numeric:tabular-nums;line-height:1.2}
.kpi-sub{font-size:12px;color:#484f58}
/* CARD */
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;overflow:hidden;margin-bottom:12px}
.card-header{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid #30363d;font-size:13px;font-weight:600;color:#c9d1d9}
.card-header span:last-child{font-size:12px;color:#8b949e;font-weight:400}
/* TABLE */
.table-head{display:flex;align-items:center;padding:8px 16px;border-bottom:1px solid #21262d;font-size:11px;color:#8b949e;text-transform:lowercase;letter-spacing:0}
.row{display:flex;align-items:center;padding:8px 16px;border-bottom:1px solid #21262d;cursor:pointer;transition:background 0.1s}
.row:hover{background:#21262d}
.row.selected{background:#21262d}
.row:last-child{border-bottom:none}
/* SPLIT LAYOUT */
.split{display:grid;gap:12px}
.split.open{grid-template-columns:1fr 360px}
/* DETAIL PANEL */
.detail{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;align-self:start}
.detail-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.detail-title span{font-weight:600;font-size:13px}
.close-btn{background:none;border:none;color:#8b949e;font-size:18px;line-height:1;padding:0}
.close-btn:hover{color:#e6edf3}
.dl{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;align-items:center}
.dt{font-size:11px;color:#8b949e;white-space:nowrap}
.dd{font-size:12px;color:#e6edf3;display:flex;align-items:center;gap:6px}
.rationale-box{margin-top:16px;padding:12px;background:#0d1117;border-radius:6px;border:1px solid #30363d}
.rationale-label{font-size:11px;color:#8b949e;margin-bottom:6px}
.rationale-text{font-size:12px;color:#e6edf3;line-height:1.6}
.action-row{display:flex;gap:8px;margin-top:16px}
/* BUTTONS */
.btn{font-size:12px;padding:5px 12px;border-radius:6px;border:1px solid #30363d;background:#21262d;color:#c9d1d9;font-family:inherit;transition:background 0.1s}
.btn:hover{background:#30363d}
.btn.primary{background:#238636;border-color:#2ea043;color:#fff}
.btn.primary:hover{background:#2ea043}
.btn.danger{background:#b62324;border-color:#b62324;color:#fff;width:100%;text-align:center}
.btn.danger:hover{background:#d73a3a}
/* BADGES */
.badge{font-size:11px;padding:1px 6px;border-radius:4px;font-weight:500;display:inline-block}
.badge.critical{color:#f85149;background:#f8514918;border:1px solid #f8514944}
.badge.high    {color:#d29922;background:#d2992218;border:1px solid #d2992244}
.badge.medium  {color:#58a6ff;background:#58a6ff18;border:1px solid #58a6ff44}
.badge.low     {color:#8b949e;background:#8b949e18;border:1px solid #8b949e44}
/* STATUS DOT */
.sdot{display:inline-block;width:7px;height:7px;border-radius:50%;flex-shrink:0}
.sdot.running{background:#3fb950}
.sdot.paused {background:#484f58}
/* RISK BAR */
.risk-wrap{display:flex;align-items:center;gap:8px}
.risk-track{width:48px;height:4px;background:#30363d;border-radius:2px}
.risk-fill{height:100%;border-radius:2px}
/* LOGS */
.log-row{display:flex;align-items:flex-start;gap:10px;padding:7px 16px;border-bottom:1px solid #21262d;font-size:12px}
.log-row:last-child{border-bottom:none}
.log-time{font-size:11px;color:#484f58;flex-shrink:0;font-family:monospace;padding-top:2px;width:60px}
.log-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;margin-top:5px}
.log-type-label{margin-left:auto;font-size:11px;color:#484f58;flex-shrink:0}
/* PRE */
.poc-pre{font-size:12px;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;color:#3fb950;white-space:pre-wrap;word-break:break-all;line-height:1.6;max-height:200px;overflow-y:auto;margin-top:6px}
/* EMPTY */
.empty{padding:40px 16px;text-align:center;color:#484f58;font-size:13px}
</style>
</head>
<body>
<div class="header">
  <span class="logo">v8<span>fuzz</span></span>
  <button class="nav-btn active" onclick="setTab('overview',this)">overview</button>
  <button class="nav-btn" onclick="setTab('targets',this)">targets</button>
  <button class="nav-btn" onclick="setTab('crashes',this)">crashes</button>
  <button class="nav-btn" onclick="setTab('logs',this)">logs</button>
  <div class="live"><span class="live-dot"></span><span id="last-update">—</span></div>
</div>
<div class="main">
  <div id="tab-overview">
    <div class="kpi-row">
      <div class="kpi"><div class="kpi-label">executions / sec</div><div class="kpi-value" id="kv-rate">—</div><div class="kpi-sub" id="kv-total">—</div></div>
      <div class="kpi"><div class="kpi-label">crashes</div><div class="kpi-value" id="kv-crashes" style="color:#f85149">—</div><div class="kpi-sub" id="kv-unique">— unique</div></div>
      <div class="kpi"><div class="kpi-label">corpus</div><div class="kpi-value" id="kv-seeds">—</div><div class="kpi-sub">seeds</div></div>
      <div class="kpi"><div class="kpi-label">uptime</div><div class="kpi-value" id="kv-uptime">—</div><div class="kpi-sub" id="kv-since">—</div></div>
    </div>
    <div class="card">
      <div class="card-header"><span>recent crashes</span><span id="ov-crash-count">—</span></div>
      <div id="ov-crash-list"><div class="empty">loading...</div></div>
    </div>
    <div class="card">
      <div class="card-header"><span>live log</span><span id="ov-log-count">—</span></div>
      <div id="ov-log-list" style="max-height:280px;overflow-y:auto"><div class="empty">loading...</div></div>
    </div>
  </div>

  <div id="tab-targets" style="display:none">
    <div class="split" id="targets-split">
      <div class="card">
        <div class="card-header"><span>targets</span><span>sorted by AI risk score</span></div>
        <div class="table-head">
          <span style="flex:0 0 220px">file</span>
          <span style="flex:0 0 90px">component</span>
          <span style="flex:0 0 120px">risk</span>
          <span style="flex:0 0 40px">nets</span>
          <span style="flex:0 0 60px">exec/s</span>
          <span style="flex:0 0 60px">crashes</span>
          <span style="margin-left:auto">status</span>
        </div>
        <div id="target-list"><div class="empty">loading...</div></div>
      </div>
      <div class="detail" id="target-detail" style="display:none"></div>
    </div>
  </div>

  <div id="tab-crashes" style="display:none">
    <div class="split" id="crashes-split">
      <div class="card">
        <div class="card-header"><span>crashes</span><span id="cr-count">—</span></div>
        <div class="table-head">
          <span style="flex:0 0 70px">id</span>
          <span style="flex:0 0 85px">severity</span>
          <span style="flex:0 0 150px">type</span>
          <span style="flex:1">file</span>
          <span style="flex:0 0 50px">cvss</span>
          <span style="flex:0 0 80px">minimized</span>
          <span style="flex:0 0 70px;text-align:right">time</span>
        </div>
        <div id="crash-list"><div class="empty">loading...</div></div>
      </div>
      <div class="detail" id="crash-detail" style="display:none"></div>
    </div>
  </div>

  <div id="tab-logs" style="display:none">
    <div class="card">
      <div class="card-header"><span>logs</span><span id="log-count">—</span></div>
      <div id="full-log-list" style="max-height:70vh;overflow-y:auto"><div class="empty">loading...</div></div>
    </div>
  </div>
</div>
<script>
const API = 'https://v8fuzz.yoyosan0929.workers.dev';

// ── utils ──────────────────────────────────────────────
function fmt(n) {
  if (n==null) return '—';
  if (n>=1e9) return (n/1e9).toFixed(2)+'B';
  if (n>=1e6) return (n/1e6).toFixed(1)+'M';
  if (n>=1e3) return (n/1e3).toFixed(1)+'K';
  return String(n);
}
function sev(cvss) {
  if (!cvss) return 'low';
  if (cvss>=9) return 'critical';
  if (cvss>=7) return 'high';
  if (cvss>=4) return 'medium';
  return 'low';
}
function sevLabel(cvss) { return sev(cvss).charAt(0).toUpperCase()+sev(cvss).slice(1); }
function riskColor(v) { return v>=8?'#f85149':v>=7?'#d29922':'#8b949e'; }
function riskBar(v) {
  const c = riskColor(v);
  return \`<div class="risk-wrap">
    <div class="risk-track"><div class="risk-fill" style="width:\${v*10}%;background:\${c}"></div></div>
    <span style="font-size:12px;color:\${c};font-weight:600;font-variant-numeric:tabular-nums">\${v}</span>
  </div>\`;
}
function badge(cvss) {
  const s=sev(cvss);
  return \`<span class="badge \${s}">\${sevLabel(cvss)}</span>\`;
}
function sdot(status) {
  return \`<span class="sdot \${status||'running'}"></span>\`;
}
const LOG_COLOR = {crash:'#f85149',warn:'#d29922',ai:'#3fb950',info:'#8b949e'};

// ── tab switching ──────────────────────────────────────
window.setTab = function(name, btn) {
  ['overview','targets','crashes','logs'].forEach(t => {
    document.getElementById('tab-'+t).style.display = t===name?'':'none';
  });
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  if(btn) btn.classList.add('active');
};

// ── state ──────────────────────────────────────────────
let allCrashes = [];
let allTargets = [];
let allLogs    = [];
let selectedTarget = null;
let selectedCrash  = null;

// ── render targets ─────────────────────────────────────
function renderTargets() {
  const el = document.getElementById('target-list');
  if (!allTargets.length) { el.innerHTML='<div class="empty">No target data yet</div>'; return; }
  el.innerHTML = allTargets.map(t => \`
    <div class="row\${selectedTarget?.id===t.id?' selected':''}" onclick="selectTarget('\${t.id}')">
      <span style="flex:0 0 220px;display:flex;align-items:center;gap:6px">\${sdot(t.status)}<span style="font-size:13px;color:#58a6ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${t.name}</span></span>
      <span style="flex:0 0 90px;font-size:12px;color:#8b949e">\${t.component||'—'}</span>
      <span style="flex:0 0 120px">\${riskBar(t.risk||0)}</span>
      <span style="flex:0 0 40px;font-size:12px;color:#8b949e">\${t.nets||0}</span>
      <span style="flex:0 0 60px;font-size:12px;color:#8b949e;font-variant-numeric:tabular-nums">\${t.execs||0}</span>
      <span style="flex:0 0 60px;font-size:12px;color:\${(t.crashes||0)>0?'#f85149':'#484f58'}">\${(t.crashes||0)>0?t.crashes:'—'}</span>
      <span style="margin-left:auto;font-size:12px;color:\${t.status==='running'?'#3fb950':'#484f58'}">\${t.status||'—'}</span>
    </div>\`).join('');
}

window.selectTarget = function(id) {
  selectedTarget = allTargets.find(t=>t.id==id)||null;
  renderTargets();
  const det = document.getElementById('target-detail');
  const split = document.getElementById('targets-split');
  if (!selectedTarget) { det.style.display='none'; split.classList.remove('open'); return; }
  split.classList.add('open');
  det.style.display='';
  det.innerHTML = \`
    <div class="detail-title"><span>\${selectedTarget.name}</span><button class="close-btn" onclick="selectTarget(null)">×</button></div>
    <dl class="dl">
      <dt class="dt">component</dt><dd class="dd">\${selectedTarget.component||'—'}</dd>
      <dt class="dt">risk score</dt><dd class="dd">\${riskBar(selectedTarget.risk||0)}</dd>
      <dt class="dt">nets</dt><dd class="dd">\${selectedTarget.nets||0}</dd>
      <dt class="dt">exec / sec</dt><dd class="dd">\${selectedTarget.execs||0}</dd>
      <dt class="dt">crashes</dt><dd class="dd" style="color:\${(selectedTarget.crashes||0)>0?'#f85149':'#8b949e'}">\${selectedTarget.crashes||0}</dd>
      <dt class="dt">status</dt><dd class="dd">\${sdot(selectedTarget.status)}\${selectedTarget.status||'—'}</dd>
    </dl>
    \${selectedTarget.reason?\`<div class="rationale-box"><div class="rationale-label">AI rationale</div><div class="rationale-text">\${selectedTarget.reason}</div></div>\`:''}
    <div class="action-row">
      <button class="btn primary">add net</button>
      <button class="btn">\${selectedTarget.status==='running'?'pause':'resume'}</button>
    </div>\`;
};

// ── render crashes ─────────────────────────────────────
function renderCrashes() {
  document.getElementById('cr-count').textContent = allCrashes.length+' total';
  const el = document.getElementById('crash-list');
  if (!allCrashes.length) { el.innerHTML='<div class="empty">No crashes yet — fuzzer is running</div>'; return; }
  el.innerHTML = allCrashes.slice(0,100).map(c => {
    const s=sev(c.cvss);
    const cvssColor=c.cvss>=8?'#f85149':c.cvss>=7?'#d29922':'#58a6ff';
    return \`<div class="row\${selectedCrash?.id===c.id?' selected':''}" onclick="selectCrash('\${c.id}')">
      <span style="flex:0 0 70px;font-size:12px;color:#58a6ff">\${(c.id||'').slice(0,8)}</span>
      <span style="flex:0 0 85px">\${badge(c.cvss)}</span>
      <span style="flex:0 0 150px;font-size:13px">\${c.crash_type||'—'}</span>
      <span style="flex:1;font-size:12px;color:#8b949e">\${c.file||c.component||'—'}</span>
      <span style="flex:0 0 50px;font-size:13px;font-weight:600;color:\${cvssColor};font-variant-numeric:tabular-nums">\${c.cvss||'—'}</span>
      <span style="flex:0 0 80px;font-size:12px;color:\${c.minimized?'#3fb950':'#8b949e'}">\${c.minimized?'yes':'pending'}</span>
      <span style="flex:0 0 70px;font-size:12px;color:#484f58;text-align:right">\${c.detected_at?timeAgo(c.detected_at):'—'}</span>
    </div>\`;
  }).join('');

  // overview recent
  const ov = document.getElementById('ov-crash-list');
  document.getElementById('ov-crash-count').textContent = allCrashes.length+' total';
  if (!allCrashes.length) { ov.innerHTML='<div class="empty">No crashes yet</div>'; return; }
  ov.innerHTML = allCrashes.slice(0,5).map(c=>{
    const cvssColor=c.cvss>=8?'#f85149':c.cvss>=7?'#d29922':'#58a6ff';
    return \`<div class="row">
      <span style="flex:0 0 70px;font-size:12px;color:#58a6ff">\${(c.id||'').slice(0,8)}</span>
      <span style="flex:0 0 85px">\${badge(c.cvss)}</span>
      <span style="flex:1;font-size:13px">\${c.crash_type||'—'}</span>
      <span style="flex:0 0 50px;font-size:13px;font-weight:600;color:\${cvssColor}">\${c.cvss||'—'}</span>
      <span style="flex:0 0 70px;font-size:12px;color:#484f58;text-align:right">\${c.detected_at?timeAgo(c.detected_at):'—'}</span>
    </div>\`;
  }).join('');
}

window.selectCrash = function(id) {
  selectedCrash = allCrashes.find(c=>c.id==id)||null;
  renderCrashes();
  const det = document.getElementById('crash-detail');
  const split = document.getElementById('crashes-split');
  if (!selectedCrash) { det.style.display='none'; split.classList.remove('open'); return; }
  split.classList.add('open');
  det.style.display='';
  const c = selectedCrash;
  const cvssColor=c.cvss>=8?'#f85149':c.cvss>=7?'#d29922':'#58a6ff';
  det.innerHTML = \`
    <div class="detail-title"><span>\${(c.id||'').slice(0,8)}</span><button class="close-btn" onclick="selectCrash(null)">×</button></div>
    <div style="display:flex;gap:8px;margin-bottom:16px">\${badge(c.cvss)}<span style="font-size:12px;color:#8b949e;padding:1px 6px;border:1px solid #30363d;border-radius:4px">expl: \${c.exploitability||'—'}</span></div>
    <dl class="dl">
      <dt class="dt">type</dt><dd class="dd">\${c.crash_type||'—'}</dd>
      <dt class="dt">file</dt><dd class="dd" style="font-size:12px;color:#8b949e">\${c.file||c.component||'—'}</dd>
      <dt class="dt">cvss</dt><dd class="dd" style="color:\${cvssColor};font-weight:600">\${c.cvss||'—'}</dd>
      <dt class="dt">minimized</dt><dd class="dd" style="color:\${c.minimized?'#3fb950':'#8b949e'}">\${c.minimized?'yes':'no'}</dd>
      <dt class="dt">detected</dt><dd class="dd" style="color:#8b949e">\${c.detected_at?timeAgo(c.detected_at):'—'}</dd>
    </dl>
    \${(c.poc_js||c.js_code)?\`<div style="font-size:11px;color:#8b949e;margin:16px 0 4px">minimized PoC</div><pre class="poc-pre">\${(c.poc_js||c.js_code).replace(/</g,'&lt;')}</pre>\`:''}
    <div style="display:flex;flex-direction:column;gap:8px;margin-top:16px">
      <button class="btn danger" onclick="generateVrpReport('${c.id}')">generate VRP report</button>
      <div style="display:flex;gap:8px">
        <button class="btn" style="flex:1" onclick="downloadFile('${c.id}','js')">download .js</button>
        <button class="btn" style="flex:1" onclick="downloadFile('${c.id}','log')">download log</button>
      </div>
    </div>\`;
};

// ── download helpers ────────────────────────────────────
async function downloadFile(crashId, type) {
  try {
    const res = await apiFetch(`/report/crash/${crashId}`);
    if (!res) return;
    const crash = await res.json();
    let content, filename, mime;
    if (type === 'js') {
      content = crash.poc_js || crash.js_code || '// no JS available';
      filename = `${crashId}.js`;
      mime = 'text/javascript';
    } else {
      content = crash.stderr || crash.asan_log || '// no log available';
      filename = `${crashId}.log`;
      mime = 'text/plain';
    }
    const blob = new Blob([content], {type: mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  } catch(e) { alert('Download failed: ' + e.message); }
}

async function generateVrpReport(crashId) {
  try {
    const res = await apiFetch(`/report/crash/${crashId}/vrp`);
    if (!res) return;
    const data = await res.json();
    const content = data.report || JSON.stringify(data, null, 2);
    const blob = new Blob([content], {type: 'text/markdown'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${crashId}_vrp_report.md`; a.click();
    URL.revokeObjectURL(url);
  } catch(e) { alert('VRP report generation failed: ' + e.message); }
}

// ── render logs ─────────────────────────────────────────
function renderLogs() {
  function logHTML(logs) {
    if (!logs.length) return '<div class="empty">No logs yet</div>';
    return logs.map(l=>{
      const col = LOG_COLOR[l.type]||'#8b949e';
      const textCol = l.type==='crash'?'#f85149':l.type==='warn'?'#d29922':'#8b949e';
      return \`<div class="log-row">
        <span class="log-time">\${l.t||''}</span>
        <span class="log-dot" style="background:\${col}"></span>
        <span style="font-size:12px;color:\${textCol};line-height:1.5">\${l.msg||''}</span>
        <span class="log-type-label">\${l.type||''}</span>
      </div>\`;
    }).join('');
  }
  const recent = allLogs.slice(-20).reverse();
  document.getElementById('ov-log-list').innerHTML = logHTML(recent);
  document.getElementById('ov-log-count').textContent = allLogs.length+' events';
  document.getElementById('full-log-list').innerHTML = logHTML([...allLogs].reverse());
  document.getElementById('log-count').textContent = allLogs.length+' events';
}

// ── time ago ────────────────────────────────────────────
function timeAgo(ts) {
  const diff = Math.floor(Date.now()/1000 - ts);
  if (diff<60) return diff+'秒前';
  if (diff<3600) return Math.floor(diff/60)+'分前';
  if (diff<86400) return Math.floor(diff/3600)+'時間前';
  return Math.floor(diff/86400)+'日前';
}

function generateMdReport(c) {
  return `# VRP Report: ${c.crash_type||'Unknown'} in ${c.component||'V8'}

## Summary
- **Crash ID**: ${c.id}
- **Type**: ${c.crash_type||'Unknown'}
- **CVSS**: ${c.cvss||0}
- **Exploitability**: ${c.exploitability||'unknown'}
- **Component**: ${c.component||c.file||'V8 JIT'}

## Steps to Reproduce
\`\`\`javascript
${c.poc_js||c.js_code||'// PoC not available'}
\`\`\`

## ASAN Output
\`\`\`
${c.stderr||c.asan_log||'// Log not available'}
\`\`\`

## Impact
${c.attack_scenario||'Under investigation'}
`;
}

// ── fetch ────────────────────────────────────────────────
async function fetchStats() {
  try {
    const s = await fetch(API+'/stats').then(r=>r.json());
    document.getElementById('kv-rate').textContent   = fmt(s.exec_rate);
    document.getElementById('kv-total').textContent  = fmt(s.total_execs)+' total';
    document.getElementById('kv-crashes').textContent= fmt(s.total_crashes);
    document.getElementById('kv-unique').textContent = fmt(s.unique_crashes)+' unique';
    document.getElementById('kv-seeds').textContent  = fmt(s.corpus_size);
    if (s.start_time) {
      const days = Math.floor((Date.now()/1000-s.start_time)/86400);
      document.getElementById('kv-uptime').textContent = days+'d';
      document.getElementById('kv-since').textContent  = new Date(s.start_time*1000).toLocaleDateString('ja-JP');
    }
    document.getElementById('last-update').textContent = new Date().toLocaleTimeString('ja-JP');
  } catch(e){}
}
async function fetchCrashesData() {
  try { allCrashes = await fetch(API+'/crashes').then(r=>r.json()); renderCrashes(); } catch(e){}
}
async function fetchTargetsData() {
  try { allTargets = await fetch(API+'/targets').then(r=>r.json()); renderTargets(); } catch(e){}
}
async function fetchLogsData() {
  try { allLogs = await fetch(API+'/logs').then(r=>r.json()); renderLogs(); } catch(e){}
}

async function refresh() {
  await Promise.all([fetchStats(), fetchCrashesData(), fetchTargetsData(), fetchLogsData()]);
}

refresh();
setInterval(refresh, 10000);

</script>
</body>
</html>
`;

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/' || path === '/dashboard') {
      return new Response(DASHBOARD_HTML, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
      });
    }

    const secret = request.headers.get('X-API-Secret');
    const authorized = secret === env.API_SECRET;

    try {
      if (path === '/crashes' && request.method === 'GET') return await getCrashes(env);
      if (path.startsWith('/crashes/') && request.method === 'GET') return await getCrash(env, path.split('/')[2]);
      if (path === '/stats'   && request.method === 'GET') return await getStats(env);
      if (path === '/logs'    && request.method === 'GET') return await getLogs(env);
      if (path === '/targets' && request.method === 'GET') return await getTargets(env);

      if (!authorized) return json({ error: 'Unauthorized' }, 401);
      if (path === '/report/crash' && request.method === 'POST') return await receiveCrash(request, env);
      if (path.startsWith('/report/crash/') && request.method === 'GET') {
        const crashId = path.split('/report/crash/')[1].replace('/vrp','');
        const isVrp = path.endsWith('/vrp');
        const val = await env.KV.get('crash:' + crashId);
        if (!val) return new Response('Not found', {status:404});
        const crash = JSON.parse(val);
        if (isVrp) {
          // VRPレポートをMarkdown形式で返す
          const report = crash.vrp_report || generateMdReport(crash);
          return new Response(JSON.stringify({report}), {headers:corsHeaders('application/json')});
        }
        return new Response(val, {headers:corsHeaders('application/json')});
      }
      if (path === '/report/stats' && request.method === 'POST') return await receiveStats(request, env);
      if (path === '/report/log'   && request.method === 'POST') return await receiveLog(request, env);

      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  }
};

async function getCrashes(env) { return json(await env.KV.get('crashes','json') || []); }
async function getCrash(env, id) {
  const crashes = await env.KV.get('crashes','json') || [];
  const c = crashes.find(c=>c.id===id);
  return c ? json(c) : json({error:'Not found'},404);
}
async function getTargets(env) { return json(await env.KV.get('targets','json') || []); }
async function getStats(env)   { return json(await env.KV.get('stats','json')   || {}); }
async function getLogs(env)    { return json((await env.KV.get('logs','json') || []).slice(-100)); }
async function receiveCrash(request, env) {
  const crash = await request.json();
  const crashes = await env.KV.get('crashes','json') || [];
  crashes.unshift(crash);
  await env.KV.put('crashes', JSON.stringify(crashes.slice(0,500)));
  await appendLog(env, { t: new Date().toISOString().slice(11,19), type:'crash', msg:`${crash.id} — ${crash.engine?.toUpperCase()} ${crash.crash_type} CVSS${crash.cvss}` });
  return json({ok:true});
}
async function receiveStats(request, env) {
  const stats = await request.json();
  await env.KV.put('stats', JSON.stringify({...stats, updated_at: Date.now()}));
  return json({ok:true});
}
async function receiveLog(request, env) {
  await appendLog(env, await request.json());
  return json({ok:true});
}
async function appendLog(env, entry) {
  const logs = await env.KV.get('logs','json') || [];
  logs.push(entry);
  await env.KV.put('logs', JSON.stringify(logs.slice(-1000)));
}
function json(data, status=200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {'Content-Type':'application/json', ...CORS_HEADERS},
  });
}
