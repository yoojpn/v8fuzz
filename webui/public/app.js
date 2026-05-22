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
  return `<div class="risk-wrap">
    <div class="risk-track"><div class="risk-fill" style="width:${v*10}%;background:${c}"></div></div>
    <span style="font-size:12px;color:${c};font-weight:600;font-variant-numeric:tabular-nums">${v}</span>
  </div>`;
}
function badge(cvss) {
  const s=sev(cvss);
  return `<span class="badge ${s}">${sevLabel(cvss)}</span>`;
}
function sdot(status) {
  return `<span class="sdot ${status||'running'}"></span>`;
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
  el.innerHTML = allTargets.map(t => `
    <div class="row${selectedTarget?.id===t.id?' selected':''}" onclick="selectTarget('${t.id}')">
      <span style="flex:0 0 220px;display:flex;align-items:center;gap:6px">${sdot(t.status)}<span style="font-size:13px;color:#58a6ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${t.name}</span></span>
      <span style="flex:0 0 90px;font-size:12px;color:#8b949e">${t.component||'—'}</span>
      <span style="flex:0 0 120px">${riskBar(t.risk||0)}</span>
      <span style="flex:0 0 40px;font-size:12px;color:#8b949e">${t.nets||0}</span>
      <span style="flex:0 0 60px;font-size:12px;color:#8b949e;font-variant-numeric:tabular-nums">${t.execs||0}</span>
      <span style="flex:0 0 60px;font-size:12px;color:${(t.crashes||0)>0?'#f85149':'#484f58'}">${(t.crashes||0)>0?t.crashes:'—'}</span>
      <span style="margin-left:auto;font-size:12px;color:${t.status==='running'?'#3fb950':'#484f58'}">${t.status||'—'}</span>
    </div>`).join('');
}

window.selectTarget = function(id) {
  selectedTarget = allTargets.find(t=>t.id==id)||null;
  renderTargets();
  const det = document.getElementById('target-detail');
  const split = document.getElementById('targets-split');
  if (!selectedTarget) { det.style.display='none'; split.classList.remove('open'); return; }
  split.classList.add('open');
  det.style.display='';
  det.innerHTML = `
    <div class="detail-title"><span>${selectedTarget.name}</span><button class="close-btn" onclick="selectTarget(null)">×</button></div>
    <dl class="dl">
      <dt class="dt">component</dt><dd class="dd">${selectedTarget.component||'—'}</dd>
      <dt class="dt">risk score</dt><dd class="dd">${riskBar(selectedTarget.risk||0)}</dd>
      <dt class="dt">nets</dt><dd class="dd">${selectedTarget.nets||0}</dd>
      <dt class="dt">exec / sec</dt><dd class="dd">${selectedTarget.execs||0}</dd>
      <dt class="dt">crashes</dt><dd class="dd" style="color:${(selectedTarget.crashes||0)>0?'#f85149':'#8b949e'}">${selectedTarget.crashes||0}</dd>
      <dt class="dt">status</dt><dd class="dd">${sdot(selectedTarget.status)}${selectedTarget.status||'—'}</dd>
    </dl>
    ${selectedTarget.reason?`<div class="rationale-box"><div class="rationale-label">AI rationale</div><div class="rationale-text">${selectedTarget.reason}</div></div>`:''}
    <div class="action-row">
      <button class="btn primary">add net</button>
      <button class="btn">${selectedTarget.status==='running'?'pause':'resume'}</button>
    </div>`;
};

// ── render crashes ─────────────────────────────────────
function renderCrashes() {
  document.getElementById('cr-count').textContent = allCrashes.length+' total';
  const el = document.getElementById('crash-list');
  if (!allCrashes.length) { el.innerHTML='<div class="empty">No crashes yet — fuzzer is running</div>'; return; }
  el.innerHTML = allCrashes.slice(0,100).map(c => {
    const s=sev(c.cvss);
    const cvssColor=c.cvss>=8?'#f85149':c.cvss>=7?'#d29922':'#58a6ff';
    return `<div class="row${selectedCrash?.id===c.id?' selected':''}" onclick="selectCrash('${c.id}')">
      <span style="flex:0 0 70px;font-size:12px;color:#58a6ff">${(c.id||'').slice(0,8)}</span>
      <span style="flex:0 0 85px">${badge(c.cvss)}</span>
      <span style="flex:0 0 150px;font-size:13px">${c.crash_type||'—'}</span>
      <span style="flex:1;font-size:12px;color:#8b949e">${c.file||c.component||'—'}</span>
      <span style="flex:0 0 50px;font-size:13px;font-weight:600;color:${cvssColor};font-variant-numeric:tabular-nums">${c.cvss||'—'}</span>
      <span style="flex:0 0 80px;font-size:12px;color:${c.minimized?'#3fb950':'#8b949e'}">${c.minimized?'yes':'pending'}</span>
      <span style="flex:0 0 70px;font-size:12px;color:#484f58;text-align:right">${c.detected_at?timeAgo(c.detected_at):'—'}</span>
    </div>`;
  }).join('');

  // overview recent
  const ov = document.getElementById('ov-crash-list');
  document.getElementById('ov-crash-count').textContent = allCrashes.length+' total';
  if (!allCrashes.length) { ov.innerHTML='<div class="empty">No crashes yet</div>'; return; }
  ov.innerHTML = allCrashes.slice(0,5).map(c=>{
    const cvssColor=c.cvss>=8?'#f85149':c.cvss>=7?'#d29922':'#58a6ff';
    return `<div class="row">
      <span style="flex:0 0 70px;font-size:12px;color:#58a6ff">${(c.id||'').slice(0,8)}</span>
      <span style="flex:0 0 85px">${badge(c.cvss)}</span>
      <span style="flex:1;font-size:13px">${c.crash_type||'—'}</span>
      <span style="flex:0 0 50px;font-size:13px;font-weight:600;color:${cvssColor}">${c.cvss||'—'}</span>
      <span style="flex:0 0 70px;font-size:12px;color:#484f58;text-align:right">${c.detected_at?timeAgo(c.detected_at):'—'}</span>
    </div>`;
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
  det.innerHTML = `
    <div class="detail-title"><span>${(c.id||'').slice(0,8)}</span><button class="close-btn" onclick="selectCrash(null)">×</button></div>
    <div style="display:flex;gap:8px;margin-bottom:16px">${badge(c.cvss)}<span style="font-size:12px;color:#8b949e;padding:1px 6px;border:1px solid #30363d;border-radius:4px">expl: ${c.exploitability||'—'}</span></div>
    <dl class="dl">
      <dt class="dt">type</dt><dd class="dd">${c.crash_type||'—'}</dd>
      <dt class="dt">file</dt><dd class="dd" style="font-size:12px;color:#8b949e">${c.file||c.component||'—'}</dd>
      <dt class="dt">cvss</dt><dd class="dd" style="color:${cvssColor};font-weight:600">${c.cvss||'—'}</dd>
      <dt class="dt">minimized</dt><dd class="dd" style="color:${c.minimized?'#3fb950':'#8b949e'}">${c.minimized?'yes':'no'}</dd>
      <dt class="dt">detected</dt><dd class="dd" style="color:#8b949e">${c.detected_at?timeAgo(c.detected_at):'—'}</dd>
    </dl>
    ${(c.poc_js||c.js_code)?`<div style="font-size:11px;color:#8b949e;margin:16px 0 4px">minimized PoC</div><pre class="poc-pre">${(c.poc_js||c.js_code).replace(/</g,'&lt;')}</pre>`:''}
    <div style="display:flex;flex-direction:column;gap:8px;margin-top:16px">
      <button class="btn danger">generate VRP report</button>
      <div style="display:flex;gap:8px">
        <button class="btn" style="flex:1">download .js</button>
        <button class="btn" style="flex:1">download log</button>
      </div>
    </div>`;
};

// ── render logs ─────────────────────────────────────────
function renderLogs() {
  function logHTML(logs) {
    if (!logs.length) return '<div class="empty">No logs yet</div>';
    return logs.map(l=>{
      const col = LOG_COLOR[l.type]||'#8b949e';
      const textCol = l.type==='crash'?'#f85149':l.type==='warn'?'#d29922':'#8b949e';
      return `<div class="log-row">
        <span class="log-time">${l.t||''}</span>
        <span class="log-dot" style="background:${col}"></span>
        <span style="font-size:12px;color:${textCol};line-height:1.5">${l.msg||''}</span>
        <span class="log-type-label">${l.type||''}</span>
      </div>`;
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
