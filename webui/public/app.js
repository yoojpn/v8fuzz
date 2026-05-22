const API = 'https://v8fuzz.YOUR_SUBDOMAIN.workers.dev';
let crashes = [];

function fmt(n) {
  if (n == null) return '—';
  if (n >= 1e9) return (n/1e9).toFixed(2)+'B';
  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
  if (n >= 1e3) return (n/1e3).toFixed(1)+'K';
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
    const s = await fetch(API+'/stats').then(r=>r.json());
    document.getElementById('kpi-execs').textContent = fmt(s.total_execs);
    document.getElementById('kpi-execs-rate').textContent = fmt(s.exec_rate)+' exec/s';
    document.getElementById('kpi-crashes').textContent = fmt(s.total_crashes);
    document.getElementById('kpi-crashes-sub').textContent = fmt(s.unique_crashes)+' unique';
    document.getElementById('kpi-seeds').textContent = fmt(s.corpus_size);
    document.getElementById('stat-api').textContent = fmt(s.api_requests_today);
    document.getElementById('stat-workers').textContent = s.active_workers ?? '—';
    if (s.start_time) {
      const days = Math.floor((Date.now()/1000 - s.start_time)/86400);
      document.getElementById('kpi-uptime').textContent = days+'d';
      document.getElementById('kpi-uptime-sub').textContent = new Date(s.start_time*1000).toLocaleDateString('ja-JP');
    }
    document.getElementById('last-update').textContent = new Date().toLocaleTimeString('ja-JP');
  } catch(e) {}
}

async function fetchCrashes() {
  try {
    crashes = await fetch(API+'/crashes').then(r=>r.json());
    renderCrashes();
    document.getElementById('crash-count').textContent = crashes.length+' entries';
  } catch(e) {}
}

function renderCrashes() {
  const el = document.getElementById('crash-list');
  if (!crashes.length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">🔍</div>No crashes yet — fuzzer is running</div>';
    return;
  }
  el.innerHTML = crashes.slice(0,50).map(c => {
    const sev = severity(c.cvss);
    const col = sev==='CRITICAL'?'critical':sev==='HIGH'?'high':sev==='MEDIUM'?'medium':'low';
    return `<div class="crash-row" onclick="showCrash('${c.id}')">
      <div class="crash-id">${(c.id||'').slice(0,8)}</div>
      <div class="crash-type">${c.crash_type||'—'}</div>
      <div class="crash-title">${c.title||'—'}</div>
      <div class="cvss-val" style="color:var(--${col})">${c.cvss||'—'}</div>
      <div><span class="engine-badge">${(c.engine||'v8').toUpperCase()}</span></div>
      <div><span class="sev ${sev}">${sev}</span></div>
    </div>`;
  }).join('');
}

async function fetchLogs() {
  try {
    const logs = await fetch(API+'/logs').then(r=>r.json());
    const el = document.getElementById('log-feed');
    if (!logs.length) return;
    document.getElementById('log-count').textContent = logs.length+' events';
    el.innerHTML = logs.slice(-80).reverse().map(l => {
      const cls = l.type==='crash'?'crash':l.type==='warn'?'warn':'info';
      return `<div class="log-entry ${cls}"><span class="log-time">${l.t||''}</span><span class="log-msg">${l.msg||''}</span></div>`;
    }).join('');
  } catch(e) {}
}

window.showCrash = function(id) {
  const c = crashes.find(x=>x.id===id);
  if (!c) return;
  const sev = severity(c.cvss);
  document.getElementById('modal-title').innerHTML =
    `<span class="sev ${sev}" style="font-size:12px;margin-right:10px">${sev}</span>${c.title||id}`;
  document.getElementById('modal-grid').innerHTML = [
    ['ID',c.id],['Engine',(c.engine||'').toUpperCase()],
    ['Crash Type',c.crash_type],['CVSS',c.cvss],
    ['Component',c.component],['Exploitability',c.exploitability],
    ['Detected',c.detected_at?new Date(c.detected_at*1000).toLocaleString('ja-JP'):'—'],
    ['Minimized',c.minimized?'✅ Yes':'—'],
  ].map(([l,v])=>`<div class="modal-field"><label>${l}</label><p>${v||'—'}</p></div>`).join('');
  const poc = c.poc_js||c.js_code;
  document.getElementById('modal-poc').innerHTML = poc
    ? `<div style="font-size:10px;letter-spacing:1.5px;color:var(--muted);text-transform:uppercase;margin-bottom:6px">PoC</div>
       <div class="poc-block"><pre>${poc.replace(/</g,'&lt;')}</pre></div>` : '';
  document.getElementById('modal-overlay').classList.add('open');
};

window.closeModal = function() {
  document.getElementById('modal-overlay').classList.remove('open');
};
document.getElementById('modal-overlay').addEventListener('click', e => {
  if (e.target===e.currentTarget) closeModal();
});

async function refresh() {
  await Promise.all([fetchStats(), fetchCrashes(), fetchLogs()]);
}
refresh();
setInterval(refresh, 10000);
