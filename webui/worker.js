/**
 * Cloudflare Workers - v8fuzz API
 * WebUIとDropletの中継・ダッシュボードデータ配信
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // 認証チェック
    const secret = request.headers.get('X-API-Secret');
    if (secret !== env.API_SECRET) {
      // GETの一部は認証不要（ダッシュボード表示用）
      if (!path.startsWith('/public/')) {
        return json({ error: 'Unauthorized' }, 401);
      }
    }

    try {
      // ルーティング
      if (path === '/crashes' && request.method === 'GET') {
        return await getCrashes(env);
      }
      if (path.startsWith('/crashes/') && request.method === 'GET') {
        const id = path.split('/')[2];
        return await getCrash(env, id);
      }
      if (path === '/targets' && request.method === 'GET') {
        return await getTargets(env);
      }
      if (path === '/stats' && request.method === 'GET') {
        return await getStats(env);
      }
      if (path === '/logs' && request.method === 'GET') {
        return await getLogs(env);
      }

      // Dropletからのデータ受信
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

// --- データ取得 ---

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
  return json(data.slice(-100)); // 最新100件
}

// --- Dropletからのデータ受信 ---

async function receiveCrash(request, env) {
  const crash = await request.json();

  // 既存クラッシュ一覧を取得して追加
  const crashes = await env.KV.get('crashes', 'json') || [];
  crashes.unshift(crash); // 先頭に追加

  // 最大500件保持
  const trimmed = crashes.slice(0, 500);
  await env.KV.put('crashes', JSON.stringify(trimmed));

  // ログにも記録
  await appendLog(env, {
    t: new Date().toISOString().slice(11, 19),
    type: 'crash',
    msg: `${crash.id} detected — ${crash.engine.toUpperCase()} ${crash.crash_type} CVSS${crash.cvss}`
  });

  return json({ ok: true });
}

async function receiveStats(request, env) {
  const stats = await request.json();
  await env.KV.put('stats', JSON.stringify({
    ...stats,
    updated_at: Date.now(),
  }));
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
  // 最大1000件
  const trimmed = logs.slice(-1000);
  await env.KV.put('logs', JSON.stringify(trimmed));
}

// --- ユーティリティ ---

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS,
    },
  });
}
