const PLATFORMS = new Set(['51彩娱乐', 'MK体育']);
const SESSION_COOKIE = 'aa138_admin';
const SESSION_TTL_SECONDS = 86400;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    },
  });
}

function noContent(headers = {}) {
  return new Response(null, { status: 204, headers });
}

function clientIp(request) {
  return request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || '';
}

function normalizeAccount(value) {
  return String(value || '').trim().replace(/\s+/g, '').toLowerCase();
}

function publicApplication(row) {
  return {
    id: row.id,
    platform: row.platform,
    account: row.account,
    status: row.status,
    created_at: row.created_at,
    paid_at: row.paid_at || null,
  };
}

function base64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64Text(text) {
  return base64url(new TextEncoder().encode(text));
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return base64url(new Uint8Array(sig));
}

async function makeSession(env) {
  const payload = JSON.stringify({ exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS, nonce: crypto.randomUUID() });
  const body = b64Text(payload);
  const sig = await hmac(env.SESSION_SECRET, body);
  return `${body}.${sig}`;
}

async function verifySession(request, env) {
  const cookie = request.headers.get('cookie') || '';
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`));
  if (!m) return false;
  const token = decodeURIComponent(m[1]);
  const [body, sig] = token.split('.');
  if (!body || !sig) return false;
  const expected = await hmac(env.SESSION_SECRET, body);
  if (expected !== sig) return false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(body.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))));
    return Number(payload.exp || 0) >= Math.floor(Date.now() / 1000);
  } catch (_) {
    return false;
  }
}

async function requireAdmin(request, env) {
  if (!(await verifySession(request, env))) throw json({ ok: false, message: '未登录或登录已过期' }, 401);
}

async function readJson(request) {
  try { return await request.json(); } catch (_) { return {}; }
}

async function handleApply(request, env) {
  const body = await readJson(request);
  const platform = String(body.platform || '').trim();
  const account = String(body.account || '').trim();
  const accountNorm = normalizeAccount(account);

  if (!PLATFORMS.has(platform)) return json({ ok: false, message: '请选择正确的平台' }, 400);
  if (accountNorm.length < 3 || accountNorm.length > 40) return json({ ok: false, message: '请填写正确的平台账号' }, 400);
  if (!/^[\p{Script=Han}a-z0-9_.@\-]+$/u.test(accountNorm)) return json({ ok: false, message: '账号仅支持中文、英文、数字、下划线、横杠、点和@' }, 400);

  try {
    const result = await env.DB.prepare(
      `INSERT INTO applications(platform, account, account_norm, status, ip, user_agent)
       VALUES(?1, ?2, ?3, 'pending', ?4, ?5)`
    ).bind(platform, account, accountNorm, clientIp(request).slice(0, 80), (request.headers.get('user-agent') || '').slice(0, 300)).run();
    return json({ ok: true, id: result.meta.last_row_id, message: '申请已提交，赔付将在24小时内发放到对应的游戏账户，完成1倍流水后即可提款。' });
  } catch (e) {
    if (String(e && e.message || e).includes('UNIQUE')) {
      return json({ ok: false, code: 'DUPLICATE_ACCOUNT', message: '该账户已经参与过该活动' }, 409);
    }
    return json({ ok: false, message: '申请失败，请稍后重试' }, 500);
  }
}

async function handleAdminLogin(request, env) {
  const body = await readJson(request);
  if (!env.ADMIN_PASSWORD || String(body.password || '') !== env.ADMIN_PASSWORD) {
    return json({ ok: false, message: '密码错误' }, 401);
  }
  const token = await makeSession(env);
  return json({ ok: true }, 200, {
    'set-cookie': `${SESSION_COOKIE}=${encodeURIComponent(token)}; Max-Age=${SESSION_TTL_SECONDS}; Path=/api/admin; HttpOnly; Secure; SameSite=Strict`,
  });
}

async function handleAdminList(request, env) {
  await requireAdmin(request, env);
  const url = new URL(request.url);
  const status = url.searchParams.get('status') || '';
  let query = `SELECT id, platform, account, status, created_at, paid_at FROM applications`;
  const binds = [];
  if (status === 'pending' || status === 'paid') { query += ` WHERE status=?1`; binds.push(status); }
  query += ` ORDER BY id DESC LIMIT 300`;
  const stmt = env.DB.prepare(query);
  const rows = binds.length ? await stmt.bind(...binds).all() : await stmt.all();
  return json({ ok: true, items: (rows.results || []).map(publicApplication) });
}

async function handleAdminPaid(request, env, id) {
  await requireAdmin(request, env);
  const body = await readJson(request);
  const paid = !!body.paid;
  const status = paid ? 'paid' : 'pending';
  const paidAt = paid ? new Date().toISOString().replace('T', ' ').slice(0, 19) : null;
  await env.DB.prepare(`UPDATE applications SET status=?1, paid_at=?2 WHERE id=?3`).bind(status, paidAt, id).run();
  const row = await env.DB.prepare(`SELECT id, platform, account, status, created_at, paid_at FROM applications WHERE id=?1`).bind(id).first();
  if (!row) return json({ ok: false, message: '记录不存在' }, 404);
  return json({ ok: true, item: publicApplication(row) });
}

async function handleAdminLogout() {
  return json({ ok: true }, 200, {
    'set-cookie': `${SESSION_COOKIE}=; Max-Age=0; Path=/api/admin; HttpOnly; Secure; SameSite=Strict`,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return noContent({ 'access-control-allow-methods': 'GET,POST,OPTIONS', 'access-control-allow-headers': 'content-type' });
    try {
      if (url.pathname === '/api/comp/apply' && request.method === 'POST') return await handleApply(request, env);
      if (url.pathname === '/api/admin/login' && request.method === 'POST') return await handleAdminLogin(request, env);
      if (url.pathname === '/api/admin/logout' && request.method === 'POST') return await handleAdminLogout();
      if (url.pathname === '/api/admin/applications' && request.method === 'GET') return await handleAdminList(request, env);
      const paidMatch = url.pathname.match(/^\/api\/admin\/applications\/(\d+)\/paid$/);
      if (paidMatch && request.method === 'POST') return await handleAdminPaid(request, env, Number(paidMatch[1]));
      return json({ ok: false, message: 'Not found' }, 404);
    } catch (e) {
      if (e instanceof Response) return e;
      return json({ ok: false, message: '服务异常' }, 500);
    }
  }
};
