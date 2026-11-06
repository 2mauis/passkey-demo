// @pkauth/workers — 接入方唯一的运行时。配置全部来自 env.PKAUTH_*（§4.3）。
import {
  loadConfig, selectRule, safeReturnTo, sealCookie, openCookie, verifyJwt, pkceS256, randomToken,
  CLOCK_TOLERANCE_SECONDS,
} from '@pkauth/core';

export { CLOCK_TOLERANCE_SECONDS };

const COOKIE = '__Host-pkauth';
const TX = '__Host-pkauth_tx';
const TX_TTL_MS = 10 * 60 * 1000;
const ONLINE_TIMEOUT_MS = 2000;
const JWKS_STALE_MS = 60 * 60 * 1000;
const JWKS_COOLDOWN_MS = 30 * 1000;
const CSRF_HEADER = 'x-pkauth-csrf';

const text = (status, body, headers = {}) => new Response(body, {
  status,
  headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'private, no-store', ...headers },
});

function readCookie(request, name) {
  const header = request.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function setCookie(name, value, maxAge) {
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function isApi(request, url) {
  if (request.headers.has('authorization')) return true;
  if (url.pathname.startsWith('/api/')) return true;
  const mode = request.headers.get('sec-fetch-mode');
  if (mode === 'navigate' || request.headers.get('sec-fetch-dest') === 'document') return false;
  const accept = request.headers.get('accept') || '';
  if ((request.method === 'GET' || request.method === 'HEAD') && accept.includes('text/html')) return false;
  return true;
}

function classify(url, method, cfg) {
  const sel = selectRule(url.pathname, method, cfg.rules);
  if (sel.kind === 'decode-error') return { access: 'protected', reason: 'decode' };
  if (sel.kind === 'method') return { access: 'method', methods: sel.methods };
  if (sel.kind === 'rule') return { access: 'protected', rule: sel.rule };
  if (cfg.defaultAccess === 'protected') return { access: 'protected', rule: { require: { login: true } } };
  return { access: 'public' };
}

function createJwks(cfg, fetchImpl, now, staleMs, cooldownMs) {
  let keys = null;
  let fetchedAt = 0;
  let lastUnknown = 0;
  return {
    async keysFor(_kid, refetch) {
      const t = now();
      const fresh = keys && t - fetchedAt <= staleMs;
      if (keys && !refetch && fresh) return { keys };
      // 未知 kid 的第一次重新拉取不受冷却限制；冷却只挡住紧接着的重复拉取（S-5 计数 = 1）。
      if (refetch && lastUnknown && t - lastUnknown < cooldownMs) return { keys };
      if (refetch) lastUnknown = t;
      try {
        const res = await fetchImpl(new Request(`${cfg.issuer}/oauth/jwks`));
        if (!res.ok) throw new Error('status');
        const body = await res.json();
        if (!body || !Array.isArray(body.keys)) throw new Error('shape');
        keys = body.keys;
        fetchedAt = t;
        return { keys };
      } catch {
        if (keys && t - fetchedAt <= staleMs) return { keys };
        return { error: 'stale' };
      }
    },
  };
}

async function verifyAccess(token, cfg, jwks, nowMs) {
  let keys = (await jwks.keysFor(null, false)).keys;
  if (!keys) return { error: 'stale' };
  try {
    const c = await verifyJwt(token, keys, {
      issuer: cfg.issuer, audience: cfg.resource, typ: 'at+jwt', now: nowMs, leewaySec: CLOCK_TOLERANCE_SECONDS,
    });
    return { claims: c };
  } catch (e) {
    if (e.code !== 'kid') return { error: e.code || 'invalid' };
    const again = await jwks.keysFor(null, true);
    if (again.error) return { error: 'stale' };
    try {
      const c = await verifyJwt(token, again.keys, {
        issuer: cfg.issuer, audience: cfg.resource, typ: 'at+jwt', now: nowMs, leewaySec: CLOCK_TOLERANCE_SECONDS,
      });
      return { claims: c };
    } catch (e2) {
      return { error: e2.code || 'invalid' };
    }
  }
}

function bearer(request) {
  const h = request.headers.get('authorization');
  if (h == null) return undefined;
  const m = /^Bearer\s+(\S+)\s*$/i.exec(h);
  return m ? m[1] : '';
}

async function callIdp(env, cfg, path, init, fetchImpl) {
  const binding = env.PKAUTH_IDP;
  if (binding && typeof binding.fetch === 'function') return binding.fetch(new Request(`${cfg.issuer}${path}`, init));
  return fetchImpl(new Request(`${cfg.issuer}${path}`, init));
}

function featuresOf(claims) {
  const ent = claims && claims.ent;
  return Array.isArray(ent) ? ent.filter((x) => typeof x === 'string') : [];
}

function hasFeature(claims, feature) {
  if (!feature) return true;
  return featuresOf(claims).includes(feature);
}

export function protect(upstream, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const now = () => (opts.now ? opts.now() : Date.now());
  const onlineTimeout = opts.onlineTimeoutMs ?? ONLINE_TIMEOUT_MS;
  const staleMs = opts.jwksStaleMs ?? JWKS_STALE_MS;
  const cooldownMs = opts.jwksCooldownMs ?? JWKS_COOLDOWN_MS;
  const cache = new Map();

  function jwksFor(cfg) {
    const hit = cache.get(cfg.issuer);
    if (hit) return hit;
    const created = createJwks(cfg, fetchImpl, now, staleMs, cooldownMs);
    cache.set(cfg.issuer, created);
    return created;
  }

  async function login(request, env, cfg, url) {
    const returnTo = safeReturnTo(url.searchParams.get('return_to') || '/');
    const state = randomToken(24);
    const nonce = randomToken(24);
    const verifier = randomToken(32);
    const tx = { v: 1, state, nonce, verifier, returnTo, exp: now() + TX_TTL_MS };
    const sealed = await sealCookie(cfg.secret, TX, tx);
    const u = new URL(`${cfg.issuer}/oauth/authorize`);
    const redirectUri = `${url.origin}/_pkauth/callback`;
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('client_id', cfg.clientId);
    u.searchParams.set('redirect_uri', redirectUri);
    u.searchParams.set('scope', 'openid profile offline_access');
    u.searchParams.set('state', state);
    u.searchParams.set('nonce', nonce);
    u.searchParams.set('code_challenge', await pkceS256(verifier));
    u.searchParams.set('code_challenge_method', 'S256');
    const maxAge = url.searchParams.get('max_age');
    if (maxAge) u.searchParams.set('max_age', maxAge);
    const acr = url.searchParams.get('acr_values');
    if (acr) u.searchParams.set('acr_values', acr);
    return new Response(null, {
      status: 302,
      headers: { location: u.toString(), 'cache-control': 'private, no-store', 'set-cookie': setCookie(TX, sealed, 600) },
    });
  }

  async function callback(request, env, cfg, url) {
    const tx = await openCookie(cfg.secret, TX, readCookie(request, TX));
    const clear = setCookie(TX, '', 0);
    const fail = () => new Response('login rejected', { status: 400, headers: { 'cache-control': 'private, no-store', 'set-cookie': clear } });
    if (!tx || now() > tx.exp) return fail();
    if (url.searchParams.get('state') !== tx.state) return fail();
    if (url.searchParams.get('iss') !== cfg.issuer) return fail();
    if (url.searchParams.get('error')) return fail();
    const code = url.searchParams.get('code') || '';
    const redirectUri = `${url.origin}/_pkauth/callback`;
    const body = new URLSearchParams({
      grant_type: 'authorization_code', client_id: cfg.clientId, code, redirect_uri: redirectUri, code_verifier: tx.verifier,
    });
    let tokenRes;
    try {
      tokenRes = await callIdp(env, cfg, '/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body }, fetchImpl);
    } catch { return fail(); }
    if (!tokenRes.ok) return fail();
    const tokens = await tokenRes.json();
    let idc;
    try {
      const jwks = await jwksFor(cfg).keysFor(null, false);
      if (!jwks.keys) return fail();
      idc = await verifyJwt(tokens.id_token, jwks.keys, { issuer: cfg.issuer, audience: cfg.clientId, typ: 'JWT', now: now(), leewaySec: CLOCK_TOLERANCE_SECONDS });
    } catch { return fail(); }
    if (idc.nonce !== tx.nonce) return fail();
    let at;
    try { at = await verifyAccess(tokens.access_token, cfg, jwksFor(cfg), now()); } catch { return fail(); }
    if (at.error) return fail();
    const expMs = (at.claims.exp || 0) * 1000;
    const session = {
      v: 1, sid: typeof at.claims.sid === 'string' ? at.claims.sid : '', sub: at.claims.sub,
      at: tokens.access_token, rt: tokens.refresh_token || undefined, atExp: expMs,
      authTime: at.claims.auth_time || 0, acr: at.claims.acr || '', absExp: now() + 7 * 24 * 3600 * 1000,
      ent: featuresOf(at.claims),
    };
    const sealed = await sealCookie(cfg.secret, COOKIE, session);
    const headers = new Headers({ location: safeReturnTo(tx.returnTo), 'cache-control': 'private, no-store' });
    headers.append('set-cookie', clear);
    headers.append('set-cookie', setCookie(COOKIE, sealed, 7 * 24 * 3600));
    return new Response(null, { status: 302, headers });
  }

  function logout() {
    const headers = new Headers({ location: '/', 'cache-control': 'private, no-store' });
    headers.append('set-cookie', setCookie(COOKIE, '', 0));
    headers.append('set-cookie', setCookie(TX, '', 0));
    return new Response(null, { status: 302, headers });
  }

  async function sessionInfo(request, cfg) {
    const s = await openCookie(cfg.secret, COOKIE, readCookie(request, COOKIE));
    if (!s || (s.absExp && now() > s.absExp)) return Response.json({ loggedIn: false }, { headers: { 'cache-control': 'private, no-store' } });
    return Response.json({ loggedIn: true, sub: s.sub, acr: s.acr, authTime: s.authTime }, { headers: { 'cache-control': 'private, no-store' } });
  }

  async function refresh(env, cfg, session) {
    if (!session.rt) return null;
    const body = new URLSearchParams({ grant_type: 'refresh_token', client_id: cfg.clientId, refresh_token: session.rt });
    let res;
    try { res = await callIdp(env, cfg, '/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body }, fetchImpl); }
    catch { return null; }
    if (!res.ok) return null;
    const tokens = await res.json();
    const checked = await verifyAccess(tokens.access_token, cfg, jwksFor(cfg), now());
    if (checked.error) return null;
    return {
      ...session,
      at: tokens.access_token,
      rt: tokens.refresh_token || session.rt,
      atExp: (checked.claims.exp || 0) * 1000,
      authTime: checked.claims.auth_time || session.authTime,
      acr: checked.claims.acr || session.acr,
      sub: checked.claims.sub || session.sub,
      ent: featuresOf(checked.claims),
    };
  }

  function deny(request, url, status, extra = {}) {
    if (status === 401 && !isApi(request, url)) {
      const back = safeReturnTo(url.pathname + url.search);
      return new Response(null, { status: 302, headers: { location: `/_pkauth/login?return_to=${encodeURIComponent(back)}`, 'cache-control': 'private, no-store', ...extra } });
    }
    const headers = { 'cache-control': 'private, no-store', ...extra };
    if (status === 401 && !headers['www-authenticate']) headers['www-authenticate'] = 'Bearer error="invalid_token"';
    return Response.json({ error: status === 403 ? 'forbidden' : 'unauthorized' }, { status, headers });
  }

  async function online(env, cfg, sub, feature) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), onlineTimeout);
    try {
      const res = await callIdp(env, cfg, '/ent/v1/check', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ sub, feature }),
        signal: ac.signal,
      }, fetchImpl);
      if (!res.ok) return { error: res.status === 403 ? 'deny' : 'down' };
      const body = await res.json();
      return body && body.allow === true ? { allow: true } : { allow: false };
    } catch { return { error: 'down' }; }
    finally { clearTimeout(timer); }
  }

  function csrfOk(request, url) {
    const sfs = request.headers.get('sec-fetch-site');
    if (sfs != null && sfs !== 'same-origin') return false;
    if (request.headers.get('origin') !== url.origin) return false;
    if (request.headers.get(CSRF_HEADER) !== '1') return false;
    return true;
  }

  async function forward(request, env, ctx, cfg, claims, sessionCookie) {
    const headers = new Headers(request.headers);
    for (const key of [...headers.keys()]) if (key.toLowerCase().startsWith('x-pkauth-')) headers.delete(key);
    for (const name of Object.keys(cfg.inject)) headers.delete(name);
    headers.delete('authorization');
    if (claims) {
      headers.set('x-pkauth-sub', String(claims.sub || ''));
      headers.set('x-pkauth-features', featuresOf(claims).join(','));
    }
    for (const [name, secretName] of Object.entries(cfg.inject)) {
      const value = env[secretName];
      if (typeof value === 'string') headers.set(name, value);
    }
    const init = { method: request.method, headers };
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      init.body = request.body;
      init.duplex = 'half';
    }
    const res = await upstream.fetch(new Request(request.url, init), env, ctx);
    const out = new Response(res.body, res);
    out.headers.set('cache-control', 'private, no-store');
    out.headers.delete('access-control-allow-origin');
    if (sessionCookie) out.headers.append('set-cookie', sessionCookie);
    return out;
  }

  async function handle(request, env, ctx) {
    const url = new URL(request.url);
    const cfg = loadConfig(env);
    if (url.pathname === '/_pkauth/login' || url.pathname === '/_pkauth/callback' || url.pathname === '/_pkauth/logout' || url.pathname === '/_pkauth/session') {
      if (!cfg.ok || !cfg.secret) return text(503, 'pkauth unavailable');
      if (url.hostname.toLowerCase() === '' || (cfg.hosts.length && !cfg.hosts.includes(url.hostname.toLowerCase()))) return text(421, 'Misdirected Request');
      if (!cfg.hosts.length) return text(421, 'Misdirected Request');
      if (url.pathname === '/_pkauth/login') return login(request, env, cfg, url);
      if (url.pathname === '/_pkauth/callback') return callback(request, env, cfg, url);
      if (url.pathname === '/_pkauth/logout') return logout();
      return sessionInfo(request, cfg);
    }

    const gate = classify(url, request.method, cfg);
    // 规则缺失或空白时：DEFAULT=protected 则全部按受保护（随后因配置不完整 503），不能放成公开。
    const rulesAbsent = env.PKAUTH_RULES == null || String(env.PKAUTH_RULES).trim() === '';
    const access = !cfg.ok && rulesAbsent
      ? (cfg.defaultAccess === 'protected' ? 'protected' : 'public')
      : gate.access;
    if (access === 'public') return upstream.fetch(request, env, ctx);
    if (!cfg.ok || cfg.mode === 'off') return text(503, 'pkauth unavailable');
    if (!cfg.hosts.includes(url.hostname.toLowerCase())) return text(421, 'Misdirected Request');
    if (request.method === 'OPTIONS') return text(403, 'forbidden');
    if (access === 'method') return text(405, 'method not allowed', { allow: (gate.methods || []).join(', ') });

    const reqr = (gate.rule && gate.rule.require) || {};
    const presented = bearer(request);
    let claims = null;
    let session = null;
    let sessionCookie = null;
    if (presented !== undefined) {
      if (!presented || presented.split('.').length !== 3) return deny(request, url, 401);
      const checked = await verifyAccess(presented, cfg, jwksFor(cfg), now());
      if (checked.error === 'stale') return text(503, 'pkauth unavailable');
      if (checked.error) return deny(request, url, 401);
      claims = checked.claims;
    } else {
      session = await openCookie(cfg.secret, COOKIE, readCookie(request, COOKIE));
      if (session && session.absExp && now() > session.absExp) session = null;
      if (session) {
        const atExp = session.atExp || 0;
        if (atExp <= now()) {
          const next = await refresh(env, cfg, session);
          if (!next) return deny(request, url, 401);
          session = next;
          sessionCookie = setCookie(COOKIE, await sealCookie(cfg.secret, COOKIE, session), 7 * 24 * 3600);
        }
        const checked = await verifyAccess(session.at, cfg, jwksFor(cfg), now());
        if (checked.error === 'stale') return text(503, 'pkauth unavailable');
        if (checked.error) return deny(request, url, 401);
        claims = checked.claims;
      }
    }
    if (!claims) return deny(request, url, 401);

    if (reqr.feature && reqr.online) {
      const live = await online(env, cfg, claims.sub, reqr.feature);
      if (live.error === 'down') return text(503, 'pkauth unavailable');
      if (!live.allow) return Response.json({ error: 'insufficient_entitlement', feature: reqr.feature }, { status: 403, headers: { 'cache-control': 'private, no-store' } });
    } else if (reqr.feature && !hasFeature(claims, reqr.feature)) {
      return Response.json({ error: 'insufficient_entitlement', feature: reqr.feature }, { status: 403, headers: { 'cache-control': 'private, no-store' } });
    }

    if (reqr.maxAge || reqr.acr) {
      const authTime = Number(claims.auth_time || session?.authTime || 0);
      const maxAge = Number(reqr.maxAge || 0);
      const tooOld = maxAge > 0 && (now() / 1000 - authTime) > maxAge;
      const acrMiss = reqr.acr && claims.acr !== reqr.acr;
      if (tooOld || acrMiss) {
        if (!isApi(request, url)) {
          const q = new URLSearchParams({ return_to: safeReturnTo(url.pathname + url.search) });
          if (maxAge) q.set('max_age', String(maxAge));
          if (reqr.acr) q.set('acr_values', reqr.acr);
          return new Response(null, { status: 302, headers: { location: `/_pkauth/login?${q}`, 'cache-control': 'private, no-store' } });
        }
        const wa = `Bearer error="insufficient_user_authentication"${reqr.acr ? `, acr_values="${reqr.acr}"` : ''}${maxAge ? `, max_age=${maxAge}` : ''}`;
        return Response.json({ error: 'step_up_required', login_url: `/_pkauth/login?max_age=${maxAge || 300}&return_to=${encodeURIComponent(safeReturnTo(url.pathname + url.search))}` }, {
          status: 401, headers: { 'www-authenticate': wa, 'cache-control': 'private, no-store' },
        });
      }
    }

    const write = !['GET', 'HEAD', 'OPTIONS'].includes(request.method);
    if (write && presented === undefined && (reqr.csrf || write)) {
      if (!csrfOk(request, url)) return Response.json({ error: 'csrf' }, { status: 403, headers: { 'cache-control': 'private, no-store' } });
    }

    return forward(request, env, ctx, cfg, claims, sessionCookie);
  }

  const out = {
    fetch: (request, env, ctx) => handle(request, env, ctx),
  };
  if (upstream && typeof upstream.scheduled === 'function') out.scheduled = (event, env, ctx) => upstream.scheduled(event, env, ctx);
  if (upstream && typeof upstream.queue === 'function') out.queue = (batch, env, ctx) => upstream.queue(batch, env, ctx);
  return out;
}
