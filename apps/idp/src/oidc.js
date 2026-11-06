// OIDC Phase 1：discovery / JWKS / authorize（code + PKCE S256）/ token（含 refresh 轮换）/ userinfo。
// 依赖通过 makeOidc(deps) 注入，避免与 worker.js 循环 import。规格：docs/specs/oidc-phase1.md
import { importSigningKey, signJwt, verifyJwt, publicJwk, sha256b64u, pkceS256, randomToken, redirectAllowed } from './oidc-core.js';
import { getClient } from './oidc-clients.js';

export const ACR_STEPUP = 'urn:pkauth:acr:stepup';
export const ACR_BASE = 'urn:pkauth:acr:passkey';
const TOKEN_TTL = 600; // 秒：access / id token
const REFRESH_GRACE_MS = 30_000; // D6：轮换后 30 秒内，同一 client 重放刚换掉的 refresh 返回同一份新 token

export function refreshGraceMs(env) {
  if (env && env.RP_ID === 'localhost' && env.OIDC_REFRESH_GRACE_MS != null && String(env.OIDC_REFRESH_GRACE_MS) !== '') {
    const n = Number(env.OIDC_REFRESH_GRACE_MS);
    if (Number.isFinite(n) && n >= 0) return n;
  }
  return REFRESH_GRACE_MS;
}
// otp / single 不签发 refresh（§7.3）。字段缺省（旧授权码）仍允许，避免把没有策略的账户误伤。
export function allowsRefresh(expiry) {
  return !(expiry && (expiry.once === 'otp' || expiry.once === 'single'));
}
export async function takeOtpQuota(state, username, expiry) {
  if (!expiry || expiry.once !== 'otp') return true;
  return state.takeQuota(`otp:${username}`);
}
export function clientAccessDenied(client, ent) {
  if (!client || client.access !== 'feature_required') return false;
  return !Array.isArray(ent) || ent.length === 0;
}
const CODE_TTL_MS = 60e3;
const REFRESH_MAX_MS = 30 * 24 * 3600e3;
const FRESH_MIN_MS = 60e3; // prompt=login / 很小的 max_age：60 秒内的验证视为新鲜（防止 step-up 后循环）
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const NONCE_MAX = 256, STATE_MAX = 512;

export function makeOidc({ json, getSession, getUser, accountExpired, getRole, getExpiry, stateStub, stepUpWindow, audit, securityHeaders }) {
  let keyCache = null; // { src, sk }
  async function signingKey(env) {
    const src = env.OIDC_SIGNING_KEY;
    if (typeof src !== 'string' || !src.trim().startsWith('{')) return null;
    if (keyCache && keyCache.src === src) return keyCache.sk;
    try { keyCache = { src, sk: await importSigningKey(src) }; } catch { return null; }
    return keyCache.sk;
  }
  function jwks(env, sk) {
    const keys = [sk.jwk];
    try { // 轮换期：上一把公钥（只含公钥字段）
      if (env.OIDC_SIGNING_KEY_PREV_PUBLIC) { const p = publicJwk(JSON.parse(env.OIDC_SIGNING_KEY_PREV_PUBLIC)); if (p.kid && p.kid !== sk.kid && p.x && p.y) keys.push(p); }
    } catch { /* 忽略格式错误的上一把公钥 */ }
    return keys;
  }
  const iss = (env) => env.ORIGIN;
  const userinfoAud = (env) => `${env.ORIGIN}/oauth/userinfo`;
  const oerr = (error, status = 400, description) => json(description ? { error, error_description: description } : { error }, status, [], { Pragma: 'no-cache' });
  const unavailable = () => oerr('temporarily_unavailable', 503, 'OIDC 未配置签名密钥');
  const text = (body, status) => new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...securityHeaders } });
  const redirect = (loc) => new Response(null, { status: 302, headers: { Location: loc, 'Cache-Control': 'no-store', ...securityHeaders } });

  function discovery(env) {
    const o = iss(env);
    return json({
      issuer: o,
      authorization_endpoint: `${o}/oauth/authorize`,
      token_endpoint: `${o}/oauth/token`,
      userinfo_endpoint: `${o}/oauth/userinfo`,
      jwks_uri: `${o}/oauth/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: ['openid', 'profile', 'offline_access'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp', 'preferred_username'],
      acr_values_supported: [ACR_BASE, ACR_STEPUP],
      prompt_values_supported: ['none', 'login'],
      authorization_response_iss_parameter_supported: true,
    }, 200, [], { 'Cache-Control': 'public, max-age=300' });
  }

  async function authorize(env, request, url) {
    const q = url.searchParams;
    const client = getClient(env, q.get('client_id'));
    const ru = q.get('redirect_uri');
    // INV-3：client 或 redirect_uri 不对 → 只显示错误，绝不重定向
    if (!client || !redirectAllowed(client, ru)) return text('无效的 client_id 或 redirect_uri（未登记）。', 400);
    const state = q.get('state');
    const back = (params) => {
      const u = new URL(ru);
      for (const [k, v] of Object.entries(params)) if (v != null) u.searchParams.set(k, v);
      if (state && state.length <= STATE_MAX) u.searchParams.set('state', state);
      u.searchParams.set('iss', iss(env));
      return redirect(u.toString());
    };
    const fail = (error, d) => back({ error, error_description: d });
    if (q.get('response_type') !== 'code') return fail('unsupported_response_type', '只支持 response_type=code');
    if (!state || state.length > STATE_MAX) return fail('invalid_request', '必须带 state');
    if (q.get('code_challenge_method') !== 'S256' || !CHALLENGE_RE.test(q.get('code_challenge') || '')) return fail('invalid_request', '必须使用 PKCE S256');
    const asked = (q.get('scope') || '').split(' ').filter(Boolean);
    if (!asked.includes('openid')) return fail('invalid_scope', 'scope 必须包含 openid');
    const scope = [...new Set(asked.filter((s) => client.scopes.includes(s)))].join(' ');
    const nonce = q.get('nonce');
    if (nonce && nonce.length > NONCE_MAX) return fail('invalid_request', 'nonce 过长');
    const prompt = (q.get('prompt') || '').split(' ').filter(Boolean);
    const maxAgeRaw = q.get('max_age');
    const maxAge = maxAgeRaw == null ? null : Number(maxAgeRaw);
    if (maxAge != null && !(Number.isInteger(maxAge) && maxAge >= 0)) return fail('invalid_request', 'max_age 无效');
    const wantStepUp = (q.get('acr_values') || '').split(' ').includes(ACR_STEPUP);

    const session = await getSession(env, request);
    const cont = `/?continue=${encodeURIComponent(url.pathname + url.search)}`;
    if (!session) return prompt.includes('none') ? fail('login_required') : redirect(cont);
    const now = Date.now(), uvAge = session.uvAt ? now - session.uvAt : Infinity;
    const stepUpOk = uvAge <= stepUpWindow(env) && !session.risk;
    const need = !!session.risk || !session.uvAt
      || (prompt.includes('login') && uvAge > FRESH_MIN_MS)
      || (maxAge != null && uvAge > Math.max(maxAge * 1000, FRESH_MIN_MS))
      || (wantStepUp && !stepUpOk);
    if (need) return prompt.includes('none') ? fail('interaction_required') : redirect(`${cont}&stepup=1`);

    const expiry = typeof getExpiry === 'function' ? await getExpiry(env, session.username) : null;
    if (!(await takeOtpQuota(stateStub(env), session.username, expiry))) return fail('access_denied', '一次性登录额度已用完');
    const role = await getRole(env, session.username);
    const ent = client.ent[role ? 'staff' : 'member'];
    if (clientAccessDenied(client, ent)) return fail('access_denied', '没有该应用的访问资格');

    const code = randomToken(32);
    await stateStub(env).issue(`oc:${await sha256b64u(code)}`, CODE_TTL_MS, {
      cid: q.get('client_id'), ru, cc: q.get('code_challenge'), sid: session.sid, username: session.username,
      scope, nonce: nonce || null, authTime: Math.floor(session.uvAt / 1000), acr: stepUpOk ? ACR_STEPUP : ACR_BASE,
      refreshOk: allowsRefresh(expiry),
    });
    return back({ code });
  }

  // 账户还在、未过期、签发它的 IdP 会话仍存活（INV-6 / INV-7）
  async function alive(env, g) {
    const s = await stateStub(env).sessGet(g.sid);
    if (!s || s.username !== g.username || Date.now() >= s.absAt) return null;
    if (await accountExpired(env, g.username)) return null;
    const user = await getUser(env, g.username);
    return user ? { user, session: s } : null;
  }
  async function buildTokens(env, sk, client, g, user, { nonce, refresh }) {
    const now = Math.floor(Date.now() / 1000);
    const role = await getRole(env, user.username);
    const ent = client.ent[role ? 'staff' : 'member'];
    const sub = user.userID;
    const sid = g.sid ? await sha256b64u(g.sid) : undefined;
    const access = await signJwt(sk, {
      iss: iss(env), sub, aud: [...client.audiences, userinfoAud(env)], client_id: g.cid, scope: g.scope, ent,
      tid: 'default', sid, iat: now, exp: now + TOKEN_TTL, jti: randomToken(16), auth_time: g.authTime, acr: g.acr,
      ...(g.scope.split(' ').includes('profile') ? { preferred_username: user.username } : {}),
    }, 'at+jwt');
    const idc = { iss: iss(env), sub, aud: g.cid, azp: g.cid, tid: 'default', sid, iat: now, exp: now + TOKEN_TTL, auth_time: g.authTime, acr: g.acr, amr: ['hwk', 'user'] };
    if (nonce) idc.nonce = nonce;
    if (g.scope.split(' ').includes('profile')) idc.preferred_username = user.username;
    const out = { access_token: access, token_type: 'Bearer', expires_in: TOKEN_TTL, id_token: await signJwt(sk, idc), scope: g.scope };
    if (refresh) out.refresh_token = refresh;
    return out;
  }
  const issueTokens = async (...args) => json(await buildTokens(...args), 200, [], { Pragma: 'no-cache' });

  async function token(env, request) {
    const ct = (request.headers.get('Content-Type') || '').toLowerCase();
    if (!ct.startsWith('application/x-www-form-urlencoded')) return oerr('invalid_request', 'Content-Type 必须是 application/x-www-form-urlencoded');
    const body = await request.text();
    if (body.length > 8192) return oerr('invalid_request');
    const f = new URLSearchParams(body);
    const cid = f.get('client_id');
    const client = getClient(env, cid);
    if (!client) return oerr('invalid_client', 401);
    const sk = await signingKey(env);
    const stub = stateStub(env);
    const gt = f.get('grant_type');

    if (gt === 'authorization_code') {
      const code = f.get('code') || '', ver = f.get('code_verifier') || '';
      if (!TOKEN_RE.test(code)) return oerr('invalid_grant');
      const r = await stub.consume(`oc:${await sha256b64u(code)}`); // INV-5：原子一次性
      if (!r) return oerr('invalid_grant', 400, '授权码无效、已使用或已过期');
      const g = r.data;
      if (g.cid !== cid || g.ru !== f.get('redirect_uri')) return oerr('invalid_grant');
      if (!VERIFIER_RE.test(ver) || (await pkceS256(ver)) !== g.cc) return oerr('invalid_grant', 400, 'PKCE 校验失败');
      const a = await alive(env, g);
      if (!a) return oerr('invalid_grant');
      let refresh = null;
      if (g.refreshOk !== false && g.scope.split(' ').includes('offline_access')) {
        refresh = randomToken(32);
        const ttl = Math.min(a.session.absAt - Date.now(), REFRESH_MAX_MS);
        await stub.rtIssue(await sha256b64u(refresh), randomToken(16), { ...g, nonce: null, cc: null }, ttl);
      }
      await audit(env, request, 'oidc_code', g.username, g.username, { client: cid });
      return issueTokens(env, sk, client, g, a.user, { nonce: g.nonce, refresh });
    }
    if (gt === 'refresh_token') {
      const old = f.get('refresh_token') || '';
      if (!TOKEN_RE.test(old)) return oerr('invalid_grant');
      const graceMs = refreshGraceMs(env);
      const oldHash = await sha256b64u(old);
      const peek = await stub.rtPeek(oldHash, graceMs);
      if (peek.status === 'grace') return json(peek.replay, 200, [], { Pragma: 'no-cache' });
      if (peek.status === 'invalid') return oerr('invalid_grant');
      if (peek.status === 'stale') {
        const revoked = await stub.rtCommit(oldHash, oldHash, null, graceMs);
        if (revoked.grant) await audit(env, request, 'oidc_refresh_reuse', null, revoked.grant.username, { client: revoked.grant.cid });
        return oerr('invalid_grant', 400, 'refresh token 已被使用，整个系列已吊销');
      }
      const g = peek.grant;
      if (g.cid !== cid) { await stub.rtRevokeFamily(peek.fam); return oerr('invalid_grant'); }
      const a = await alive(env, g);
      if (!a) { await stub.rtRevokeFamily(peek.fam); return oerr('invalid_grant'); }
      const next = randomToken(32);
      const payload = await buildTokens(env, sk, client, g, a.user, { nonce: null, refresh: next });
      const committed = await stub.rtCommit(oldHash, await sha256b64u(next), payload, graceMs);
      if (committed.status === 'grace') return json(committed.replay, 200, [], { Pragma: 'no-cache' });
      if (committed.status === 'reuse') {
        await audit(env, request, 'oidc_refresh_reuse', null, (committed.grant || g).username, { client: cid });
        return oerr('invalid_grant', 400, 'refresh token 已被使用，整个系列已吊销');
      }
      if (committed.status !== 'ok') return oerr('invalid_grant');
      return json(payload, 200, [], { Pragma: 'no-cache' });
    }
    return oerr('unsupported_grant_type');
  }

  async function userinfo(env, request, sk) {
    const m = /^Bearer ([A-Za-z0-9_.-]{1,4096})$/.exec(request.headers.get('Authorization') || '');
    const bad = () => json({ error: 'invalid_token' }, 401, [], { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
    if (!m) return bad();
    let c;
    try { c = await verifyJwt(m[1], jwks(env, sk), { issuer: iss(env), audience: userinfoAud(env), typ: 'at+jwt', leewaySec: 0 }); } catch { return bad(); }
    const out = { sub: c.sub };
    if (String(c.scope || '').split(' ').includes('profile')) {
      // 只有 profile scope 才回用户名；sub 是随机 userID，需要反查时只在这里做
      const u = await getUser(env, c.preferred_username || '');
      if (u && u.userID === c.sub) out.preferred_username = u.username;
    }
    return json(out);
  }

  // 返回 Response 或 null（不是 OIDC 路径）
  return async function handle(env, request, url) {
    const p = url.pathname;
    const routes = { '/.well-known/openid-configuration': 'GET', '/oauth/jwks': 'GET', '/oauth/authorize': 'GET', '/oauth/token': 'POST', '/oauth/userinfo': 'GET' };
    if (!Object.hasOwn(routes, p)) return null;
    if (request.method !== routes[p] && !(routes[p] === 'GET' && request.method === 'HEAD')) return oerr('invalid_request', 405);
    const sk = await signingKey(env);
    if (!sk) return unavailable(); // INV-1：fail closed
    const rl = p === '/oauth/authorize' ? 'RL_OPTIONS' : (p === '/oauth/token' || p === '/oauth/userinfo') ? 'RL_VERIFY' : null;
    if (rl) {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const { success } = await env[rl].limit({ key: `${p}|${ip}` });
      if (!success) return oerr('slow_down', 429);
    }
    try {
      if (p === '/.well-known/openid-configuration') return discovery(env);
      if (p === '/oauth/jwks') return json({ keys: jwks(env, sk) }, 200, [], { 'Cache-Control': 'public, max-age=300' });
      if (p === '/oauth/authorize') return await authorize(env, request, url);
      if (p === '/oauth/token') return await token(env, request);
      return await userinfo(env, request, sk);
    } catch (e) {
      console.error('oidc error', e && e.name);
      return oerr('server_error', 500);
    }
  };
}
