// S-1 … S-16：由已关闭的 Access PR 测试改写的 OIDC 版 SDK 回归。本地 ES256，固定时钟，不访问网络。
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, createHmac } from 'node:crypto';
import { protect, CLOCK_TOLERANCE_SECONDS } from '../src/index.js';
import { importSigningKey, publicJwk, signJwt, sealCookie, decodeCookieSecret, randomToken, ALGORITHMS } from '@pkauth/core';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const HOST = 'ainews.example.com';
const BASE = `https://${HOST}`;
const ISS = 'https://id.example.com';
const AUD = 'https://ainews.example.com/api';
const NOW = Date.parse('2026-11-05T04:00:00Z');
const nowSec = Math.floor(NOW / 1000);
const SUB = 'sub-owner-1';
const SECRET = randomToken(32);
const secretBytes = decodeCookieSecret(SECRET);

const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const priv = { ...(await crypto.subtle.exportKey('jwk', kp.privateKey)), kid: 'k1' };
const sk = await importSigningKey(JSON.stringify(priv));
const jwk = publicJwk(priv);
const otherKp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const otherSk = await importSigningKey(JSON.stringify({ ...(await crypto.subtle.exportKey('jwk', otherKp.privateKey)), kid: 'k1' }));

const RULES = JSON.stringify([
  { prefix: '/subscriptions', methods: ['GET', 'HEAD'], require: { login: true, feature: 'ainews:feeds.read' } },
  { prefix: '/api/subscriptions', methods: ['GET', 'HEAD'], require: { login: true, feature: 'ainews:feeds.read' } },
  { prefix: '/api/subscriptions', methods: ['POST', 'PUT', 'DELETE'], require: { login: true, feature: 'ainews:feeds.write', online: true, csrf: true } },
]);

const sign = (over = {}) => signJwt(over.key || sk, {
  iss: over.iss || ISS,
  sub: over.sub || SUB,
  aud: over.aud || [AUD],
  iat: nowSec - 30,
  exp: over.exp ?? nowSec + 600,
  auth_time: over.auth_time ?? nowSec - 10,
  acr: over.acr || 'urn:pkauth:acr:passkey',
  ent: over.ent || ['ainews:feeds.read'],
  sid: 'sid-hash',
  client_id: 'ainews',
}, over.typ || 'at+jwt');

function baseEnv(over = {}) {
  return {
    PKAUTH_ISSUER: ISS,
    PKAUTH_CLIENT_ID: 'ainews',
    PKAUTH_RESOURCE: AUD,
    PKAUTH_ALLOWED_HOSTS: HOST,
    PKAUTH_RULES: RULES,
    PKAUTH_DEFAULT: 'public',
    PKAUTH_MODE: 'enforce',
    PKAUTH_COOKIE_SECRET: SECRET,
    ADMIN_TOKEN: 'test-admin-secret',
    ...over,
  };
}

let jwksFetches = 0;
let entMode = 'allow';
let tokenHandler = null;
const fetchImpl = async (input) => {
  const req = input instanceof Request ? input : new Request(input);
  const url = new URL(req.url);
  if (url.pathname === '/oauth/jwks') {
    jwksFetches += 1;
    if (jwksMode === 'fail') return new Response('no', { status: 503 });
    return Response.json({ keys: [jwk] });
  }
  if (url.pathname === '/oauth/token') {
    if (tokenHandler) return tokenHandler(req);
    return Response.json({ error: 'unsupported' }, { status: 400 });
  }
  if (url.pathname === '/ent/v1/check') {
    entCalls.push(url.toString());
    if (entMode === 'down') return new Response('no', { status: 503 });
    if (entMode === 'hang') return new Promise((_resolve, reject) => { req.signal.addEventListener('abort', () => reject(new Error('aborted'))); });
    const allow = entMode === 'allow';
    return Response.json({ allow });
  }
  return new Response('missing', { status: 404 });
};
let jwksMode = 'ok';
let entCalls = [];

let seen = null;
const upstream = {
  fetch: async (req) => {
    seen = req;
    return new Response('inner-ok', { status: 200, headers: { 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=60' } });
  },
  scheduled: async () => 'sched',
};

function make(envOver = {}, opt = {}) {
  seen = null;
  const env = baseEnv(envOver);
  let clock = opt.now ?? NOW;
  const worker = protect(upstream, { fetchImpl, now: () => clock, jwksCooldownMs: 0, onlineTimeoutMs: opt.onlineTimeoutMs ?? 50, jwksStaleMs: opt.jwksStaleMs, ...opt });
  return {
    env, worker,
    setNow(ms) { clock = ms; },
    call(path, { token, method = 'GET', headers = {}, host, cookie } = {}) {
      seen = null;
      const h = new Headers(headers);
      if (token !== undefined) h.set('authorization', `Bearer ${token}`);
      if (cookie) h.set('cookie', cookie);
      const body = method === 'GET' || method === 'HEAD' ? undefined : '{}';
      return worker.fetch(new Request(`https://${host || HOST}${path}`, { method, headers: h, body }), env, {});
    },
  };
}

async function sessionCookie(over = {}) {
  const at = await sign(over);
  const payload = { v: 1, sid: 'sid', sub: over.sub || SUB, at, rt: over.rt, atExp: ((over.exp ?? nowSec + 600) * 1000), authTime: over.auth_time ?? nowSec - 10, acr: over.acr || 'urn:pkauth:acr:passkey', absExp: NOW + 86400000, ent: over.ent || ['ainews:feeds.read'] };
  const sealed = await sealCookie(over.secret || secretBytes, '__Host-pkauth', payload);
  return { cookie: `__Host-pkauth=${sealed}`, at };
}

test('S-1 有效 AT 放行且 X-PKAuth-Sub 正确；伪造的内部头被剥离', async () => {
  const w = make();
  const token = await sign();
  const r = await w.call('/subscriptions', { token, headers: { 'x-pkauth-sub': 'attacker', 'x-pkauth-features': 'nope' } });
  assert.equal(r.status, 200);
  assert.equal(seen.headers.get('x-pkauth-sub'), SUB);
  assert.equal(seen.headers.get('x-pkauth-features'), 'ainews:feeds.read');
  assert.equal(seen.headers.get('authorization'), null);
});

test('S-2 缺少凭据、空字符串、不是 JWT → 401，且不调用上游', async () => {
  const w = make();
  assert.equal((await w.call('/api/subscriptions')).status, 401);
  assert.equal(seen, null);
  for (const token of ['', 'not-a-jwt', 'a.b', 'a.b.c']) {
    const r = await w.call('/api/subscriptions', { token });
    assert.equal(r.status, 401, JSON.stringify(token));
    assert.equal(seen, null);
  }
  const nav = await w.call('/subscriptions', { headers: { accept: 'text/html' } });
  assert.equal(nav.status, 302);
  assert.match(nav.headers.get('location'), /^\/_pkauth\/login\?/);
  assert.equal(seen, null);
});

test('S-3 aud / iss / 签名密钥 / typ 不对 → 401', async () => {
  const w = make();
  assert.equal((await w.call('/subscriptions', { token: await sign({ aud: ['https://other.example.com/api'] }) })).status, 401);
  assert.equal((await w.call('/subscriptions', { token: await sign({ iss: 'https://evil.example.com' }) })).status, 401);
  assert.equal((await w.call('/subscriptions', { token: await sign({ key: otherSk }) })).status, 401);
  assert.equal((await w.call('/subscriptions', { token: await sign({ typ: 'JWT' }) })).status, 401);
  assert.equal(seen, null);
});

test('S-4 exp 比固定时钟早 1 秒 → 401；时钟容差 ≤ 5 秒', async () => {
  assert.ok(CLOCK_TOLERANCE_SECONDS <= 5);
  const w = make();
  assert.equal((await w.call('/subscriptions', { token: await sign({ exp: nowSec - 1 }) })).status, 401);
  assert.equal((await w.call('/subscriptions', { token: await sign({ exp: nowSec + 1 }) })).status, 200);
});

test('S-5 未知 kid 重新拉取 JWKS 一次后仍 401；缓存超过陈旧期且拉取失败 → 503', async () => {
  jwksMode = 'ok';
  jwksFetches = 0;
  const w = make();
  assert.equal((await w.call('/subscriptions', { token: await sign() })).status, 200);
  const before = jwksFetches;
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'at+jwt', kid: 'unknown-kid' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ iss: ISS, sub: SUB, aud: [AUD], exp: nowSec + 60, ent: ['ainews:feeds.read'] })).toString('base64url');
  const badKid = `${header}.${body}.aaaa`;
  assert.equal((await w.call('/subscriptions', { token: badKid })).status, 401);
  assert.equal(jwksFetches - before, 1);
  jwksMode = 'fail';
  const cold = make({}, { jwksStaleMs: -1 });
  assert.equal((await cold.call('/subscriptions', { token: await sign() })).status, 503);
  jwksMode = 'ok';
});

test('S-6 alg none 与 HS256 → 401；算法白名单只有 ES256', async () => {
  assert.deepEqual(ALGORITHMS, ['ES256']);
  const w = make();
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const none = `${b64({ alg: 'none', typ: 'at+jwt', kid: 'k1' })}.${b64({ sub: SUB, iss: ISS, aud: [AUD], exp: nowSec + 60 })}.`;
  assert.equal((await w.call('/subscriptions', { token: none })).status, 401);
  const input = `${b64({ alg: 'HS256', kid: 'k1', typ: 'at+jwt' })}.${b64({ sub: SUB, iss: ISS, aud: [AUD], exp: nowSec + 60 })}`;
  const sig = createHmac('sha256', JSON.stringify(jwk)).update(input).digest('base64url');
  assert.equal((await w.call('/subscriptions', { token: `${input}.${sig}` })).status, 401);
});

test('S-7 路径表：命中受保护、不命中公开、解码失败受保护、未列出的方法 405', async () => {
  const w = make();
  const token = await sign();
  for (const p of ['/subscriptions', '/subscriptions/', '/subscriptions/x', '/SUBSCRIPTIONS', '/%73ubscriptions', '//api//subscriptions']) {
    assert.equal((await w.call(p, { token })).status, 200, p);
  }
  for (const p of ['/subscriptionsx', '/api/subscriptionsx', '/', '/health']) {
    const r = await w.call(p);
    assert.equal(r.status, 200, p);
    assert.equal(await r.text(), 'inner-ok');
  }
  assert.equal((await w.call('/%E0%A4%A')).status, 401);
  assert.equal((await w.call('/subscriptions', { method: 'POST', token })).status, 405);
});

test('S-8 Host 不在白名单或白名单为空 → 421', async () => {
  const w = make();
  assert.equal((await w.call('/subscriptions', { token: await sign(), host: 'x.example.workers.dev' })).status, 421);
  const empty = make({ PKAUTH_ALLOWED_HOSTS: '' });
  assert.equal((await empty.call('/subscriptions', { token: await sign() })).status, 421);
});

test('S-9 cookie 写操作的 CSRF；Bearer 写请求不要求 CSRF 头', async () => {
  entMode = 'allow';
  const w = make();
  const token = await sign({ ent: ['ainews:feeds.write'] });
  const { cookie } = await sessionCookie({ ent: ['ainews:feeds.write'] });
  const cases = [
    { origin: 'https://evil.example.com', 'x-pkauth-csrf': '1' },
    { origin: BASE, 'sec-fetch-site': 'same-site', 'x-pkauth-csrf': '1' },
    { origin: BASE },
  ];
  for (const headers of cases) {
    const r = await w.call('/api/subscriptions', { method: 'POST', cookie, headers });
    assert.equal(r.status, 403, JSON.stringify(headers));
    assert.equal(seen, null);
  }
  const ok = await w.call('/api/subscriptions', { method: 'POST', token });
  assert.equal(ok.status, 200);
});

test('S-10 回调校验 state / iss / nonce / tx 过期；坏的 return_to 改成 /', async () => {
  tokenHandler = async () => Response.json({ error: 'no' }, { status: 400 });
  const w = make();
  const login = await w.call('/_pkauth/login?return_to=/subscriptions', { headers: { accept: 'text/html' } });
  assert.equal(login.status, 302);
  const loc = new URL(login.headers.get('location'));
  assert.equal(loc.origin, ISS);
  assert.equal(loc.pathname, '/oauth/authorize');
  assert.equal(loc.searchParams.get('redirect_uri'), `${BASE}/_pkauth/callback`);
  const tx = login.headers.get('set-cookie').split(';')[0];
  const nonce = loc.searchParams.get('nonce');
  const state = loc.searchParams.get('state');
  const id = await signJwt(sk, { iss: ISS, aud: 'ainews', sub: SUB, exp: nowSec + 60, iat: nowSec, nonce, auth_time: nowSec }, 'JWT');
  const at = await sign();
  tokenHandler = async () => Response.json({ access_token: at, id_token: id, token_type: 'Bearer', expires_in: 600 });
  const cookie = tx;
  const cb = (q) => w.worker.fetch(new Request(`${BASE}/_pkauth/callback?${q}`, { headers: { cookie } }), w.env, {});
  const badState = await cb(`code=${'a'.repeat(20)}&state=nope&iss=${encodeURIComponent(ISS)}`);
  assert.equal(badState.status, 400);
  assert.equal((badState.headers.get('set-cookie') || '').includes('__Host-pkauth='), false);
  const badIss = await cb(`code=${'a'.repeat(20)}&state=${state}&iss=${encodeURIComponent('https://evil.example.com')}`);
  assert.equal(badIss.status, 400);
  const badNonceId = await signJwt(sk, { iss: ISS, aud: 'ainews', sub: SUB, exp: nowSec + 60, iat: nowSec, nonce: 'other-nonce', auth_time: nowSec }, 'JWT');
  tokenHandler = async () => Response.json({ access_token: at, id_token: badNonceId, token_type: 'Bearer', expires_in: 600 });
  const badNonce = await cb(`code=${'a'.repeat(20)}&state=${state}&iss=${encodeURIComponent(ISS)}`);
  assert.equal(badNonce.status, 400);
  w.setNow(NOW + 11 * 60 * 1000);
  tokenHandler = async () => Response.json({ access_token: at, id_token: id, token_type: 'Bearer', expires_in: 600 });
  const expired = await cb(`code=${'a'.repeat(20)}&state=${state}&iss=${encodeURIComponent(ISS)}`);
  assert.equal(expired.status, 400);
  w.setNow(NOW);
  const evilLogin = await w.call('/_pkauth/login?return_to=https://evil.example.net/phish', { headers: { accept: 'text/html' } });
  const evilTx = evilLogin.headers.get('set-cookie').split(';')[0];
  const evilLoc = new URL(evilLogin.headers.get('location'));
  const evilId = await signJwt(sk, { iss: ISS, aud: 'ainews', sub: SUB, exp: nowSec + 60, iat: nowSec, nonce: evilLoc.searchParams.get('nonce'), auth_time: nowSec }, 'JWT');
  tokenHandler = async () => Response.json({ access_token: at, id_token: evilId, token_type: 'Bearer', expires_in: 600 });
  const back = await w.worker.fetch(new Request(`${BASE}/_pkauth/callback?code=${'b'.repeat(20)}&state=${evilLoc.searchParams.get('state')}&iss=${encodeURIComponent(ISS)}`, { headers: { cookie: evilTx } }), w.env, {});
  assert.equal(back.status, 302);
  assert.equal(new URL(back.headers.get('location'), BASE).pathname, '/');
  const slash = await w.call('/_pkauth/login?return_to=//evil.example.net', { headers: { accept: 'text/html' } });
  const slashTx = slash.headers.get('set-cookie').split(';')[0];
  const slashLoc = new URL(slash.headers.get('location'));
  const slashId = await signJwt(sk, { iss: ISS, aud: 'ainews', sub: SUB, exp: nowSec + 60, iat: nowSec, nonce: slashLoc.searchParams.get('nonce'), auth_time: nowSec }, 'JWT');
  tokenHandler = async () => Response.json({ access_token: at, id_token: slashId, token_type: 'Bearer', expires_in: 600 });
  const slashBack = await w.worker.fetch(new Request(`${BASE}/_pkauth/callback?code=${'c'.repeat(20)}&state=${slashLoc.searchParams.get('state')}&iss=${encodeURIComponent(ISS)}`, { headers: { cookie: slashTx } }), w.env, {});
  assert.equal(new URL(slashBack.headers.get('location'), BASE).pathname, '/');
});

test('S-11 cookie 被篡改、密钥换了、版本不对 → 当作未登录', async () => {
  const w = make();
  const good = await sessionCookie();
  assert.equal((await w.call('/api/subscriptions', { cookie: good.cookie })).status, 200);
  const flipped = good.cookie.slice(0, -2) + (good.cookie.endsWith('aa') ? 'bb' : 'aa');
  assert.equal((await w.call('/api/subscriptions', { cookie: flipped })).status, 401);
  const other = await sessionCookie({ secret: decodeCookieSecret(randomToken(32)) });
  assert.equal((await w.call('/api/subscriptions', { cookie: other.cookie })).status, 401);
  const v2 = await sealCookie(secretBytes, '__Host-pkauth', { v: 2, sub: SUB, at: good.at, atExp: NOW + 60000, absExp: NOW + 60000 });
  assert.equal((await w.call('/api/subscriptions', { cookie: `__Host-pkauth=${v2}` })).status, 401);
  assert.equal(seen, null);
});

test('S-12 AT 过期时用 refresh 换新；宽限内并发都成功；超过宽限再重放则家族失效', async () => {
  let issued = null;
  let revoked = false;
  tokenHandler = async (req) => {
    const params = new URLSearchParams(await req.text());
    const rt = params.get('refresh_token');
    if (revoked) return Response.json({ error: 'invalid_grant' }, { status: 400 });
    if (rt === 'rt-old') {
      if (!issued) issued = { at: NOW, access_token: await sign({ exp: nowSec + 600 }), refresh_token: 'rt-new' };
      return Response.json({ access_token: issued.access_token, refresh_token: issued.refresh_token, token_type: 'Bearer', expires_in: 600 });
    }
    return Response.json({ error: 'invalid_grant' }, { status: 400 });
  };
  const w = make();
  const { cookie } = await sessionCookie({ exp: nowSec - 10, rt: 'rt-old' });
  const [a, b] = await Promise.all([
    w.call('/api/subscriptions', { cookie }),
    w.call('/api/subscriptions', { cookie }),
  ]);
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
  // 超过 30 秒宽限后再提交旧 refresh：IdP 吊销家族，SDK 得到 401。
  tokenHandler = async (req) => {
    const params = new URLSearchParams(await req.text());
    const rt = params.get('refresh_token');
    if (rt === 'rt-old' || rt === 'rt-new') {
      revoked = true;
      return Response.json({ error: 'invalid_grant' }, { status: 400 });
    }
    return Response.json({ error: 'invalid_grant' }, { status: 400 });
  };
  const late = await w.call('/api/subscriptions', { cookie });
  assert.equal(late.status, 401);
  const { cookie: next } = await sessionCookie({ exp: nowSec - 10, rt: 'rt-new' });
  assert.equal((await w.call('/api/subscriptions', { cookie: next })).status, 401);
  assert.equal(revoked, true);
});

test('S-13 online：拒绝 403、超时 503、没有 service binding 时走 HTTPS', async () => {
  entCalls = [];
  entMode = 'deny';
  const w = make();
  const token = await sign({ ent: ['ainews:feeds.write'] });
  assert.equal((await w.call('/api/subscriptions', { method: 'DELETE', token })).status, 403);
  assert.equal(seen, null);
  assert.match(entCalls[0], /^https:\/\/id\.example\.com\/ent\/v1\/check$/);
  entMode = 'hang';
  assert.equal((await w.call('/api/subscriptions', { method: 'DELETE', token })).status, 503);
  entMode = 'allow';
  let bound = 0;
  const boundEnv = make({ PKAUTH_IDP: { fetch: async (req) => { bound += 1; assert.equal(new URL(req.url).pathname, '/ent/v1/check'); return Response.json({ allow: true }); } } });
  const before = entCalls.length;
  assert.equal((await boundEnv.call('/api/subscriptions', { method: 'DELETE', token })).status, 200);
  assert.equal(bound, 1);
  assert.equal(entCalls.length, before);
  entMode = 'allow';
});

test('S-14 授权通过后注入 secret；客户端自带的头被删掉；未授权时上游收不到', async () => {
  const w = make({ PKAUTH_UPSTREAM_INJECT: '{"x-admin-token":"ADMIN_TOKEN"}' });
  const token = await sign();
  const ok = await w.call('/subscriptions', { token, headers: { 'x-admin-token': 'from-client', authorization: 'Bearer ignored' } });
  assert.equal(ok.status, 200);
  assert.equal(seen.headers.get('x-admin-token'), 'test-admin-secret');
  const denied = await w.call('/subscriptions');
  assert.equal(denied.status, 401);
  assert.equal(seen, null);
});

test('S-15 受保护响应 no-store 且没有 ACAO *；OPTIONS → 403', async () => {
  const w = make();
  const r = await w.call('/subscriptions', { token: await sign() });
  assert.equal(r.headers.get('cache-control'), 'private, no-store');
  assert.equal(r.headers.get('access-control-allow-origin'), null);
  const opt = await w.call('/subscriptions', { method: 'OPTIONS' });
  assert.equal(opt.status, 403);
  assert.equal(seen, null);
  const pub = await w.call('/health');
  assert.equal(pub.headers.get('access-control-allow-origin'), '*');
});

test('PKAUTH_DEFAULT=protected 且规则缺失或为空时全部受保护，不转给上游', async () => {
  for (const rules of [undefined, '']) {
    const w = make({ PKAUTH_RULES: rules, PKAUTH_DEFAULT: 'protected' });
    assert.equal((await w.call('/health')).status, 503, String(rules));
    assert.equal(seen, null);
    assert.equal((await w.call('/private')).status, 503);
    assert.equal(seen, null);
  }
  const listed = make({ PKAUTH_RULES: '[]', PKAUTH_DEFAULT: 'protected' });
  assert.equal((await listed.call('/health')).status, 401);
  assert.equal(seen, null);
  assert.equal((await listed.call('/private', { token: await sign() })).status, 200);
  const open = make({ PKAUTH_RULES: undefined, PKAUTH_DEFAULT: 'public' });
  assert.equal((await open.call('/health')).status, 200);
});

test('前缀 / 命中全部后代路径；更长前缀仍然优先', async () => {
  const w = make({
    PKAUTH_DEFAULT: 'public',
    PKAUTH_RULES: JSON.stringify([
      { prefix: '/', methods: ['GET', 'HEAD'], require: { login: true } },
      { prefix: '/subscriptions', methods: ['GET', 'HEAD'], require: { login: true, feature: 'ainews:feeds.read' } },
    ]),
  });
  assert.equal((await w.call('/private')).status, 401);
  assert.equal(seen, null);
  assert.equal((await w.call('/private', { token: await sign() })).status, 200);
  assert.equal((await w.call('/subscriptions', { token: await sign({ ent: [] }) })).status, 403);
  assert.equal(seen, null);
});

test('S-16 MODE=off 或缺配置时受保护路径 503、公开路径不变；scheduled 透传', async () => {
  const off = make({ PKAUTH_MODE: 'off' });
  assert.equal((await off.call('/subscriptions', { token: await sign() })).status, 503);
  assert.equal((await off.call('/health')).status, 200);
  const missing = make({ PKAUTH_COOKIE_SECRET: '' });
  assert.equal((await missing.call('/subscriptions')).status, 503);
  assert.equal(await (await missing.call('/health')).text(), 'inner-ok');
  assert.equal(await off.worker.scheduled({}, off.env, {}), 'sched');
});
