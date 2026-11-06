import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  pkceS256, signJwt, verifyJwt, importSigningKey, publicJwk, CLOCK_TOLERANCE_SECONDS, ALGORITHMS,
  normalizePath, selectRule, safeReturnTo, sealCookie, openCookie, decodeCookieSecret, loadConfig, randomToken,
} from '../src/index.js';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const RFC_VERIFIER = ['dBjftJeZ4CVP', 'mB92K27uhbUJU' + '1p1r_wW1gFWFOEjXk'].join('-');
const RFC_CHALLENGE = ['E9Melhoa2OwvFrEMTJ' + 'guCHaoeK1t8URWbuGJSstw', 'cM'].join('-');

test('PKCE S256 与 RFC 7636 附录 B 向量一致', async () => {
  assert.equal(await pkceS256(RFC_VERIFIER), RFC_CHALLENGE);
});

test('ES256 往返、篡改、过期、iss、aud、alg 白名单', async () => {
  assert.deepEqual(ALGORITHMS, ['ES256']);
  assert.ok(CLOCK_TOLERANCE_SECONDS <= 5);
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await crypto.subtle.exportKey('jwk', kp.privateKey)), kid: 'test-k1' };
  const key = await importSigningKey(JSON.stringify(jwk));
  const pub = publicJwk(jwk);
  assert.equal('d' in pub, false);
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: 'https://id.example.com', aud: ['https://ainews.example.com/api', 'b'], sub: 'u1', iat: now, exp: now + 60 };
  const token = await signJwt(key, claims, 'at+jwt');
  const opt = { issuer: 'https://id.example.com', audience: 'https://ainews.example.com/api', typ: 'at+jwt', now: now * 1000 };
  assert.equal((await verifyJwt(token, [pub], opt)).sub, 'u1');
  const [h, p, s] = token.split('.');
  const forged = [h, Buffer.from(JSON.stringify({ ...claims, sub: 'admin' })).toString('base64url'), s].join('.');
  await assert.rejects(() => verifyJwt(forged, [pub], opt), /signature/);
  const expired = await signJwt(key, { ...claims, exp: now - 1 }, 'at+jwt');
  await assert.rejects(() => verifyJwt(expired, [pub], opt), /expired/);
  await assert.rejects(() => verifyJwt(token, [pub], { ...opt, issuer: 'https://evil.example.com' }), /iss/);
  await assert.rejects(() => verifyJwt(token, [pub], { ...opt, audience: 'https://other.example.com/api' }), /aud/);
  await assert.rejects(() => verifyJwt(token, [pub], { ...opt, typ: 'JWT' }), /typ/);
  const none = `${Buffer.from(JSON.stringify({ alg: 'none', typ: 'at+jwt', kid: 'test-k1' })).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
  await assert.rejects(() => verifyJwt(none, [pub], opt), /malformed|alg/);
});

test('路径规范化、最长前缀、未列出的方法、解码失败', () => {
  const rules = [
    { prefix: '/subscriptions', methods: ['GET', 'HEAD'], require: { login: true } },
    { prefix: '/api/subscriptions', methods: ['GET', 'HEAD'], require: { login: true, feature: 'ainews:feeds.read' } },
    { prefix: '/api/subscriptions', methods: ['POST', 'PUT', 'DELETE'], require: { login: true, feature: 'ainews:feeds.write' } },
  ];
  const hit = (p, m = 'GET') => selectRule(p, m, rules).kind === 'rule';
  assert.equal(hit('/subscriptions'), true);
  assert.equal(hit('/subscriptions/'), true);
  assert.equal(hit('/subscriptions/x'), true);
  assert.equal(hit('/subscriptionsx'), false);
  assert.equal(hit('/SUBSCRIPTIONS'), true);
  assert.equal(hit('/%73ubscriptions'), true);
  assert.equal(hit('//api//subscriptions'), true);
  assert.equal(hit('/api/subscriptions/abc'), true);
  assert.equal(hit('/api/%2573'), false);
  assert.equal(normalizePath('/%E0%A4%A').ok, false);
  assert.equal(selectRule('/%E0%A4%A', 'GET', rules).kind, 'decode-error');
  assert.equal(selectRule('/subscriptions', 'POST', rules).kind, 'method');
  assert.equal(selectRule('/api/subscriptions', 'DELETE', rules).rule.require.feature, 'ainews:feeds.write');
  const both = [
    { prefix: '/api', methods: ['GET'], require: { login: true } },
    { prefix: '/api/subscriptions', methods: ['GET'], require: { feature: 'ainews:feeds.read' } },
  ];
  assert.equal(selectRule('/api/subscriptions/x', 'GET', both).rule.require.feature, 'ainews:feeds.read');
});

test('前缀 / 匹配全部后代，更长前缀仍优先', () => {
  const rules = [
    { prefix: '/', methods: ['GET'], require: { login: true } },
    { prefix: '/subscriptions', methods: ['GET'], require: { feature: 'ainews:feeds.read' } },
  ];
  assert.equal(selectRule('/private', 'GET', rules).rule.require.login, true);
  assert.equal(selectRule('/private/x', 'GET', rules).rule.prefix, '/');
  assert.equal(selectRule('/', 'GET', rules).rule.prefix, '/');
  assert.equal(selectRule('/subscriptions', 'GET', rules).rule.require.feature, 'ainews:feeds.read');
  assert.equal(selectRule('/subscriptions/x', 'GET', rules).rule.require.feature, 'ainews:feeds.read');
  assert.equal(selectRule('/subscriptionsx', 'GET', rules).rule.prefix, '/');
});

test('return_to 只接受同源路径', () => {
  assert.equal(safeReturnTo('/subscriptions'), '/subscriptions');
  assert.equal(safeReturnTo('https://evil.example.net/x'), '/');
  assert.equal(safeReturnTo('//evil.example.net'), '/');
  assert.equal(safeReturnTo('/../etc'), '/');
  assert.equal(safeReturnTo(''), '/');
});

test('cookie 密封可解开；篡改、换密钥、版本不对都当作没有会话', async () => {
  const secret = decodeCookieSecret(randomToken(32));
  assert.equal(secret.length, 32);
  const payload = { v: 1, sub: 'u1', at: 'a.b.c' };
  const sealed = await sealCookie(secret, '__Host-pkauth', payload);
  assert.equal((await openCookie(secret, '__Host-pkauth', sealed)).sub, 'u1');
  const flipped = `${sealed.slice(0, -2)}${sealed.slice(-2) === 'aa' ? 'bb' : 'aa'}`;
  assert.equal(await openCookie(secret, '__Host-pkauth', flipped), null);
  const other = decodeCookieSecret(randomToken(32));
  assert.equal(await openCookie(other, '__Host-pkauth', sealed), null);
  assert.equal(await openCookie(secret, '__Host-pkauth_tx', sealed), null);
  const v2 = await sealCookie(secret, '__Host-pkauth', { v: 2, sub: 'u1' });
  assert.equal(await openCookie(secret, '__Host-pkauth', v2), null);
});

test('配置缺失 fail-closed；空 Host 名单不是缺失', () => {
  const secret = randomToken(32);
  const base = {
    PKAUTH_ISSUER: 'https://id.example.com',
    PKAUTH_CLIENT_ID: 'ainews',
    PKAUTH_RESOURCE: 'https://ainews.example.com/api',
    PKAUTH_ALLOWED_HOSTS: 'ainews.example.com',
    PKAUTH_RULES: '[]',
    PKAUTH_DEFAULT: 'public',
    PKAUTH_MODE: 'enforce',
    PKAUTH_COOKIE_SECRET: secret,
  };
  assert.equal(loadConfig(base).ok, true);
  assert.equal(loadConfig({ ...base, PKAUTH_COOKIE_SECRET: '' }).ok, false);
  assert.equal(loadConfig({ ...base, PKAUTH_MODE: 'off' }).mode, 'off');
  const emptyHost = loadConfig({ ...base, PKAUTH_ALLOWED_HOSTS: '' });
  assert.equal(emptyHost.ok, true);
  assert.deepEqual(emptyHost.hosts, []);
  const inject = loadConfig({ ...base, PKAUTH_UPSTREAM_INJECT: '{"x-admin-token":"ADMIN_TOKEN"}' });
  assert.equal(inject.inject['x-admin-token'], 'ADMIN_TOKEN');
});
