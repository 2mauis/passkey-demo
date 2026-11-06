// P1 IdP：acr、回调路径、D1 邀请消费、迁移票据、otp/single 不发 refresh、过期账户拒绝。不连 wrangler、不写线上 KV。
import { webcrypto } from 'node:crypto';
import { ACR_BASE, ACR_STEPUP, allowsRefresh, takeOtpQuota, clientAccessDenied, refreshGraceMs, makeOidc } from '../src/oidc.js';
import { getClient } from '../src/oidc-clients.js';
import { consumeInvite, migrateKvToD1, SQL, D1_PREFIXES, attachStore } from '../src/store.js';
import { issueMigrationTicket, redeemMigrationTicket, migrationRegisterPlan, TICKET_TTL_MS, migrationRedirect } from '../src/migrate.js';
import { importSigningKey } from '../src/oidc-core.js';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const R = [];
const check = (n, ok, d = '') => { R.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${d && !ok ? '  — ' + d : ''}`); };

check('acr URN 使用 urn:pkauth:acr', ACR_BASE === 'urn:pkauth:acr:passkey' && ACR_STEPUP === 'urn:pkauth:acr:stepup');
const ainews = getClient({ RP_ID: 'id.example.com' }, 'ainews');
check('ainews redirect_uri 是 /_pkauth/callback', ainews && ainews.redirectUris.length === 1 && ainews.redirectUris[0] === 'https://ainews.example.com/_pkauth/callback');
check('otp / single 不签发 refresh，普通账户可以', allowsRefresh({ once: 'otp' }) === false && allowsRefresh({ once: 'single' }) === false && allowsRefresh(null) === true && allowsRefresh({ ax: 1 }) === true);
check('feature_required 且没有权益时拒绝', clientAccessDenied({ access: 'feature_required' }, []) === true && clientAccessDenied({ access: 'feature_required' }, ['ainews:feeds.read']) === false && clientAccessDenied({}, []) === false);
check('refresh 宽限默认 30 秒，本地可覆盖为 0', refreshGraceMs({}) === 30000 && refreshGraceMs({ RP_ID: 'localhost', OIDC_REFRESH_GRACE_MS: '0' }) === 0);

function memoryDb() {
  const rows = new Map();
  const id = (tenant, k) => `${tenant}\0${k}`;
  function exec(sql, args) {
    if (sql === SQL.upsert || sql.startsWith('INSERT')) {
      const [tenant, k, v, expiration, metadata] = args;
      rows.set(id(tenant, k), { v, expiration, metadata, k });
      return { success: true };
    }
    if (sql === SQL.consume) {
      const [tenant, k] = args;
      const row = rows.get(id(tenant, k));
      if (!row) return null;
      rows.delete(id(tenant, k));
      return row;
    }
    if (sql === SQL.del || sql.startsWith('DELETE')) {
      const [tenant, k] = args;
      rows.delete(id(tenant, k));
      return { success: true };
    }
    if (sql === SQL.get || sql.startsWith('SELECT v')) {
      const [tenant, k] = args;
      return rows.get(id(tenant, k)) || null;
    }
    if (sql === SQL.list || sql.startsWith('SELECT k')) {
      const [tenant, start, end, limit] = args;
      const results = [];
      for (const row of [...rows.values()].sort((a, b) => a.k < b.k ? -1 : 1)) {
        const key = [...rows.entries()].find(([, v]) => v === row)?.[0] || '';
        const tenantId = key.split('\0')[0];
        if (tenantId !== tenant || row.k < start || row.k >= end) continue;
        results.push(row);
        if (results.length >= limit) break;
      }
      return results;
    }
    throw new Error('unexpected sql');
  }
  return {
    rows,
    prepare(sql) {
      return { bind(...args) {
        return {
          run: async () => exec(sql, args),
          first: async () => exec(sql, args),
          all: async () => ({ results: exec(sql, args) || [] }),
        };
      } };
    },
  };
}

const db = memoryDb();
const hash = 'ab'.repeat(32);
await db.prepare(SQL.upsert).bind('default', `inv:${hash}`, JSON.stringify({ id: 'abcd', u: 'ada', x: Date.now() + 60000 }), null, null).run();
const pair = await Promise.all([consumeInvite({ DB: db }, hash), consumeInvite({ DB: db }, hash)]);
check('D1 邀请并发消费只成功一次', pair.filter(Boolean).length === 1 && pair.filter(Boolean)[0].u === 'ada');
check('消费 SQL 是单条 DELETE RETURNING', SQL.consume.includes('DELETE') && SQL.consume.includes('RETURNING') && D1_PREFIXES.includes('inv:') && D1_PREFIXES.includes('user:') && D1_PREFIXES.includes('cred:') && D1_PREFIXES.includes('role:'));

const kvStore = new Map([
  ['user:ada', JSON.stringify({ username: 'ada', userID: 'uid-ada' })],
  ['cred:c1', 'ada'],
  ['role:ada', 'inviter'],
  ['inv:ff', JSON.stringify({ id: 'ff' })],
]);
const kv = {
  async get(k) { return kvStore.has(k) ? kvStore.get(k) : null; },
  async list({ prefix, cursor }) {
    const keys = [...kvStore.keys()].filter((k) => k.startsWith(prefix) && (!cursor || k > cursor)).sort();
    return { keys: keys.map((name) => ({ name, metadata: { name } })), list_complete: true };
  },
};
const db2 = memoryDb();
const migrated = await migrateKvToD1(kv, db2);
check('KV → D1 迁移复制用户、凭据、角色、邀请', migrated.copied === 4);
const env = { DB: db2, KV: { get: async () => 'kv-value' } };
const attached = attachStore(env);
check('绑定 D1 后用户记录走 D1，其它键仍走 KV', (await attached.KV.get('user:ada', 'json')).userID === 'uid-ada' && await attached.KV.get('cfg:session_preset') === 'kv-value');

const quota = { n: 1, async takeQuota() { if (this.n <= 0) return false; this.n -= 1; return true; } };
check('otp 额度在 authorize 路径原子扣减：第二次失败', await takeOtpQuota(quota, 'ada', { once: 'otp' }) === true && await takeOtpQuota(quota, 'ada', { once: 'otp' }) === false);
check('非 otp 不扣额度', await takeOtpQuota(quota, 'ada', null) === true);

const mem = new Map();
const state = {
  async issue(k, _ttl, data) { mem.set(k, data); },
  async consume(k) { const data = mem.get(k); if (!data) return null; mem.delete(k); return { data }; },
};
const migEnv = { CHAL_HMAC_KEY: 'test-hmac-key', RP_ID: 'localhost', ORIGIN: 'http://localhost:8787' };
const t0 = Date.now();
const issued = await issueMigrationTicket(migEnv, state, { userID: 'uid-ada', username: 'ada', sid: 's1' }, t0);
check('迁移票据指向新站或本地源，且带 ticket 片段', issued.url.startsWith('http://localhost:8787/migrate#ticket=') && migrationRedirect({ RP_ID: 'id.example.com' }, 'x') === 'https://id.example.com/migrate#ticket=x');
const again = await Promise.all([
  redeemMigrationTicket(migEnv, state, issued.ticket, t0 + 1000),
  redeemMigrationTicket(migEnv, state, issued.ticket, t0 + 1000),
]);
check('迁移票据一次性，只能绑定原 userID', again.filter(Boolean).length === 1 && again.find(Boolean).userID === 'uid-ada');
const late = await issueMigrationTicket(migEnv, state, { userID: 'uid-ada', username: 'ada' }, t0);
check('迁移票据 5 分钟后过期', TICKET_TTL_MS === 300000 && await redeemMigrationTicket(migEnv, state, late.ticket, t0 + TICKET_TTL_MS + 1) === null);
const pending = { userID: 'uid-ada', username: 'ada' };
check('迁移登记只接受同一个 userID', migrationRegisterPlan({ pending, user: { username: 'ada', userID: 'uid-ada' } }).kind === 'add-passkey' && migrationRegisterPlan({ pending, user: { username: 'ada', userID: 'other' } }).kind === 'reject');

const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const jwk = { ...(await crypto.subtle.exportKey('jwk', kp.privateKey)), kid: 'unit-k' };
const signing = JSON.stringify(jwk);
await importSigningKey(signing);
const codes = new Map();
const sessions = new Map([['sid-1', { username: 'ada', absAt: Date.now() + 3600000 }]]);
let expired = false;
let expiry = null;
const fakeState = {
  async issue(k, _ttl, data) { codes.set(k, data); },
  async consume(k) { const data = codes.get(k); if (!data) return null; codes.delete(k); return { data }; },
  async sessGet(sid) { return sessions.get(sid) || null; },
  async takeQuota(key) { const n = codes.get(key) ?? 0; if (!(n > 0)) return false; codes.set(key, n - 1); return true; },
  async rtIssue() {},
  async rtPeek() { return { status: 'current', grant: { cid: 'demo-rp-local', username: 'ada', sid: 'sid-1', scope: 'openid offline_access', authTime: 1, acr: ACR_BASE, refreshOk: true }, fam: 'f', exp: Date.now() + 1000 }; },
  async rtCommit() { return { status: 'invalid' }; },
  async rtRevokeFamily() { sessions.delete('sid-1'); },
};
codes.set('otp:ada', 1);
const handle = makeOidc({
  json: (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } }),
  getSession: async () => ({ sid: 'sid-1', username: 'ada', uvAt: Date.now(), risk: null }),
  getUser: async () => ({ username: 'ada', userID: 'uid-ada' }),
  accountExpired: async () => expired,
  getRole: async () => null,
  getExpiry: async () => expiry,
  stateStub: () => fakeState,
  stepUpWindow: () => 300000,
  audit: async () => {},
  securityHeaders: {},
});
const rl = { limit: async () => ({ success: true }) };
const idpEnv = { ORIGIN: 'http://localhost:8787', RP_ID: 'localhost', OIDC_SIGNING_KEY: signing, RL_OPTIONS: rl, RL_VERIFY: rl };
const authUrl = new URL('http://localhost:8787/oauth/authorize?response_type=code&client_id=demo-rp-local&redirect_uri=http://localhost:8788/callback&scope=openid%20offline_access&state=state-value-1&nonce=n1&code_challenge_method=S256&code_challenge=' + 'a'.repeat(43));
expiry = { once: 'otp' };
const first = await handle(idpEnv, new Request(authUrl), authUrl);
const loc = new URL(first.headers.get('location'));
check('otp 账户 authorize 成功一次', first.status === 302 && loc.searchParams.get('code'));
const second = await handle(idpEnv, new Request(authUrl), authUrl);
const loc2 = new URL(second.headers.get('location'));
check('otp 额度用完后 authorize 返回 access_denied', loc2.searchParams.get('error') === 'access_denied');
expiry = { once: 'single' };
codes.set('otp:ada', 1);
const single = await handle(idpEnv, new Request(authUrl), authUrl);
check('single 账户可以签发授权码', single.status === 302 && new URL(single.headers.get('location')).searchParams.get('code'));

expired = true;
const tokenReq = new Request('http://localhost:8787/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=refresh_token&client_id=demo-rp-local&refresh_token=' + 'b'.repeat(43) });
const refused = await handle(idpEnv, tokenReq, new URL(tokenReq.url));
const refusedBody = await refused.json();
check('过期账户在 refresh 阶段被拒', refused.status === 400 && refusedBody.error === 'invalid_grant');

const f = R.filter((x) => !x).length;
console.log(`结果：${R.length - f}/${R.length} 通过`);
process.exit(f ? 1 : 0);
