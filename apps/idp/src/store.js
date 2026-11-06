// D1 记录层（D4）。未绑定 env.DB 时，调用方继续用 KV，现有测试行为不变。
// 迁到 D1 的前缀：用户、凭据、角色、过期、拒绝、邀请、模板、审计。
export const TENANT = 'default';
export const D1_PREFIXES = ['user:', 'cred:', 'role:', 'exp:', 'deny:', 'inv:', 'tpl:', 'audit:'];

export const SQL = {
  upsert: 'INSERT INTO records (tenant_id, k, v, expiration, metadata) VALUES (?, ?, ?, ?, ?) ON CONFLICT(tenant_id, k) DO UPDATE SET v = excluded.v, expiration = excluded.expiration, metadata = excluded.metadata',
  get: 'SELECT v, expiration, metadata FROM records WHERE tenant_id = ? AND k = ?',
  del: 'DELETE FROM records WHERE tenant_id = ? AND k = ?',
  consume: 'DELETE FROM records WHERE tenant_id = ? AND k = ? RETURNING v, expiration',
  list: 'SELECT k, v, expiration, metadata FROM records WHERE tenant_id = ? AND k >= ? AND k < ? ORDER BY k LIMIT ?',
};

export function isD1Key(key) {
  return typeof key === 'string' && D1_PREFIXES.some((p) => key.startsWith(p));
}

function prefixEnd(prefix) {
  return prefix.slice(0, -1) + String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);
}

function expirationOf(opts) {
  if (!opts) return null;
  if (typeof opts.expiration === 'number') return opts.expiration;
  if (typeof opts.expirationTtl === 'number') return Math.floor(Date.now() / 1000) + opts.expirationTtl;
  return null;
}

function expired(row, nowSec = Math.floor(Date.now() / 1000)) {
  return !!(row && typeof row.expiration === 'number' && row.expiration <= nowSec);
}

export async function d1Put(db, key, value, opts) {
  const metadata = opts && opts.metadata != null ? JSON.stringify(opts.metadata) : null;
  await db.prepare(SQL.upsert).bind(TENANT, key, value == null ? null : String(value), expirationOf(opts), metadata).run();
}

export async function d1Get(db, key, type) {
  const row = await db.prepare(SQL.get).bind(TENANT, key).first();
  if (!row || expired(row)) {
    if (row && expired(row)) await db.prepare(SQL.del).bind(TENANT, key).run();
    return null;
  }
  if (type === 'json' || (type && type.type === 'json')) {
    try { return JSON.parse(row.v); } catch { return null; }
  }
  return row.v;
}

export async function d1Delete(db, key) {
  await db.prepare(SQL.del).bind(TENANT, key).run();
}

export async function d1List(db, { prefix = '', limit = 1000, cursor } = {}) {
  const start = cursor ? `${cursor}\0` : prefix;
  const rows = await db.prepare(SQL.list).bind(TENANT, start, prefixEnd(prefix || '\0'), limit).all();
  const nowSec = Math.floor(Date.now() / 1000);
  const keys = [];
  for (const row of rows.results || []) {
    if (expired(row, nowSec)) continue;
    let metadata;
    if (row.metadata) { try { metadata = JSON.parse(row.metadata); } catch { metadata = undefined; } }
    keys.push({ name: row.k, metadata });
  }
  const last = keys.length ? keys[keys.length - 1].name : undefined;
  return { keys, list_complete: (rows.results || []).length < limit, cursor: last };
}

// 邀请消费：D1 用单条 DELETE … RETURNING，并发只有一个调用能拿到记录（INV-P1.5）。
export async function consumeInvite(env, hash) {
  const key = `inv:${hash}`;
  if (env && env.DB) {
    const row = await env.DB.prepare(SQL.consume).bind(TENANT, key).first();
    if (!row || expired(row)) return null;
    try { return JSON.parse(row.v); } catch { return null; }
  }
  const v = await env.KV.get(key, 'json');
  if (!v) return null;
  await env.KV.delete(key);
  return v;
}

export async function migrateKvToD1(kv, db, prefixes = D1_PREFIXES) {
  let copied = 0;
  for (const prefix of prefixes) {
    let cursor;
    for (;;) {
      const page = await kv.list({ prefix, limit: 1000, cursor });
      for (const item of page.keys || []) {
        const value = await kv.get(item.name);
        await d1Put(db, item.name, value, { metadata: item.metadata });
        copied += 1;
      }
      if (page.list_complete || !page.cursor) break;
      cursor = page.cursor;
    }
  }
  return { copied };
}

export function makeHybrid(db, kv) {
  return {
    __pkauthHybrid: true,
    get: (key, type) => (isD1Key(key) ? d1Get(db, key, type) : kv.get(key, type)),
    put: (key, value, opts) => (isD1Key(key) ? d1Put(db, key, value, opts) : kv.put(key, value, opts)),
    delete: (key) => (isD1Key(key) ? d1Delete(db, key) : kv.delete(key)),
    list: (opts = {}) => (isD1Key(opts.prefix || '') ? d1List(db, opts) : kv.list(opts)),
  };
}

export function attachStore(env) {
  if (!env || !env.DB || (env.KV && env.KV.__pkauthHybrid)) return env;
  const hybrid = makeHybrid(env.DB, env.KV);
  try {
    env.KV = hybrid;
    return env;
  } catch {
    return new Proxy(env, { get(target, prop, receiver) { return prop === 'KV' ? hybrid : Reflect.get(target, prop, receiver); } });
  }
}
