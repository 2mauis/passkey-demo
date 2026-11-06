// 强一致状态：Durable Object（单实例 "global"）。
// 用途：一次性 challenge 的原子消费、一次性凭据（恢复码 / OTP）的原子消费与失败计数、服务端会话表（按用户吊销）、登录环境历史。
// KV 是最终一致的（跨地区最长约 60 秒），不能保证“只用一次”或精确计数，所以这些状态放在这里。
// 每个 RPC 方法内部只做本对象存储读写、没有外部 I/O：在 DO 的输入门（input gate）保护下，单次调用内的 读-改-写 是原子的。
// 过期清理：读取时惰性判断 + 每个 key 自带 exp；写入带 exp 的记录时确保有 alarm，alarm 分页扫描删除过期记录（防止放弃的 challenge、过期会话、旧环境历史无限累积）。
import { DurableObject } from 'cloudflare:workers';

export const SWEEP_MS = 10 * 60e3;
export const SESS_CAP = 50;

export class AuthState extends DurableObject {
  async _put(key, v) {
    await this.ctx.storage.put(key, v);
    if (typeof v.exp === 'number' && (await this.ctx.storage.getAlarm()) == null) await this.ctx.storage.setAlarm(Date.now() + SWEEP_MS);
  }
  // 定时清理：删除所有已过期记录；用户会话索引里去掉已不存在的 sid；仍有带 exp 的记录则继续排期
  async alarm() {
    const now = Date.now();
    let pending = false, start;
    for (;;) {
      const page = await this.ctx.storage.list({ start, limit: 512 });
      if (!page.size) break;
      const dead = [];
      for (const [k, v] of page) {
        if (v && typeof v.exp === 'number') { if (now > v.exp) dead.push(k); else pending = true; }
      }
      if (dead.length) await this.ctx.storage.delete(dead);
      const last = [...page.keys()].pop();
      if (page.size < 512) break;
      start = last + '\0';
    }
    const idx = await this.ctx.storage.list({ prefix: 'us:' });
    for (const [k, v] of idx) {
      const live = [];
      for (const sid of v.data) if (await this.ctx.storage.get(`s:${sid}`)) live.push(sid);
      if (!live.length) await this.ctx.storage.delete(k); else if (live.length !== v.data.length) await this.ctx.storage.put(k, { data: live });
    }
    if (pending) await this.ctx.storage.setAlarm(now + SWEEP_MS);
  }
  async _get(key, now) {
    const v = await this.ctx.storage.get(key);
    if (v && typeof v.exp === 'number' && now > v.exp) { await this.ctx.storage.delete(key); return undefined; }
    return v;
  }
  // ---- 一次性记号：put 一次，consume 一次（原子取出并删除）----
  async issue(key, ttlMs, data = null) {
    await this._put(key, { exp: Date.now() + ttlMs, data });
  }
  async consume(key) {
    const v = await this._get(key, Date.now());
    if (!v) return null;
    await this.ctx.storage.delete(key);
    return { data: v.data };
  }
  async peek(key) {
    const v = await this._get(key, Date.now());
    return v ? v.data : null;
  }
  async remove(key) { await this.ctx.storage.delete(key); }
  // ---- 计数（原子 +1，带窗口过期）----
  async incr(key, ttlMs) {
    const now = Date.now();
    const v = await this._get(key, now);
    const n = (v ? v.data : 0) + 1;
    await this._put(key, { exp: v ? v.exp : now + ttlMs, data: n });
    return n;
  }
  // ---- 一次性登录额度（OTP）：原子扣减，成功返回 true ----
  async takeQuota(key) {
    const v = await this._get(key, Date.now());
    if (!v || !(v.data > 0)) return false;
    await this.ctx.storage.put(key, { ...v, data: v.data - 1 });
    return true;
  }
  async setQuota(key, n, ttlMs) { await this._put(key, { exp: Date.now() + ttlMs, data: n }); }

  // ---- 会话表 ----
  // s:<sid> = { exp, data: { username, createdAt, lastSeen, absAt, uvAt, risk } }；us:<username> = { data: [sid...] }
  async sessCreate(sid, rec, maxMs) {
    await this._put(`s:${sid}`, { exp: Date.now() + maxMs, data: rec });
    const idx = (await this.ctx.storage.get(`us:${rec.username}`)) || { data: [] };
    const live = [];
    for (const x of idx.data) if (await this._get(`s:${x}`, Date.now())) live.push(x);
    live.push(sid);
    // 超过上限：被挤出索引的最旧会话同时删除，保证 sessRevokeUser 能吊销该用户的每一个存活会话
    const evicted = live.length > SESS_CAP ? live.splice(0, live.length - SESS_CAP) : [];
    if (evicted.length) await this.ctx.storage.delete(evicted.map((x) => `s:${x}`));
    await this.ctx.storage.put(`us:${rec.username}`, { data: live });
  }
  async sessGet(sid) {
    const v = await this._get(`s:${sid}`, Date.now());
    return v ? v.data : null;
  }
  async sessUpdate(sid, patch) {
    const v = await this._get(`s:${sid}`, Date.now());
    if (!v) return null;
    v.data = { ...v.data, ...patch };
    await this.ctx.storage.put(`s:${sid}`, v);
    return v.data;
  }
  async sessDelete(sid) { await this.ctx.storage.delete(`s:${sid}`); }
  // 吊销某用户全部会话（改角色、删 passkey、恢复、风险事件），返回吊销数量
  async sessRevokeUser(username) {
    const idx = await this.ctx.storage.get(`us:${username}`);
    if (!idx) return 0;
    let n = 0;
    for (const sid of idx.data) { if (await this.ctx.storage.get(`s:${sid}`)) n++; await this.ctx.storage.delete(`s:${sid}`); }
    await this.ctx.storage.delete(`us:${username}`);
    return n;
  }

  // ---- OIDC refresh token 系列 ----
  // rt:<hash> = { exp, data: { fam } }；rf:<fam> = { exp, data: { cur, prev, rotatedAt, revoked, grant, replay } }
  // replay 只在轮换后的宽限窗口内保存刚刚签发的 token 响应，供并发重放返回同一份（D6）。不写日志。
  async rtIssue(hash, fam, grant, ttlMs) {
    const exp = Date.now() + ttlMs;
    await this._put(`rf:${fam}`, { exp, data: { cur: hash, revoked: false, grant } });
    await this._put(`rt:${hash}`, { exp, data: { fam } });
  }
  async rtPeek(oldHash, graceMs = 30000, now = Date.now()) {
    const t = await this._get(`rt:${oldHash}`, now);
    if (!t) return { status: 'invalid' };
    const f = await this._get(`rf:${t.data.fam}`, now);
    if (!f || f.data.revoked) return { status: 'invalid' };
    if (f.data.cur === oldHash) return { status: 'current', grant: f.data.grant, fam: t.data.fam, exp: f.exp };
    if (graceMs > 0 && f.data.prev === oldHash && f.data.replay && now <= f.data.rotatedAt + graceMs) {
      return { status: 'grace', replay: f.data.replay, fam: t.data.fam };
    }
    return { status: 'stale', grant: f.data.grant, fam: t.data.fam };
  }
  async rtCommit(oldHash, newHash, replay, graceMs = 30000, now = Date.now()) {
    const t = await this._get(`rt:${oldHash}`, now);
    if (!t) return { status: 'invalid' };
    const fam = t.data.fam;
    const f = await this._get(`rf:${fam}`, now);
    if (!f || f.data.revoked) return { status: 'invalid' };
    if (f.data.cur !== oldHash) {
      if (graceMs > 0 && f.data.prev === oldHash && f.data.replay && now <= f.data.rotatedAt + graceMs) {
        return { status: 'grace', replay: f.data.replay, fam };
      }
      f.data.revoked = true;
      await this.ctx.storage.put(`rf:${fam}`, f);
      return { status: 'reuse', grant: f.data.grant, fam };
    }
    f.data.prev = oldHash;
    f.data.cur = newHash;
    f.data.rotatedAt = now;
    if (replay) f.data.replay = replay;
    await this.ctx.storage.put(`rf:${fam}`, f);
    await this._put(`rt:${newHash}`, { exp: f.exp, data: { fam } });
    return { status: 'ok', grant: f.data.grant, fam, exp: f.exp, replay };
  }
  async rtRevokeFamily(fam) {
    const f = await this._get(`rf:${fam}`, Date.now());
    if (f) { f.data.revoked = true; await this.ctx.storage.put(`rf:${fam}`, f); }
  }

  // ---- 登录环境历史（只存国家代码、ASN、HMAC 指纹，不存原始 IP）----
  async envGet(username) {
    const v = await this._get(`env:${username}`, Date.now());
    return v ? v.data : null;
  }
  async envPut(username, data, retentionMs) {
    await this._put(`env:${username}`, { exp: Date.now() + retentionMs, data });
  }
}
