// Durable Object AuthState 单元测试（Node 内存模拟 storage，不需要 wrangler）
// 用法：node tests/state-unit.mjs
import { register } from 'node:module';
register('data:text/javascript,' + encodeURIComponent(`
export async function resolve(s, c, n) { return s === 'cloudflare:workers' ? { url: 'data:text/javascript,export class DurableObject{constructor(ctx,env){this.ctx=ctx;this.env=env}}', shortCircuit: true } : n(s, c); }`));
const { AuthState, SESS_CAP } = await import('../src/state.js');
const R = []; const check = (n, ok, d = '') => { R.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${d ? '  — ' + d : ''}`); };
function mockStorage() {
  const m = new Map(); let alarm = null;
  return { m, get alarm() { return alarm; },
    async get(k) { return m.get(k); }, async put(k, v) { m.set(k, structuredClone(v)); },
    async delete(k) { if (Array.isArray(k)) { let n = 0; for (const x of k) n += m.delete(x) ? 1 : 0; return n; } return m.delete(k); },
    async list({ prefix = '', start, limit = Infinity } = {}) { const out = new Map(); for (const k of [...m.keys()].sort()) { if (!k.startsWith(prefix) || (start && k < start)) continue; out.set(k, m.get(k)); if (out.size >= limit) break; } return out; },
    async getAlarm() { return alarm; }, async setAlarm(t) { alarm = t; } };
}
const st = mockStorage(); const s = new AuthState({ storage: st }, {});
const rec = { username: 'u1', createdAt: 0, lastSeen: 0, absAt: 0 };
for (let i = 0; i <= SESS_CAP; i++) await s.sessCreate('sid' + i, rec, 3600e3);
check(`会话超过上限 ${SESS_CAP}：被挤出索引的最旧会话同时删除`, (await s.sessGet('sid0')) === null && (await s.sessGet('sid1')) !== null);
const n = await s.sessRevokeUser('u1');
let alive = 0; for (let i = 0; i <= SESS_CAP; i++) if (await s.sessGet('sid' + i)) alive++;
check('超过上限后吊销用户：没有任何存活会话', alive === 0 && n === SESS_CAP, `吊销 ${n}，存活 ${alive}`);
check('写入带 exp 的记录时排期清理 alarm', typeof st.alarm === 'number');
await s.issue('chal:old', 1); await s.issue('chal:new', 3600e3); await s.envPut('u2', { c: 'TW' }, 1);
await s.sessCreate('sx', { ...rec, username: 'u3' }, 1);
await new Promise((r) => setTimeout(r, 5));
await s.alarm();
check('alarm 删除放弃的过期 challenge，保留未过期的', !st.m.has('chal:old') && st.m.has('chal:new'));
check('alarm 删除过期环境历史与过期会话，并清理空的用户索引', !st.m.has('env:u2') && !st.m.has('s:sx') && !st.m.has('us:u3'));
check('仍有未过期记录时 alarm 继续排期', typeof st.alarm === 'number');
const ok = R.filter(Boolean).length; console.log(`\n结果：${ok}/${R.length} 通过`); process.exitCode = ok === R.length ? 0 : 1;
