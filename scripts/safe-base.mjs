// 发送管理 token 前校验目标：只允许 https，或本机回环地址上的 http（本地 wrangler dev）。
// 防止把从本地文件读出的 Bearer token 以明文发给非本机的 http 地址。
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
export function assertSafeBase(base) {
  const u = new URL(base);
  if (u.protocol === 'https:') return u.origin;
  if (u.protocol === 'http:' && LOOPBACK.has(u.hostname)) return u.origin;
  throw new Error('拒绝发送管理 token：目标必须是 https，或本机 localhost 上的 http');
}
