// 生成 OIDC ES256 签名私钥（JWK，带随机 kid），写进指定的 dotenv 文件（默认 .dev.vars）的 OIDC_SIGNING_KEY 行。
// 不打印密钥；文件权限 0600。
// 只 open 一次（O_RDWR|O_CREAT|O_NOFOLLOW）。之后的 fstat、读、截断、写、fchmod 都作用在同一个 fd 上，
// 不再按路径做 exists → read → write。路径的最后一段若是符号链接则直接失败，避免把私钥写到被调包的目标。
// 生产：生成到临时文件后 `npx wrangler secret put OIDC_SIGNING_KEY`（从文件读入），并立即删除文件；见 docs/oidc-integration.md。
// 用法：node scripts/oidc-keygen.mjs [文件路径]
import { webcrypto, randomBytes } from 'node:crypto';
import { closeSync, constants, fchmodSync, fstatSync, ftruncateSync, openSync, readSync, writeSync } from 'node:fs';

const file = process.argv[2] || '.dev.vars';
const MAX = 1024 * 1024;
const kp = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const { kty, crv, x, y, d } = await webcrypto.subtle.exportKey('jwk', kp.privateKey);
const kid = `k-${new Date().toISOString().slice(0, 10)}-${randomBytes(4).toString('hex')}`;
const line = `OIDC_SIGNING_KEY='${JSON.stringify({ kty, crv, x, y, d, kid })}'`;

if (!constants.O_NOFOLLOW) throw new Error('当前平台没有 O_NOFOLLOW，拒绝按路径写私钥');
const fd = openSync(file, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
try {
  const size = fstatSync(fd).size;
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX) throw new Error('dotenv 文件过大');
  let body = '';
  if (size > 0) {
    const buf = Buffer.alloc(size);
    const n = readSync(fd, buf, 0, size, 0);
    if (n !== size) throw new Error('dotenv 文件读取不完整');
    body = buf.toString('utf8');
  }
  body = /^OIDC_SIGNING_KEY=.*$/m.test(body) ? body.replace(/^OIDC_SIGNING_KEY=.*$/m, () => line) : `${body.replace(/\n?$/, '\n')}${line}\n`;
  const out = Buffer.from(body, 'utf8');
  ftruncateSync(fd, 0);
  let off = 0;
  while (off < out.length) {
    const n = writeSync(fd, out, off, out.length - off, off);
    if (n <= 0) throw new Error('dotenv 文件写入失败');
    off += n;
  }
  fchmodSync(fd, 0o600);
} finally {
  closeSync(fd);
}
console.log(`已写入 ${file} 的 OIDC_SIGNING_KEY（kid=${kid}，私钥未输出）`);
