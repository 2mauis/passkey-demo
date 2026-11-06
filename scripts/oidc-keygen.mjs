// 生成 OIDC ES256 签名私钥（JWK，带随机 kid），写进指定的 dotenv 文件（默认 .dev.vars）的 OIDC_SIGNING_KEY 行。
// 不打印密钥；文件权限 0600。
// 生产：生成到临时文件后 `npx wrangler secret put OIDC_SIGNING_KEY`（从文件读入），并立即删除文件；见 docs/oidc-integration.md。
// 用法：node scripts/oidc-keygen.mjs [文件路径]
import { webcrypto, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';

const file = process.argv[2] || '.dev.vars';
const kp = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const { kty, crv, x, y, d } = await webcrypto.subtle.exportKey('jwk', kp.privateKey);
const kid = `k-${new Date().toISOString().slice(0, 10)}-${randomBytes(4).toString('hex')}`;
const line = `OIDC_SIGNING_KEY='${JSON.stringify({ kty, crv, x, y, d, kid })}'`;
let body = existsSync(file) ? readFileSync(file, 'utf8') : '';
body = /^OIDC_SIGNING_KEY=.*$/m.test(body) ? body.replace(/^OIDC_SIGNING_KEY=.*$/m, () => line) : `${body.replace(/\n?$/, '\n')}${line}\n`;
writeFileSync(file, body, { mode: 0o600 });
chmodSync(file, 0o600);
console.log(`已写入 ${file} 的 OIDC_SIGNING_KEY（kid=${kid}，私钥未输出）`);
