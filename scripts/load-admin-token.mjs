// 读取管理 token，并且只在目标地址已经证明可以发送之后才打开文件。
// 允许的目标：https，或本机回环上的 http（localhost / 127.0.0.1 / [::1]）。见 safe-base.mjs。
// 文件只 open 一次，用 readSync 读进单独分配的 Buffer；返回值只有通过服务端 Bearer 形状校验的 token，
// 不会把 dotenv 里的其它行（签名私钥、HMAC 密钥等）交出去。
import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { assertSafeBase } from './safe-base.mjs';

const MAX = 1024 * 1024;
const TOKEN_RE = /^[\x21-\x7e]{32,512}$/;

function readTextViaFd(file) {
  // 与 scripts/invite.mjs 相同：先 open，再对这个 fd 做 fstat 和读取。符号链接只在 open 时解析一次。
  const fd = openSync(file, 'r');
  try {
    const size = fstatSync(fd).size;
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX) throw new Error('token 文件过大');
    if (size === 0) return '';
    const buf = Buffer.alloc(size);
    const n = readSync(fd, buf, 0, size, 0);
    if (n !== size) throw new Error('token 文件读取不完整');
    return buf.toString('utf8');
  } finally {
    closeSync(fd);
  }
}

function adminTokenLine(text) {
  const m = /^ADMIN_TOKEN=(.+)$/m.exec(text);
  if (!m) throw new Error('缺少 ADMIN_TOKEN');
  return m[1].trim();
}

// opts.dotenv：文件是 dotenv（取 ADMIN_TOKEN 行）；否则整个文件就是 token（.admin-token）。
export function loadAdminToken(base, file, opts = {}) {
  assertSafeBase(base);
  const token = opts.dotenv ? adminTokenLine(readTextViaFd(file)) : readTextViaFd(file).trim();
  if (!TOKEN_RE.test(token)) throw new Error('管理 token 无效');
  return token;
}
