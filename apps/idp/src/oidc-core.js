// OIDC 纯函数里和 JWT / PKCE 有关的部分在 @pkauth/core（WebCrypto，无运行时依赖）。
// 这里只保留 IdP 自己的 redirect / continue 规则。Worker 与 Node 测试共用。
export {
  b64u, unb64u, sha256b64u, pkceS256, randomToken, publicJwk, importSigningKey, signJwt, verifyJwt,
} from '@pkauth/core';

export const redirectAllowed = (client, uri) => typeof uri === 'string' && client.redirectUris.includes(uri);

// 登录后回跳 authorize 的路径：只接受同源 /oauth/authorize?…，不接受 .. 和反斜杠
export function safeContinue(value, origin) {
  if (typeof value !== 'string' || !value.startsWith('/oauth/authorize?') || value.length > 4096) return null;
  const path = value.split('?')[0];
  if (path.includes('\\')) return null;
  if (path.split('/').some((seg) => seg === '.' || seg === '..')) return null;
  try {
    const u = new URL(value, origin);
    if (u.origin !== new URL(origin).origin || u.pathname !== '/oauth/authorize') return null;
  } catch { return null; }
  return value;
}
