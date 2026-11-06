// 最小示例 relying party（RP）：用 oauth4webapi 接入 passkey-demo 的 OIDC（授权码 + PKCE S256，公共客户端）。
// 仅供本地演示：node examples/relying-party.mjs（先在另一个终端 npx wrangler dev --port 8787，.dev.vars 需含 OIDC_SIGNING_KEY）
// 浏览器打开 http://localhost:8788/ → 跳到 IdP 登录 → 回调后显示 id_token 里的 sub / acr / auth_time，并演示用 JWKS 本地校验 access token。
// 生产 RP（如 ainews）：会话存服务端、cookie 设 HttpOnly+Secure，refresh token 只存服务端；见 docs/oidc-integration.md。
import { createServer } from 'node:http';
import { createPublicKey, verify } from 'node:crypto';
import * as oauth from 'oauth4webapi';

const ISSUER = new URL(process.env.OIDC_ISSUER || 'http://localhost:8787');
const PORT = 8788;
const client = { client_id: 'demo-rp-local', id_token_signed_response_alg: 'ES256' };
const REDIRECT = `http://localhost:${PORT}/callback`;
const RESOURCE = `http://localhost:${PORT}/api`;
const insecure = ISSUER.protocol === 'http:' ? { [oauth.allowInsecureRequests]: true } : {}; // 只允许本地 http

const as = await oauth.processDiscoveryResponse(ISSUER, await oauth.discoveryRequest(ISSUER, insecure));
const pending = new Map(); // state → { verifier, nonce }（演示用内存；生产放服务端会话）

// 资源方校验：签名（JWKS）、typ、iss、aud、exp；ent 只作提示，写操作仍需服务端查权限
async function verifyAccessToken(token) {
  const keys = (await (await fetch(as.jwks_uri)).json()).keys;
  const [h, p, s] = token.split('.');
  const hdr = JSON.parse(Buffer.from(h, 'base64url'));
  const jwk = keys.find((k) => k.kid === hdr.kid);
  if (hdr.alg !== 'ES256' || hdr.typ !== 'at+jwt' || !jwk) throw new Error('bad header');
  if (!verify('sha256', Buffer.from(`${h}.${p}`), { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url'))) throw new Error('bad signature');
  const c = JSON.parse(Buffer.from(p, 'base64url'));
  if (c.iss !== as.issuer || !c.aud.includes(RESOURCE) || c.exp < Date.now() / 1000) throw new Error('bad claims');
  return c;
}

const esc = (v) => String(v).replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  try {
    if (url.pathname === '/') {
      const verifier = oauth.generateRandomCodeVerifier(), state = oauth.generateRandomState(), nonce = oauth.generateRandomNonce();
      pending.set(state, { verifier, nonce });
      const u = new URL(as.authorization_endpoint);
      u.search = new URLSearchParams({ client_id: client.client_id, redirect_uri: REDIRECT, response_type: 'code', scope: 'openid profile', state, nonce, code_challenge: await oauth.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' });
      if (url.searchParams.get('stepup')) u.searchParams.set('acr_values', 'urn:pkauth:acr:stepup'); // 敏感操作前要求 step-up
      res.writeHead(302, { Location: u.toString() }).end();
      return;
    }
    if (url.pathname === '/callback') {
      const p = pending.get(url.searchParams.get('state'));
      if (!p) throw new Error('unknown state');
      pending.delete(url.searchParams.get('state'));
      const params = oauth.validateAuthResponse(as, client, url, url.searchParams.get('state')); // 同时校验 iss（RFC 9207）
      const tokens = await oauth.processAuthorizationCodeResponse(as, client, await oauth.authorizationCodeGrantRequest(as, client, oauth.None(), params, REDIRECT, p.verifier, insecure), { expectedNonce: p.nonce, requireIdToken: true });
      const id = oauth.getValidatedIdTokenClaims(tokens);
      const at = await verifyAccessToken(tokens.access_token);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end(`<p>sub=${esc(id.sub)}</p><p>acr=${esc(id.acr)} auth_time=${esc(new Date(id.auth_time * 1000).toISOString())}</p><p>ent=${esc(at.ent.join(','))}</p><p><a href="/?stepup=1">要求 step-up 后再登录</a></p>`);
      return;
    }
    res.writeHead(404).end();
  } catch (e) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' }).end(`登录失败：${e.message}`);
  }
}).listen(PORT, '127.0.0.1', () => console.log(`示例 RP：http://localhost:${PORT}/`));
