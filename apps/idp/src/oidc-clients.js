// OIDC 静态客户端登记（Phase 1 不做动态注册）。全部是公共客户端：无 client_secret，强制 PKCE S256。
// 生产域名是 example.com 占位，接入前由负责人替换为真实值（见 docs/oidc-integration.md）。
// ent：access token 里的短期粗粒度权益提示，按账户档位给出；写操作由资源方在服务端再查。
const PROD = {
  ainews: {
    name: 'ainews',
    redirectUris: ['https://ainews.example.com/_pkauth/callback'],
    audiences: ['https://ainews.example.com/api'],
    scopes: ['openid', 'profile', 'offline_access'],
    ent: { member: ['ainews:feeds.read'], staff: ['ainews:feeds.read', 'ainews:feeds.write'] },
    // 没有该应用任何权益时，authorize 直接 access_denied（D9 / §9.1 默认 feature_required）。
    access: 'feature_required',
  },
};
// 本地测试专用（只在 RP_ID=localhost 时存在）：A 有两个资源，B 用来验证多应用 aud 隔离
const LOCAL = {
  'demo-rp-local': {
    name: '本地示例 RP',
    redirectUris: ['http://localhost:8788/callback'],
    audiences: ['http://localhost:8788/api', 'http://localhost:8789/api'],
    scopes: ['openid', 'profile', 'offline_access'],
    ent: { member: ['demo:read'], staff: ['demo:read', 'demo:write'] },
  },
  'demo-rp-local-b': {
    name: '本地示例 RP B',
    redirectUris: ['http://localhost:8798/callback'],
    audiences: ['http://localhost:8798/api'],
    scopes: ['openid', 'offline_access'],
    ent: { member: ['b:read'], staff: ['b:read'] },
  },
};
export function getClient(env, id) {
  if (typeof id !== 'string') return null;
  if (Object.hasOwn(PROD, id)) return PROD[id];
  if (env.RP_ID === 'localhost' && Object.hasOwn(LOCAL, id)) return LOCAL[id];
  return null;
}
