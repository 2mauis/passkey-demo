# 用 passkey-demo 登录：OIDC 接入说明（Phase 1）

规格见 [specs/oidc-phase1.md](specs/oidc-phase1.md)。本页给接入方（第一个是 ainews 订阅源编辑窗口）看。所有域名都是 example.com 占位。

## 端点
| 用途 | 地址 |
|---|---|
| discovery | `https://idp.example.com/.well-known/openid-configuration` |
| JWKS | `/oauth/jwks`（ES256，缓存 5 分钟；轮换期间同时有两把公钥） |
| 授权 | `GET /oauth/authorize`（只支持 `response_type=code`，必须 PKCE S256，必须 `state`） |
| 令牌 | `POST /oauth/token`（`application/x-www-form-urlencoded`，公共客户端：只带 `client_id`，无 secret） |
| userinfo | `GET /oauth/userinfo`（`Authorization: Bearer <access_token>`） |

## ainews 的登记（`src/oidc-clients.js`）
- `client_id`：`ainews`
- `redirect_uri`：`https://ainews.example.com/_pkauth/callback`（逐字匹配：协议、主机大小写、路径、尾斜杠、查询串都必须一致）
- 资源（access token 的 `aud`）：`https://ainews.example.com/api`
- scope：`openid`、`profile`（返回 `preferred_username`）、`offline_access`（返回 refresh token）
- `ent`：普通成员 `["feeds:read"]`；负责人 / 有管理角色 `["feeds:read","feeds:write"]`

换成真实域名：只改 `src/oidc-clients.js` 的这一项并走 PR；不在 IdP 侧开放动态注册。

## ainews 需要做的（不改本仓库）
0. token 端点不提供 CORS：换 token / 刷新只能由 RP 服务端调用，不支持纯浏览器 SPA。
1. 用成熟的 OIDC 库（Node 推荐 `oauth4webapi`，示例见 [`examples/relying-party.mjs`](../examples/relying-party.mjs)）；每次登录生成新的 `state`、`nonce`、`code_verifier`，存服务端会话。
2. 回调时校验 `state` 和 `iss`（RFC 9207，库默认会做），再用 `code` + `code_verifier` 换 token；校验 id_token 的签名、`iss`、`aud`=`ainews`、`exp`、`nonce`。
3. 用 `sub`（随机且稳定的账户 ID）做本地用户主键，不要用用户名。
4. API 端（资源方）校验 access token：JWKS 验签、`typ`=`at+jwt`、`iss`、`aud` 含 `https://ainews.example.com/api`、`exp`。
5. **`ent` 只是提示**：界面可以按它显示 / 隐藏编辑按钮；真正的写操作必须在服务端再判断权限（Phase 2 提供查询接口前，先以 ainews 自己的配置为准）。
6. 敏感操作（例如删除订阅源）前，重新发起授权并带 `acr_values=urn:pkauth:acr:stepup`（或 `max_age=300`）；回来后检查 id_token 的 `acr` 与 `auth_time`。
7. refresh token 只存服务端；每次刷新都会换新，**旧的再用一次会让整个系列失效**（用户需要重新登录）。并发刷新要串行化。
8. 用户在 IdP 退出登录、被改角色、删除 passkey 或账户过期后，refresh 立即失效；已签发的 access token 最多还能用 10 分钟。

## 错误
- client_id 或 redirect_uri 未登记：IdP 显示 400，不会跳回 RP。
- 其他授权错误按 OAuth 规范跳回 `redirect_uri?error=…&state=…&iss=…`：`invalid_request`（缺 PKCE / state）、`invalid_scope`、`login_required` / `interaction_required`（`prompt=none` 时）。
- token 端点：`invalid_grant`（code 用过 / 过期 / verifier 不对 / refresh 失效）、`invalid_client`。
- 未配置签名密钥：所有 OIDC 端点 503。

## 运维（负责人操作；本 PR 不执行）
- 生成密钥：`node scripts/oidc-keygen.mjs /path/outside-repo/oidc.env`（文件 0600、不打印私钥），取出 `OIDC_SIGNING_KEY` 的值后 `npx wrangler secret put OIDC_SIGNING_KEY`，然后删除该文件。
- 轮换：把旧 key 的公钥部分（`kty/crv/x/y/kid`）设为 `OIDC_SIGNING_KEY_PREV_PUBLIC`，再换 `OIDC_SIGNING_KEY`；10 分钟后删除 PREV。
- 紧急停用：`npx wrangler secret delete OIDC_SIGNING_KEY` → OIDC 全部 503，普通 passkey 登录不受影响。
