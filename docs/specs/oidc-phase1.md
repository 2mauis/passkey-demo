# OIDC 登录服务 Phase 1（passkey-demo → 通用鉴权组件）

> 依据：调研底稿《passkey-demo 改造为通用鉴权组件：调研评估》（2026-11-05，box 本地，不入库）与其 PoC（9 项检查）。
> PoC 是 Node http server；本实现适配现有 Cloudflare Worker + Durable Object + KV 栈，签名只用 WebCrypto，不新增运行时依赖。

## 背景/目标
把 passkey-demo 扩成小型 OIDC 身份提供方（IdP），让自己写的应用（第一个：ainews 订阅源编辑窗口）复用 passkey 登录，而不是各自实现登录。

需求：
- R1 discovery：`GET /.well-known/openid-configuration`，`issuer` = `ORIGIN`。
- R2 JWKS：`GET /oauth/jwks`，只含公钥；支持轮换期间同时发布上一把公钥。
- R3 授权码 + PKCE：`GET /oauth/authorize` 仅 `response_type=code`，**强制** `code_challenge_method=S256`；回跳带 `iss`（RFC 9207）。
- R4 令牌：`POST /oauth/token` 签发 ES256 的 `id_token`（aud = client_id）和 `access_token`（JWT，`typ: at+jwt`，aud = 该应用登记的资源列表，可多个），TTL 10 分钟；access token 带短期粗粒度权益 claim `ent`。
- R5 refresh：仅在请求 `offline_access` 时签发；每次使用都轮换。轮换后 30 秒内，同一 client 重放刚刚换掉的 refresh 返回同一份新 token；超过宽限再重放 → 拒绝并吊销整个系列（family）。
- R6 客户端登记：静态配置（`apps/idp/src/oidc-clients.js`）；client `ainews`，redirect_uri 为 `https://ainews.example.com/_pkauth/callback`（域名用 example.com 占位）；本地测试 client 只在 `RP_ID=localhost` 时存在。
- R7 step-up：复用现有 step-up（5 分钟窗口、风险会话必须先 step-up）。映射：`acr_values` 含 `urn:pkauth:acr:stepup`、`max_age` 超时、`prompt=login` → 先 step-up 再签发；id_token 回写 `acr`、`amr`、`auth_time`（= 最近一次 UV 验证时间）。为防止 step-up 后循环，`prompt=login` 与小于 60 秒的 `max_age` 按“60 秒内验证过”判断。
- R8 `GET /oauth/userinfo`（Bearer access token）。
- R9 示例 relying party（`examples/relying-party.mjs`）+ 接入文档 `docs/oidc-integration.md`；**不改 ainews 仓库**。

## 非目标
2nd 隐私界面、NAS / Access / Tunnel、Stripe 权益、公开注册、管理员账号创建、账户恢复（维持 `RECOVERY_IMPLEMENTED=false`）、动态客户端注册、机密客户端（client_secret / private_key_jwt）、DPoP、RP 发起登出（end_session）、同意页（只登记自有应用，第一方免同意）、部署、设 secret、动线上 KV、同步 public。

## 不变量
- INV-1 签名私钥不入仓库：只从 `env.OIDC_SIGNING_KEY`（私钥 JWK JSON，含 `kid`）读取；本地 `.dev.vars` 由 `scripts/oidc-keygen.mjs` 生成、CI 每次随机生成。**未配置时所有 OIDC 端点返回 503（fail closed）**，现有登录不受影响。
- INV-2 RP ID 与 ORIGIN 不变；不改 `user:` / `cred` 结构；旧 passkey 和老账号无需任何迁移即可登录并完成 OIDC 授权。
- INV-3 `redirect_uri` 与登记值**逐字精确匹配**；client_id 或 redirect_uri 无效时只显示错误，**绝不重定向**（防开放重定向）。
- INV-4 PKCE 强制 S256；缺少或 `plain` 一律拒绝；`code_challenge` 必须是 43 位 base64url。
- INV-5 授权码一次性：存 DO（`oc:<hash>`，TTL 60 秒），兑换时原子 consume；绑定 client_id、redirect_uri、code_challenge。
- INV-6 refresh 一次性轮换：DO 原子操作；只存 SHA-256 哈希；重放 → 系列吊销；系列绑定签发它的 IdP 会话 sid，会话被吊销 / 退出 / 过期 → 该会话签出的所有 refresh 失效（复用现有吊销路径：改角色、删 passkey、风险事件）。
- INV-7 每次兑换 / 刷新都重新检查账户存在且未过期；账户过期或删除后不再签发。
- INV-8 风险会话（新国家 / 新 ASN 登录，`risk` 非空）不签发授权码，必须先 step-up。
- INV-9 `sub` = 账户的 WebAuthn `userID`（随机、稳定、不含用户名）；用户名只在 `profile` scope 下作为 `preferred_username` 给出。
- INV-10 `ent` 只是提示：粗粒度（如 `feeds:read`、`feeds:write`），随 access token 10 分钟过期；**写操作由资源方在服务端再查**（Phase 1 文档约定，接口留到 Phase 2）。
- INV-11 `/oauth/*` 不在 `/api/` 下：token 端点是服务器到服务器调用，不做 Origin 校验、不读 cookie；authorize 只读会话 cookie（SameSite=Lax 顶层导航）。限流复用 RL_OPTIONS（authorize）与 RL_VERIFY（token / userinfo）。
- INV-12 登录后回到 authorize 的 `continue` 参数只接受同源 `/oauth/authorize?` 开头的路径（客户端与服务端都校验）。
- INV-13 日志、审计、错误信息不含 code、token、verifier。

## 验收测试清单
单元（`node tests/oidc-unit.mjs`，纯 Node，无网络）：
- [ ] AC-1 PKCE：`tests/oidc-unit.mjs`「PKCE S256 与 RFC 7636 附录 B 向量一致」。
- [ ] AC-2 JWT：「ES256 签名可被公钥 JWK 验证」「篡改 payload 后验签失败」「过期 / iss / aud 不符被拒」。
- [ ] AC-3 redirect：「redirect_uri 逐字匹配（尾斜杠、大小写、查询串都算不同）」。
- [ ] AC-4 continue：「continue 只接受同源 /oauth/authorize?」。

端到端（`node tests/oidc.mjs`，自己启动本地 wrangler dev，客户端用 oauth4webapi，浏览器用 Playwright 虚拟认证器；RP 回调由测试内的最小 HTTP 服务接收，端口 8788 / 8798）：
- [ ] AC-5 fail closed：「未配置签名密钥时 discovery 返回 503」。
- [ ] AC-6 旧 passkey 兼容：「未开 OIDC 时注册的 passkey，开启后仍能登录并完成授权」。（PoC 无此项）
- [ ] AC-7 PoC#1：「discovery 解析成功且 issuer 匹配」「JWKS 只含公钥」。
- [ ] AC-8 PoC#2：「授权码 + PKCE S256 换 token，id_token 签名/iss/aud/exp/nonce 由 oauth4webapi 校验通过」。
- [ ] AC-9 PoC#3：「id_token 带 amr/acr/auth_time」。
- [ ] AC-10 PoC#4：「资源方用 JWKS 本地校验 access token，aud 含两个资源，ent 正确」。
- [ ] AC-11 PoC#5：「同一授权码第二次兑换被拒」。
- [ ] AC-12 PoC#6：「错误 code_verifier 被拒」；另加「缺少 PKCE 或 plain 被拒」。
- [ ] AC-13 PoC#7：「refresh 轮换拿到新 refresh token」。
- [ ] AC-14 PoC#8：宽限内重放返回同一份新 token。测试：`apps/idp/tests/oidc.mjs`「宽限内重放刚刚轮换的 refresh 返回同一份新 token」。
- [ ] AC-15 PoC#9：超过宽限再重放吊销整个系列。测试：`apps/idp/tests/state-unit.mjs`「超过宽限再重放吊销整个系列」「家族被吊销后新 refresh 也失效」。
- [ ] AC-16 INV-3：「未登记 redirect_uri / 未知 client 返回 400 且不重定向」。
- [ ] AC-17 R7：「acr_values=stepup 在窗口外先 step-up，id_token acr=stepup 且 auth_time 刷新」「prompt=none 无会话返回 login_required」。
- [ ] AC-18 INV-6：「IdP 退出登录后 refresh 失效」。
- [ ] AC-19 R8/INV-9：「userinfo 返回与 id_token 相同的 sub，sub 不含用户名」。
- [ ] AC-20 多应用隔离：「client A 的 access token aud 不含 client B 的资源」。
- [ ] AC-21 回归：既有 tests（session、expiry-roles、admin-ui、e2e、unit）全部通过。

## 威胁模型（摘要，详见调研底稿第 7 节）
| 威胁 | 处理 |
|---|---|
| 签名私钥泄露 | 只放 secret；`kid` 轮换，JWKS 同时发布上一把公钥（`OIDC_SIGNING_KEY_PREV_PUBLIC`）；泄露时换 key 并删除旧公钥，已签 token ≤10 分钟失效，refresh 不受影响（不透明） |
| 开放重定向 / code 被截 | redirect_uri 精确匹配；PKCE S256；code 60 秒一次性 |
| IdP 混淆攻击 | 回跳带 `iss`，RP 必须校验（oauth4webapi 默认校验） |
| refresh 被盗 | 轮换 + 重放吊销系列 + 绑定 IdP 会话 |
| 登录 CSRF | RP 必须使用 `state` 和 `nonce`；授权端点要求 `state` |
| token 被跨应用使用 | access token aud 为该 client 登记的资源列表；资源方必须校验 aud |
| 新环境会话被盗用 | 风险会话不签发（INV-8） |
| 权益延迟 | ent 只作提示，写操作服务端查（INV-10） |

## KV 迁移与备份
- **KV 无结构变化**：不新增、不修改 KV key；新状态全在 DO（同一个 `AuthState` 类，新 key 前缀 `oc:` `rt:` `rf:`，均带 exp 由现有 alarm 清理），**不需要新的 DO migration tag**。
- 上线前备份（文档做法，本阶段不执行）：`npx wrangler kv key list --binding KV --remote > kv-keys.json`，再按 key 逐个 `wrangler kv key get` 只读导出到仓库外的加密目录。DO 中的新数据都是短期的，回滚时可丢弃。

## 回滚
1. 删除 secret `OIDC_SIGNING_KEY` → 所有 OIDC 端点立即 503，现有登录不受影响。
2. 回退本 PR 的提交并重新部署；DO 中 `oc:/rt:/rf:` 记录到期自动清理。
3. 已签出的 access / id token 最长 10 分钟后失效。

## 待确认（Jack 未拍板，按默认执行）
1. 自建 IdP（演进 passkey-demo），不采用 Pocket ID / Authelia。
2. RP ID 保持现有域名不变；旧 passkey 继续可用，老账号兼容（INV-2）。
3. 权益只放短期粗粒度 claim，写操作服务端查（INV-10）；Phase 1 的 ent 由角色推导（负责人 / 有管理角色 → staff 集合，其余 → member 集合）。
4. 保持邀请制，不开放公开注册。
5. 账户恢复维持 `RECOVERY_IMPLEMENTED=false`，本阶段不动。
6. ainews 作为公共客户端（PKCE，无 client_secret）；生产 redirect_uri 与资源 URL 待 Jack 给出真实域名后替换 example.com 占位。
7. access / id token TTL 10 分钟；refresh 不超过 IdP 会话剩余时长。

## 风险
- 线上未验证：生产签名密钥、真实域名下的 redirect、限流阈值对 RP 的影响。
- ent 由角色推导，与未来 Stripe 权益模型不同，Phase 2 要替换。
- 公共客户端无法证明自身身份，依赖 PKCE 与精确 redirect_uri。

## 是否重大改动
是：新增对外协议端点与签名密钥。按工作流，合并与部署需 Jack 批准；本 PR 全绿后停止，不合并。
