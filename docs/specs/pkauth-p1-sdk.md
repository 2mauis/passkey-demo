# pkauth P1：IdP 调整与 Workers SDK

## 背景/目标

在 P0 布局上完成设计 §13 的 P1 代码（不部署）：

- OIDC 保持 `29d09b1` 的授权码 + PKCE + refresh 轮换；acr 改为 `urn:pkauth:acr:*`；ainews 的 redirect 改为 `https://ainews.example.com/_pkauth/callback`；client_id 为 `ainews`。
- `@pkauth/core` 用 WebCrypto 做 ES256 校验、路径规范化、cookie（AES-GCM + HKDF）和配置 schema。生产代码不依赖 jose。
- `@pkauth/workers` 的 `protect(upstream)` 按 §4.3 的顺序处理请求，并实现 S-1…S-16。
- D1 代码路径覆盖用户、凭据、邀请、角色（以及过期、拒绝、模板、审计）。未绑定 `DB` 时仍用 KV。
- 迁移票据：绑定 `userID`、5 分钟、一次性。`otp` / `single` 不签发 refresh；otp 额度在 authorize 时原子扣减。refresh 重用宽限 30 秒。

## 非目标

不实现 introspect、device code、Stripe、Node SDK、恢复码。不发布 npm（D15 在本阶段改为 workspace / git 依赖）。不创建管理员账户。不写线上 KV / D1，不部署。

## 不变量

- INV-P1.1 受保护路径没有有效凭据时，浏览器 302、API 401，不调用上游。
- 公开路径原样转发。
- `PKAUTH_MODE=off` 或缺少必填配置时，受保护路径 503，公开路径不变。
- Host 不在白名单或白名单为空时，受保护路径 421。
- 时钟容差 ≤ 5 秒；本实现为 0，因此 exp 早 1 秒即拒绝。
- 算法只接受 ES256。`alg: none` 与 HS256 拒绝。
- 授权通过后才按 `PKAUTH_UPSTREAM_INJECT` 注入 secret；未授权时上游看不到该头。
- 迁移票据不能换成另一个 `userID`。同一邀请在 D1 上并发消费只有一次成功。

## 验收测试清单

- [ ] 需求：S-1 有效 AT 与剥离伪造头；测试：`packages/workers/tests/sdk.test.mjs`「S-1 有效 AT 放行且 X-PKAuth-Sub 正确；伪造的内部头被剥离」；验证面：本地 Node。
- [ ] 需求：S-2 缺凭据；测试：同文件「S-2 缺少凭据、空字符串、不是 JWT → 401，且不调用上游」。
- [ ] 需求：S-3 aud / iss / 密钥 / typ；测试：同文件「S-3 aud / iss / 签名密钥 / typ 不对 → 401」。
- [ ] 需求：S-4 过期与容差；测试：同文件「S-4 exp 比固定时钟早 1 秒 → 401；时钟容差 ≤ 5 秒」。
- [ ] 需求：S-5 未知 kid 与 JWKS 陈旧；测试：同文件「S-5 未知 kid 重新拉取 JWKS 一次后仍 401；缓存超过陈旧期且拉取失败 → 503」。
- [ ] 需求：S-6 alg；测试：同文件「S-6 alg none 与 HS256 → 401；算法白名单只有 ES256」。
- [ ] 需求：S-7 路径；测试：同文件「S-7 路径表：命中受保护、不命中公开、解码失败受保护、未列出的方法 405」，以及 `packages/core/tests/core.test.mjs`「路径规范化、最长前缀、未列出的方法、解码失败」「前缀 / 匹配全部后代，更长前缀仍优先」。
- [ ] 需求：`PKAUTH_DEFAULT=protected` 且规则缺失或为空时 fail-closed；测试：sdk 测试「PKAUTH_DEFAULT=protected 且规则缺失或为空时全部受保护，不转给上游」「前缀 / 命中全部后代路径；更长前缀仍然优先」。
- [ ] 需求：S-8 Host；测试：sdk 测试「S-8 Host 不在白名单或白名单为空 → 421」。
- [ ] 需求：S-9 CSRF；测试：sdk 测试「S-9 cookie 写操作的 CSRF；Bearer 写请求不要求 CSRF 头」。
- [ ] 需求：S-10 回调；测试：sdk 测试「S-10 回调校验 state / iss / nonce / tx 过期；坏的 return_to 改成 /」。
- [ ] 需求：S-11 cookie；测试：sdk 测试「S-11 cookie 被篡改、密钥换了、版本不对 → 当作未登录」，以及 core 测试「cookie 密封可解开；篡改、换密钥、版本不对都当作没有会话」。
- [ ] 需求：S-12 refresh；测试：sdk 测试「S-12 AT 过期时用 refresh 换新；宽限内并发都成功；超过宽限再重放则家族失效」，以及 `apps/idp/tests/state-unit.mjs`「宽限内重放刚刚轮换的 refresh 返回同一份新 token」「超过宽限再重放吊销整个系列」。
- [ ] 需求：S-13 online；测试：sdk 测试「S-13 online：拒绝 403、超时 503、没有 service binding 时走 HTTPS」。
- [ ] 需求：S-14 注入；测试：sdk 测试「S-14 授权通过后注入 secret；客户端自带的头被删掉；未授权时上游收不到」。
- [ ] 需求：S-15 缓存与 CORS；测试：sdk 测试「S-15 受保护响应 no-store 且没有 ACAO *；OPTIONS → 403」。
- [ ] 需求：S-16 开关与 scheduled；测试：sdk 测试「S-16 MODE=off 或缺配置时受保护路径 503、公开路径不变；scheduled 透传」。
- [ ] 需求：jose 只在测试里交叉验证；测试：`packages/workers/tests/jose-cross.test.mjs`「jose 签的 ES256 能被 @pkauth/core 验过，反过来也一样」。
- [ ] 需求：redirect、D1 邀请、迁移票据、otp、过期 refresh；测试：`apps/idp/tests/pkauth-idp-unit.mjs`「ainews redirect_uri 是 /_pkauth/callback」「D1 邀请并发消费只成功一次」「迁移票据一次性，只能绑定原 userID」「迁移票据 5 分钟后过期」「otp 额度在 authorize 路径原子扣减：第二次失败」「过期账户在 refresh 阶段被拒」。

## 风险

本地 miniflare 通过不等于线上通过。D1 迁移和域名切换都要 Jack 先做 KV 只读备份再单独批准。签名私钥只放 secret，不进仓库。

## 是否重大改动

是：鉴权边界、新的 OIDC 声明和存储代码路径。合并与部署需 Jack 批准。本 PR 不合并、不部署。
