# 如何限制 passkey 的注册名单（调研 + 选型 + 2nd brain 接入方案）

> 背景：passkey 只解决“怎么证明是你”（认证），不解决“谁可以开户”（授权 / 准入）。WebAuthn 规范本身不限制谁能发起注册；
> 注册名单必须由 RP（服务端）在**发放注册 challenge 之前**决定。

## 1. 常见标准做法

| 做法 | 怎么做 | 优点 | 缺点 | 适合 |
| --- | --- | --- | --- | --- |
| **一次性邀请码 / 邀请链接** | 管理员生成高熵随机码（服务端只存哈希），有过期时间、可绑定用户名、用一次即作废、可撤销；服务端在生成注册 options 之前校验 | 不需要发邮件、不存邮箱等个人信息；实现小；与 passkey 的“无密码、无用户名枚举”配合好 | 链接被转发就能用（靠短有效期 + 绑定用户名 + 可撤销缓解）；需要管理员手动发 | 个人站点 / 小圈子 / 内测（**本 demo 选用**） |
| 邮箱白名单 + 邮箱验证（magic link / OTP） | 只允许名单内邮箱；发一次性链接或验证码证明拥有邮箱，验证后才允许创建 passkey | 用户自助；邮箱可用于账号恢复 | 需要发信服务、存邮箱（个人信息）、防枚举设计更复杂 | 有固定成员名单的团队 |
| 管理员审批 | 注册请求先进入 pending，管理员批准后才激活 | 不需要预先知道名单 | 要 pending 状态、审批 UI、通知；未审批前账号已存在，需防滥用 | 公开申请 + 人工把关 |
| 前置身份网关（Cloudflare Access / 企业 SSO） | 在应用前面加一层身份代理，只有策略里的邮箱 / 组能访问；应用本身甚至不需要账号系统 | 零代码；免费 ≤50 用户；在边缘就拦截 | 登录方式是 Access 的（邮件 OTP / 第三方 IdP），不是站点自己的 passkey | 只想“让少数人能看”的静态站（如 2nd brain） |

## 2. 权威依据

- SimpleWebAuthn 文档《Passkeys》：建议用户先通过一次性授权码 / magic link 等完成身份确认（引导注册），然后才调用 `generateRegistrationOptions()` 注册 passkey。<https://simplewebauthn.dev/docs/advanced/passkeys>
- OWASP Passkey Security Cheat Sheet：注册仪式应绑定到已验证的开户 / 账号流程，并对注册接口限流。<https://cheatsheetseries.owasp.org/cheatsheets/Passkey_Security_Cheat_Sheet.html>
- OWASP Email Validation and Verification Cheat Sheet：验证 token 必须随机、一次性、限时；响应不应泄露账号是否存在。<https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html>
- OWASP Authentication Cheat Sheet：统一的错误响应，防止枚举。<https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- OWASP API Security Top 10 2023 – API5 Broken Function Level Authorization：管理功能必须单独鉴权。<https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
- W3C WebAuthn Level 3 §1.3.1（注册）与“Registration Ceremony”定义：注册由 RP 发起，规范不规定准入策略。<https://www.w3.org/TR/webauthn-3/>
- Cloudflare KV 计费 / 限制 / 过期写入：<https://developers.cloudflare.com/kv/platform/pricing/>、<https://developers.cloudflare.com/kv/platform/limits/>、<https://developers.cloudflare.com/kv/api/write-key-value-pairs/>
- Cloudflare Access（Zero Trust 免费 ≤50 用户）：<https://www.cloudflare.com/sase/products/access/>；一次性 PIN 登录：<https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/one-time-pin/>；校验 Access JWT：<https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/>
- Pages Functions 中间件 / 计费 / 已知问题：<https://developers.cloudflare.com/pages/functions/middleware/>、<https://developers.cloudflare.com/pages/functions/pricing/>、<https://developers.cloudflare.com/pages/platform/known-issues/>、<https://developers.cloudflare.com/pages/configuration/preview-deployments/>

## 3. 本 demo 的选择：一次性邀请码

理由：个人用途、少量读者；不想存邮箱（不存个人信息）、不想接发信服务；完全在免费额度内（每个邀请 1 次 KV 写入 + 用掉时 1 次删除）。
实现要点见 README“防滥用分层 · 邀请码”：256 bit 随机码、KV 只存 SHA-256、KV expiration 自动过期、options 前校验、verify 写入前复查、成功后立即删除、统一 403 文案、管理接口 Bearer token（常量时间比较）+ 独立限流。

## 4. 2nd brain（2ndbrain.lyrae.cc，Pages 项目 2rdbrain）接入方案 —— 仅方案，未实施

目标：静态站只给自己和少数受邀人阅读。

### 方案 A（推荐先用）：Cloudflare Access

1. Zero Trust（Free 计划，≤50 用户免费）→ Access → 新建 Self-hosted 应用，域名 `2ndbrain.lyrae.cc`。
2. 策略：Allow → Emails 为受邀人邮箱（或 Emails ending in / GitHub 组织）；登录方式用 One-time PIN（邮件验证码），或接 GitHub / Google（这些账号本身可用 passkey 登录）。会话时长按需（如 24h–1 个月）。
3. **同时保护 `2rdbrain.pages.dev` 和预览部署 `*.2rdbrain.pages.dev`**：Pages 项目 Settings → “Enable access policy” 只覆盖预览；生产的 `*.pages.dev` 需另建 Access 应用（见 Pages 已知问题），否则可绕过自定义域名直接访问。
4. 可选纵深防御：Pages Functions `_middleware.js` 校验 `Cf-Access-Jwt-Assertion`（团队 certs + 应用 AUD），防止有人绕过 Access 路径访问。
- 优点：零代码、在边缘拦截、静态资源仍不计 Functions 请求（不加 middleware 时）、自带审计日志、撤销某人只需改策略。
- 缺点：登录体验是 Access 的（邮件 OTP / 第三方 IdP），不是站点自己的 passkey；成员名单要写进 Access 策略（邮箱属于个人信息，但存在 Cloudflare 账号配置里，不在代码里）；>50 用户收费。

### 方案 B：站点自己的 passkey + Pages Functions middleware 检查会话 cookie

1. 把本 demo 的注册 / 登录 / 邀请逻辑移植为 Pages Functions（`functions/api/...`），绑定一个 KV；RP ID 用 `2ndbrain.lyrae.cc`（demo 上的 passkey 不能复用，因为 RP ID 不同）。
2. `functions/_middleware.js`（放在 functions 根目录，对所有路径生效，先于静态资源执行）：放行 `/login`、`/api/*`、登录页所需静态资源；其余请求检查 `__Host-` 会话 cookie。**会话 cookie 用 HMAC 签名的无状态 token（含用户名与过期时间）**，middleware 只做 WebCrypto 验签，不读 KV，避免每个页面请求消耗 KV 读取；无效则 302 到 `/login`。
3. 注册仍用一次性邀请码；登录后签发签名会话 cookie；退出 = 清 cookie（无状态会话无法单个吊销，可通过轮换签名密钥全体失效，或缩短有效期）。
4. middleware 对 `*.pages.dev` 和预览部署同样生效（优点）。
- 优点：读者体验是真正的 passkey（指纹 / 面容）；不依赖 Zero Trust；不需要存邮箱。
- 缺点：要写和维护认证代码；**每个请求（包括 CSS / 图片）都会调用 Function**，计入 Workers 免费额度 100,000 请求 / 天（Pages 静态资源只有在不触发 Functions 时才免费且不限量）；用 `_routes.json` 排除静态资源可省额度，但被排除的资源就不受保护；KV 写入 1,000 / 天的限制只影响登录 / 注册次数，阅读不耗 KV。

### 建议

先上方案 A（几分钟配置、无代码、免费），并记得同时保护 `pages.dev` 域名；如果明确想要“站点自己的 passkey 体验”，再按方案 B 改造，复用本 demo 的邀请码与签名 cookie 代码。两种方案都**不需要**改 lyrae.cc 的 DNS / WAF / bot 设置以外的东西（方案 A 需要在 Zero Trust 里建应用；方案 B 只改 Pages 项目代码）。
