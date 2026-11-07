# pkauth（Passkey IdP + Workers SDK）

仓库是 monorepo。IdP 在 `apps/idp`（原先的 `src/`、`public/`、`tests/`、`wrangler.toml`）。`@pkauth/core` 与 `@pkauth/workers` 在 `packages/`，只通过 npm workspace 引用，不发布到 npm。下面表格里的 `src/`、`tests/`、`wrangler.toml` 均相对于 `apps/idp/`。

# Passkey（WebAuthn）登录演示

线上技术演示：<https://passkey-demo.iotempjp.workers.dev>（注册仅限受邀，不提供公开自助注册；请勿输入真实个人信息。演示数据可能被清除。）<!-- privacy-scan: allow -->

文中其余的 `passkey-demo.example.workers.dev` 都是占位符，自行部署后换成自己的 Worker 主机名。

**注册仅限受邀**：有角色的用户在演示站点登录后，在网页 [`/admin`](https://passkey-demo.iotempjp.workers.dev/admin) 签发一次性、有过期时间的邀请码 / 邀请链接（可绑定用户名），没有有效邀请无法注册。自行部署时，`/admin` 在自己的主机名上。命令行 `scripts/invite.mjs` 保留为应急入口。调研与选型见 [`docs/registration-restriction.md`](docs/registration-restriction.md)。<!-- privacy-scan: allow -->

## 架构

单个 Cloudflare Worker（`passkey-demo`）同时提供前端静态资源和 API，数据存放在一个 KV 命名空间（`passkey-demo-kv`），另用 Workers Rate Limiting 绑定与 Cloudflare Turnstile（免费）防滥用。

| 文件 | 作用 |
| --- | --- |
| `wrangler.toml` | Worker 配置：`workers_dev = true`，无 routes / 自定义域名；`RP_ID`、`ORIGIN` 通过 vars 配置；KV 绑定 `KV` |
| `src/worker.js` | API 与静态资源入口，使用 `@simplewebauthn/server` v14 生成 / 验证 options |
| `src/client.js` | 浏览器端逻辑，使用 `@simplewebauthn/browser` v14，经 esbuild 打包为 `public/app.js`（无 CDN） |
| `public/index.html`、`public/style.css` | 中文界面 |
| `public/admin.html`、`src/admin.js` | 邀请管理页 `/admin`（`src/admin.js` 打包为 `public/admin.js`） |
| `tests/admin-ui.mjs` | `/admin` 页面与角色权限测试（本地：自己启动 wrangler dev 跑完整流程；线上：拒绝路径 + 邀请链接自动填充 + Bearer） |
| `docs/acceptance-checklist.md` | 给 Jack 的真机验收清单 |
| `shots/admin.png` | 管理页截图（本地测试数据，不含邀请码 / token） |
| `tests/e2e.mjs` | Playwright + CDP 虚拟认证器端到端测试 |
| `tests/conditional.mjs` | 条件式 UI（自动填充）登录测试 |
| `tests/online-checks.mjs` | 线上验收（拒绝路径、浏览器登录路径、过期、429） |
| `scripts/invite.mjs` | 应急命令行：创建 / 列出 / 撤销邀请（token 从 `.admin-token` 读取，不打印） |
| `docs/registration-restriction.md` | 限制注册名单的标准做法调研、选型理由、2nd brain 静态站接入方案（仅方案） |
| `scripts/turnstile-setup.mjs` | 创建 Turnstile 小组件后写入 sitekey、把 secret 管道给 `wrangler secret put` |
| `share/` | 一页式介绍图（HTML 源 + PNG） |
| `tests/logs/` | 测试输出记录 |

### API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/me` | 当前登录状态与 passkey 列表；未登录时返回公开的 Turnstile sitekey |
| POST | `/api/register/options` | 未登录：`{username, invite, turnstileToken}`，依次校验用户名格式 → 邀请码 → Turnstile；已登录：为当前用户添加 passkey（无需邀请、无需 Turnstile） |
| POST | `/api/register/verify` | 验证注册响应；未登录注册在任何写入前再次确认邀请有效，成功后立即删除邀请 |
| POST | `/api/login/options` | 可发现凭据登录（`allowCredentials` 为空）；`{conditional:true}` 用于自动填充 |
| POST | `/api/login/verify` | 通过 `cred:<id>` 索引找到用户，验证签名并更新计数器 |
| POST | `/api/logout` | 删除 KV 中的会话并清除 cookie |
| GET | `/admin` | 邀请管理页：必须已登录且有角色，否则 403“无权访问”页（`/admin.html`、`/admin/…` 等别名同样处理） |
| POST | `/api/admin/invites` | 签发邀请 `{ttlSeconds?: 60–2592000（默认 259200=72h）, username?}`，邀请码明文只在本次响应返回 |
| GET | `/api/admin/invites` | 列出未过期的邀请（编号 / 绑定用户名 / 状态 / 创建时间 / 过期时间 / 签发者 / 当前用户能否撤销，没有邀请码）+ 当前用户角色 |
| POST | `/api/admin/invites/revoke` | 撤销 `{id}`（16 位十六进制） |
| GET | `/api/admin/members` | 成员角色列表（负责人、成员主管可见） |
| POST | `/api/admin/members` | 授予 / 变更 / 移除角色 `{username, role: "membership_lead" \| "inviter" \| null}` |

`/api/me` 增加 `role` 字段（`{id, label, perms}` 或 `null`），首页据此显示“邀请管理”入口。

## 角色与权限（`/admin`）

三级角色，英文标识用于接口和配置，中文名用于界面：

| 操作 | 负责人 `principal` | 成员主管 `membership_lead` | 邀请人 `inviter` | 已登录但无角色 / 未登录 |
| --- | :-: | :-: | :-: | :-: |
| 打开 `/admin`、看到自己的角色 | ✅ | ✅ | ✅ | ❌ 403 页面 / 401 接口 |
| 签发邀请（一次性、可设有效期、可绑定用户名） | ✅ | ✅ | ✅ | ❌ |
| 查看全部待使用邀请（不含邀请码） | ✅ | ✅ | ✅ | ❌ |
| 撤销邀请 | 任何邀请 | 任何邀请 | **只能撤销自己签发的**（别人签发的按钮置灰，接口 403） | ❌ |
| 查看成员角色列表 | ✅ | ✅ | ❌（区块隐藏，接口 403） | ❌ |
| 授予 / 移除“邀请人” | ✅ | ✅ | ❌ | ❌ |
| 授予 / 移除“成员主管” | ✅ | ❌（下拉框里没有，接口 403） | ❌ | ❌ |
| 授予 / 移除“负责人” | ❌ 只能改 Worker vars `PRINCIPALS` 并重新部署 | ❌ | ❌ | ❌ |
| 修改自己的角色 | ❌ | ❌ | ❌ | ❌ |

- **负责人**来自 `wrangler.toml` 的 `[vars] PRINCIPALS`（逗号分隔，当前为 `root_example`），页面上不能授予、不能移除、不能降级；`PRINCIPALS` 中尚未注册的用户名不能被新注册（防止账号数据丢失后被人用邀请抢注）。
- **成员主管 / 邀请人**由页面分配，存在 KV `role:<用户名>`（值为角色，metadata `{r: 角色, b: 授予者, t: 授予时间}`）；只能分配给已注册的用户；与当前角色相同则不写 KV。
- 每次请求都按会话里的用户名实时查角色，移除角色立即生效（同一节点；跨节点受 KV 最终一致影响，最长约 60 秒）。
- 页面只是把做不了的操作隐藏或置灰；**服务端对每个操作独立校验同样的规则**，测试里用直接调接口的方式验证了越权全部被拒。

命名与分级参考（只借鉴模式，名称是为“邀请管理”这个场景自己定的）：

- Stripe [User roles](https://docs.stripe.com/get-started/account/teams/roles)：Super Administrator 只能由 Super Administrator 授予；专管成员的 IAM Administrator 不能授予 Administrator / Super Administrator。→ 最高角色不可在页面授予；“成员主管”只能分配比自己低的角色。
- Notion [Manage members & guests](https://www.notion.com/help/add-members-admins-guests-and-groups)：Workspace owner / **Membership admin** / Member，Membership admin 专门负责添加、移除成员。→ “成员主管 `membership_lead`”这个名字和职责。
- Linear [Members and roles](https://linear.app/docs/members-roles)：Admin 可以把成员提升为 Team owner，Workspace owner 角色只由更高层级掌握。→ 逐级授权、不能越级。
- Vercel [Access Roles](https://vercel.com/docs/rbac/access-roles)：Owner 是最高权限、角色变更只能由 Owner 做；建议至少两人持有最高角色以保证延续性。→ 负责人可写多个（逗号分隔），并提示保留应急入口。
- 不用 owner / admin 一类泛称，是因为这个项目里角色只管“谁能发邀请”，不是整个系统的所有者或管理员：负责人 = 对邀请体系负最终责任；成员主管 = 管人（分配邀请人）；邀请人 = 只发邀请。

## 网页管理的鉴权与 CSRF

- **会话**：`__Host-pk_sess`（`HttpOnly; Secure; SameSite=Lax; Path=/`，时长按会话预设，见 docs/session.md）。Lax 允许从外链顶层跳转时带上 cookie（便于从邮件进入），跨站子请求（表单 POST、`<img>`、`fetch`）仍不带；写操作另由 Origin / Fetch Metadata / 自定义头拦截。
- **再加三道检查**（不读 KV，最先执行）：
  1. `Sec-Fetch-Site` 若存在必须是 `same-origin`（`same-site` 也拒绝：防同一注册域下的其他子域）；`/admin` 页面另外允许 `none`（地址栏直接打开）。
  2. `Origin` 若存在必须等于 `ORIGIN`；POST 必须带 `Origin`。
  3. 管理接口必须带自定义请求头 `X-PK-Admin: 1`。跨站页面要设置自定义头必须先过 CORS 预检，而本站不响应预检，所以伪造请求发不出来；表单 / `<img>` 这类“简单请求”也带不了这个头。
  有了 SameSite=Lax + Fetch Metadata + Origin + 自定义头，没有再加同步型 CSRF token（它需要服务端状态或额外的签名 cookie，收益很小）。
- 失败响应：跨站特征 → 403 `来源校验失败（疑似跨站请求）`；未登录 / 无角色 / 会话失效 → 401 `{"error":"未授权"}`（统一）；有角色但权限不够 → 403 `权限不足：…`。
- 所有管理路径（含 `/admin` 页面）都先过 `RL_ADMIN` 限流（10 次 / 60 秒 / IP / 路径），再做任何 KV 读取。

## 应急入口：Bearer token（保留）

`Authorization: Bearer <ADMIN_TOKEN>`（Worker secret）仍可调用三个**邀请**接口（不能查看或修改角色），供 `scripts/invite.mjs` 使用：

- 保留的理由：KV 被清空、负责人的 passkey 丢失时仍能签发邀请恢复访问；线上自动化测试也靠它验证签发 / 列表 / 撤销的接口逻辑（线上 Turnstile 需要真人，脚本拿不到带角色的会话）。
- 比较方式：两边先 SHA-256 再 `crypto.subtle.timingSafeEqual`（常量时间、与长度无关）；secret 未配置或短于 32 字符时一律 401（fail closed）；无 token / 错 token / 错方案的响应完全相同（401 `{"error":"未授权"}`）；同样先过 `RL_ADMIN` 限流。
- 请求里带了 `Authorization` 头就只走 token 校验，失败直接 401，不会回退到会话。通过 token 签发的邀请，“签发者”显示为“应急 token”（内部标识 `#token`，不可能与用户名冲突）。
- 不需要时关闭：`npx wrangler secret delete ADMIN_TOKEN`，之后这条路径对任何请求都返回 401。

### KV 键

- `user:<name>`：`{username, userID(随机 32 字节), createdAt, credentials:[...]}`
- `cred:<credIdB64url>` → 用户名
- `sess:<id>`：会话，TTL 4 小时
- `used:<challenge>`：登录成功后写入的“已使用”标记，TTL 300 秒（重放兜底）
- `role:<name>`：页面分配的角色（`membership_lead` / `inviter`），metadata `{r, b: 授予者, t: 授予时间}`；负责人不在 KV 里（来自 vars）
- `inv:<SHA-256(邀请码) hex>`：邀请，值与 metadata 均为 `{id: 哈希前 16 位, u: 绑定用户名|null, c: 创建时间, x: 过期时间, b: 签发者用户名或 #token}`；写入时带 KV `expiration`，过期后由 KV 自动删除；撤销或注册成功后直接 delete。**KV 里只有哈希，没有邀请码明文**；list 直接读 metadata，不逐个 get。
- **options 阶段不再写 KV**：challenge 存在 HMAC 签名 cookie 中。

### 防滥用分层（请求依次经过）

1. **限流**（Workers Rate Limiting 绑定，`[[ratelimits]]`）：按 `CF-Connecting-IP` + 路径计数；`RL_OPTIONS` 用于两个 options 接口，`RL_VERIFY` 用于 verify / logout，均为 10 次 / 60 秒；超限返回 429 + `Retry-After: 60` + 中文提示。限流检查在任何 KV 写入和 Turnstile siteverify 之前执行。注意：该限流按 Cloudflare 节点（location）独立计数，且是近似值。
2. **邀请码**（仅未登录注册）：32 字节（256 bit）随机数的 base64url（43 字符）。options 阶段：格式检查 → 1 次 KV 读取 `inv:<hash>` → 未过期 → 若绑定用户名则必须一致；任何失败（缺失 / 格式错 / 不存在 / 过期 / 已撤销 / 已使用 / 用户名不符）都返回**同一个** 403 和同一句“邀请码无效或已失效”，且不会调用 siteverify。邀请哈希写入签名 challenge cookie（`ih` 字段）；verify 阶段在验签之后、任何 KV 写入之前再读一次邀请（防止期间被撤销 / 用掉 / 过期），注册成功写入用户与凭据后立即 delete 邀请。注册失败（如用户名已存在）不消耗邀请。
3. **Turnstile**（仅注册）：前端显式渲染 managed 小组件（`action: 'register'`）；服务端调用 siteverify，校验 `success`、`action === 'register'`、`hostname === RP_ID`，通过后才生成 challenge。官方测试密钥的结果（`metadata.result_with_testing_key`）只在 `RP_ID=localhost` 且 `.dev.vars` 中 `TURNSTILE_ALLOW_TEST_KEYS=1` 时被接受，线上一律拒绝。
   - 登录不使用 Turnstile：条件式 UI 会在后台提前申请 options，而 Turnstile token 一次性、300 秒有效且可能需要交互，会破坏自动填充体验；登录 options 已经零 KV 写入，由限流兜底。
4. **签名 challenge cookie**：payload `{p: 'reg'|'auth', c: challenge, u: 用户名绑定, uid, su: 发起时的会话用户, ih: 邀请哈希, f: 流程, x: 过期时间(now+5 分钟)}`，用 HMAC-SHA256（WebCrypto，密钥为 secret `CHAL_HMAC_KEY`）签名，放在 `__Host-pk_chal_reg` / `__Host-pk_chal_auth` / `__Host-pk_chal_cond`（`HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=300`）。verify 时依次：格式 → `crypto.subtle.verify`（常数时间）→ 过期 → 用途/流程，然后立即清除 cookie。
5. **签名验证**：`@simplewebauthn/server` 校验 challenge、origin、rpId、签名；登录时比对 userHandle、signCount；注册时凭据 ID 去重。

### 其他安全设计

- **RP ID / Origin** 来自配置变量，不信任 Host 头；hostname ≠ `RP_ID` 返回 421；POST 的 `Origin` 必须等于 `ORIGIN`，否则 403。
- **不泄露用户名是否存在**：未登录时 register/options 不查询用户，对任意合法用户名都返回同样形状的 options（随机 userID、空 excludeCredentials）；用户名已存在或凭据已被占用时，在 verify 阶段统一返回“该用户名不可用或请求无效”。登录失败（未知凭据 / 账号不存在 / userHandle 不匹配）统一返回“该 passkey 无效或对应账号已不存在”。
- **防止把 passkey 挂到他人用户名上**：给已有账号添加 passkey 必须先用该账号登录，服务端只使用会话里的用户；challenge cookie 记录发起时的会话用户，verify 时必须一致。
- **会话 cookie**：`__Host-pk_sess`，`HttpOnly; Secure; SameSite=Lax; Path=/`；会话存于 Durable Object 会话表，可立即吊销。
- **CPU 上限**：`[limits] cpu_ms = 50`，防止单个请求消耗过多 CPU（仅部署后生效，本地 dev 不强制）。
- **其他限制**：用户名 3–32 位 `[a-zA-Z0-9_-]`；每用户最多 5 个 passkey；请求体 ≤ 16 KB；credential JSON 字段校验；`attestation: 'none'`。
- 安全响应头：严格 CSP（`script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com`，无内联脚本）、`X-Frame-Options: DENY`、`nosniff`、HSTS。

### KV 读写次数（每次操作）

免费额度：读 100,000 / 天，写 1,000 / 天，删除 1,000 / 天，list 1,000 / 天（写、删除、list 分开计数）。

| 操作 | 加邀请前 | 加邀请后 |
| --- | --- | --- |
| 打开 `/admin` 页面 | — | 1 读（会话）；非负责人再 1 读（`role:`） |
| 网页签发邀请 | — | 会话 1 读（+ 非负责人 1 读）+ 1 写 |
| 网页列出邀请 | — | 会话 1 读（+ 非负责人 1 读）+ 1 list（不逐个读取） |
| 网页撤销邀请 | — | 会话 1 读（+ 非负责人 1 读）+ 1 list + 1 删除 |
| 查看成员角色 | — | 会话 1 读（+ 非负责人 1 读）+ 1 list |
| 授予 / 移除角色 | — | 会话 1 读（+ 1 读）+ 1 读（目标当前角色）+ 授予时 1 读（目标用户是否存在）+ **只有角色真的变化时** 1 写或 1 删除 |
| 已登录用户的 `/api/me` | 读会话、用户 | 非负责人多 1 读（`role:`） |
| Bearer 应急入口（签发 / 列出 / 撤销） | 1 写 / 1 list / 1 list + 1 删除 | 不变（不读会话） |
| 未登录 register/options | 0 读 0 写 | 1 读（邀请）0 写；邀请格式不对时 0 读 |
| 新用户 register/verify（成功） | 读 user、cred；3 写（user、cred、session） | 多 1 读（邀请）；3 写 + 1 删除（邀请） |
| 已登录添加 passkey | 2 写（user、cred） | 不变 |
| 登录 | 3 读 3 写（used、user、session） | 不变 |
| 退出 | 1 删除 | 不变 |
| 邀请无效的注册请求 | — | 最多 1 读，0 写，不调 siteverify |
| 管理接口跨站 403 / 401（无会话 cookie）/ 任何 429 | 0 | 0 |

过期邀请靠 KV `expiration` 自动删除，不产生删除计费。

## 部署

```bash
npm install
npx wrangler kv namespace create passkey-demo-kv   # 首次；把 id 写入 wrangler.toml
# Turnstile 小组件（免费 managed，仅允许本 workers.dev 主机名）；sitekey 写入 wrangler.toml 的 vars，
# secret 通过管道直接交给 wrangler secret put，不打印、不落盘。
# 命令里的 passkey-demo.example.workers.dev 是占位符，创建时换成自己的主机名：
npx wrangler turnstile widget create passkey-demo --domain passkey-demo.example.workers.dev --mode managed --json \
  | node scripts/turnstile-setup.mjs
openssl rand -base64 32 | npx wrangler secret put CHAL_HMAC_KEY
# 管理 token：本地生成到 .admin-token（chmod 600，已 gitignore），从 stdin 交给 wrangler，不打印
(umask 077; openssl rand -base64 48 | tr -d '\n=' | tr '+/' '-_' > .admin-token)
npx wrangler versions secret put ADMIN_TOKEN < .admin-token   # 只创建新版本、不部署；首次部署可直接用 wrangler secret put
npx wrangler deploy                                  # 会先执行 npm run build
```

## 邀请管理

### 网页（日常）

1. 用有角色的账号（负责人 / 成员主管 / 邀请人）在演示首页用 passkey 登录，首页会显示“你的角色：… · 邀请管理”入口；或直接打开 <https://passkey-demo.iotempjp.workers.dev/admin>。自行部署时改为自己的主机名，不要用文中的 `example.workers.dev` 占位符。<!-- privacy-scan: allow -->
2. “生成邀请”：选有效期（1 小时 / 1 天 / 3 天 / 7 天 / 30 天），可填绑定用户名，点“生成邀请”。邀请码和链接**只显示这一次**，旁边有“复制”按钮；点“我已复制，隐藏”或离开页面后就不再显示（服务器只存哈希，丢了只能撤销重发）。
3. “待使用的邀请”列表：编号、绑定用户名、状态、创建时间、过期时间、签发者；点“撤销”立即作废（邀请人只能撤销自己签发的）。已使用 / 已撤销的邀请直接从存储里删除，过期的由 KV 自动删除，所以列表里只有“待使用”的。
4. “成员角色”（负责人、成员主管可见）：输入已注册的用户名，选角色，点“授予角色”；点“移除角色”收回。负责人那一行没有按钮（来自 Worker 配置）。
5. 修改负责人：编辑 `wrangler.toml` 的 `PRINCIPALS`，然后 `npx wrangler deploy`。

### 命令行（应急）

token 文件：项目根目录 `.admin-token`（权限 600，不进 git）。脚本只读取它，不打印。

```bash
node scripts/invite.mjs create                         # 不限用户名，默认 72 小时有效
node scripts/invite.mjs create --user alice --ttl 24h  # 只能注册用户名 alice，24 小时有效（60s / 30m / 12h / 7d，范围 60 秒–30 天）
node scripts/invite.mjs list                           # 列出未使用、未过期的邀请（id、绑定用户名、过期时间）
node scripts/invite.mjs revoke <id>                    # 撤销（id 来自 create / list 的输出）
# 选项：--json 输出 JSON；--base <URL>；--token-file <路径>；--local 指向本地 wrangler dev（token 取 .dev.vars 的 ADMIN_TOKEN）
```

`create` 会输出一次邀请码和邀请链接，形如 `https://passkey-demo.example.workers.dev/#invite=<邀请码>[&u=<用户名>]`。这里的主机名是占位符，实际链接用该次部署的 ORIGIN（服务器只存哈希，丢了只能撤销重发）。邀请码放在 `#` 片段里，不会出现在服务器 / CDN 日志中；页面读取后立即用 `history.replaceState` 从地址栏去掉。受邀人打开链接 → 邀请码（和绑定的用户名）自动填好 → 完成 Turnstile → 创建 passkey。

不需要应急入口时：`npx wrangler secret delete ADMIN_TOKEN`（之后 Bearer 一律 401）。

轮换 token：重新生成 `.admin-token` 后执行 `npx wrangler secret put ADMIN_TOKEN < .admin-token`（会立即部署一个带新 secret 的版本）。

本地开发：在 `.dev.vars`（已 gitignore）中写入

```
RP_ID=localhost
ORIGIN=http://localhost:8787
TURNSTILE_SITEKEY=1x00000000000000000000AA
TURNSTILE_SECRET=1x0000000000000000000000000000000AA
TURNSTILE_ALLOW_TEST_KEYS=1
CHAL_HMAC_KEY=<openssl rand -base64 32 生成的本地随机值>
ADMIN_TOKEN=<本地专用随机值，与线上不同>
```

本地负责人：`wrangler.toml` 里的 `PRINCIPALS` 在本地同样生效；本地测试时可用 `npx wrangler dev --var PRINCIPALS:<本地用户名>` 覆盖（`tests/admin-ui.mjs` 就是这么做的）。

然后 `npx wrangler dev`。

## 测试

```bash
npx playwright install chromium
BASE_URL=http://localhost:8787 node tests/e2e.mjs            # 本地全流程（Turnstile 测试密钥）
BASE_URL=http://localhost:8787 node tests/conditional.mjs    # 本地条件式 UI
node tests/online-checks.mjs                                 # 线上：所有拒绝路径 + 浏览器登录路径 + 过期 + 429
node tests/admin-ui.mjs                                      # 本地：/admin 三种角色完整流程（脚本自己启动 wrangler dev，端口 8787 须空闲）
BASE_URL=https://passkey-demo.example.workers.dev node tests/admin-ui.mjs   # 占位主机名；换成自己的 ORIGIN 后，检查 /admin 拒绝路径 + 邀请链接自动填充 + Bearer
```

测试通过管理接口自动创建测试邀请（本地用 `.dev.vars` 的 `ADMIN_TOKEN`，线上用 `.admin-token`），不打印 token 和邀请码，结束前撤销所有未用掉的测试邀请并确认列表里一个都不剩。

- `tests/e2e.mjs`：CDP 虚拟认证器；注册 → excludeCredentials → 添加到 5 个 → 第 6 个被拒 → 退出 → 缺/伪造 Turnstile token → 已存在与不存在用户名响应一致 → verify 阶段统一错误 → 注册重放 → 可发现凭据登录 → 登录重放 → 陈旧 challenge → 篡改 payload / 签名 → 用途不匹配 → 过期 cookie（本地用 `.dev.vars` 的密钥伪造一个过期 cookie；线上等待 >5 分钟）→ Origin / 用户名 / 请求体大小 → 429。脚本会自动控制请求节奏，不触发自己的限流（429 测试放在最后）。
- 线上真实 Turnstile 在自动化浏览器中会出现“请验证您是真人”的交互式挑战，测试脚本不会自动点击或绕过它，因此线上注册需人工在真实浏览器中完成。
- 邀请相关（本地）：无邀请 / 格式错 / 不存在 / 已用过 / 已撤销 / 绑定用户名不符 / 已过期（TTL 60 秒，等待后再用）全部返回同一个 403 与同一段文字；有效邀请注册成功后立即从列表消失；注册失败不消耗邀请；options 之后撤销邀请 → verify 被拒且没有写入用户；邀请链接自动填充并从地址栏移除；管理接口无 token / 错 token / Basic 方案均 401；TTL 越界 400；管理接口 429。
- 线上无法自动完成“有效邀请 + 真实 Turnstile → 注册成功”这一步（不绕过 Turnstile、不留测试开关），需在真实设备上手动验证。
- `tests/admin-ui.mjs`（本地）：阶段 1 用 Bearer 邀请注册 4 个测试用户；阶段 2 重启 wrangler dev 并把其中一个设为负责人，然后验证：负责人在页面上分配成员主管 / 邀请人、签发（复制按钮、只显示一次、列表字段）、撤销、页面邀请完成注册后立即失效；邀请人只能撤销自己的、看不到成员区、不能授予任何角色；成员主管能撤销任何邀请、只能授予 / 移除邀请人、不能动负责人和自己；负责人不能改自己和 vars 里的负责人、不能通过接口授予负责人；无角色用户和被移除角色的用户页面 403、接口 401；未登录 401；跨站 Origin / Sec-Fetch-Site / 缺自定义头 403；PRINCIPALS 里的用户名不能被抢注；最后截图 `shots/admin.png`（截图前确认页面里没有邀请码 / token）。
- 测试结果见 `tests/logs/`。

## 已知限制 / 残余风险

- passkey 与 RP ID（域名）绑定：更换域名或 Worker 名称后已有 passkey 全部失效。
- **challenge 一次性**：challenge 由 Durable Object 原子消费（同一 challenge 第二次提交被拒，见 tests/session.mjs），不再依赖 KV `used:` 标记；signCount 检查只对会递增计数的认证器有效，很多平台认证器 / 同步 passkey 的计数恒为 0。
- **用户名枚举**：options 阶段已不泄露；但完成 Turnstile 并真正创建 passkey 的人，仍能从“新名字成功、旧名字失败”推断用户名是否存在——这是“用户名注册”模式固有的。
- **限流**按节点计数且近似；按 IP 计数可被大量 IP 绕过，NAT 后的用户共享额度。登录没有 Turnstile。
- 同一用户名的并发注册存在 KV 写入竞态（没有事务）。
- **邀请撤销 / 一次性的传播延迟**：KV 最终一致，撤销或用掉的邀请在其他 Cloudflare 节点上最长约 60 秒内仍可能被读到“有效”（同一节点通常立即生效）。极端情况下，同一个邀请在两地几乎同时完成注册可能注册出 2 个账号。（会话与 challenge 已迁到 Durable Object 强一致存储；邀请仍在 KV，此限制仍适用。）
- **邀请码泄露**：持有邀请链接的任何人都可在有效期内注册（绑定用户名可缩小影响）；请通过私密渠道发送、设置较短有效期，泄露后立即 `revoke`。
- **角色依赖 passkey 账号本身**：谁能登录负责人账号，谁就是负责人。`root_example` 被设为负责人，但 KV 里没有任何信息能证明它属于 Jack（见验收清单第 0 步）。
- **页面会话没有二次确认**：已登录的负责人离开电脑，别人可以直接签发邀请 / 分配角色（会话 4 小时）。
- **线上 KV list 有缓存（最终一致）**：撤销 / 新建邀请、分配 / 移除角色后，`/admin` 的列表可能要过几十秒才更新（实测约 30 秒，个别情况超过 90 秒，见 `tests/logs/admin-ui-online-run1-list-lag.log`）。安全上不受影响：校验邀请和角色都是按 key 直接读取，撤销后立即被拒绝（同一日志中的“撤销后的邀请被拒绝”通过）。但新建的邀请可能暂时无法从列表撤销，需要稍后重试。
- 没有审计日志：只记录了邀请的签发者、角色的授予者和时间；撤销、移除角色不留记录。
- 所有角色都能看到全部待使用邀请的编号和绑定用户名（看不到邀请码）。
- **ADMIN_TOKEN** 是长期静态 Bearer token：泄露即可创建邀请（不能改角色）。只存放在 `.admin-token`（600）与 Worker secret；疑似泄露时按上文轮换。管理接口没有 IP 白名单 / 二次验证。管理接口的 `RL_ADMIN` 限流同样按节点近似计数：线上实测复用连接时第 11 次即 429，但每次新建连接时 30 次都未触发，所以它只是减速带，真正的防线是 384 bit 随机 token + 常量时间比较。
- 没有账号恢复、删除 passkey / 账号的功能。
- 未做 attestation 校验（`attestation: 'none'`）。
- 线上地址是技术演示，注册仅限受邀；演示数据可能被清除。自行部署时把 `passkey-demo.example.workers.dev` 换成自己的主机名。

## 文档

- 会话安全与预设：[`docs/session.md`](docs/session.md)
- 角色、有效期、模板、已关闭的入口：[`docs/roles-and-templates.md`](docs/roles-and-templates.md)
- 兜底恢复（仅设计，接口返回 501）：[`docs/recovery.md`](docs/recovery.md)
- 存储迁移：[`docs/migration.md`](docs/migration.md)
- 仓库分层、发布、部署权限与之后的 CD 步骤：[`docs/workflow.md`](docs/workflow.md)
- 开发流程：[`AGENTS.md`](AGENTS.md)、[`docs/workflow-v2.md`](docs/workflow-v2.md)、[`docs/specs/`](docs/specs/)
- 自查安全评审：[`docs/security-review.md`](docs/security-review.md)；漏洞报告：[`SECURITY.md`](SECURITY.md)

## 许可证

MIT，见 [`LICENSE`](LICENSE)。
