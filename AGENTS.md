# 项目施工说明（AGENTS.md）

> 来源：按 quest-vr-assistant 仓的 AGENTS.md / docs/workflow-v2.md 改写（只读参考，未修改源仓库）。
> 本仓库是 Cloudflare Worker + KV + Durable Object 的 passkey 邀请制登录演示，不含任何头显 / 语音 / MCP 内容。

## 开工前

1. 先读 README、docs/workflow-v2.md、docs/workflow.md、docs/session.md、docs/roles-and-templates.md、docs/recovery.md。
2. `git status` 检查工作区；保留不属于本次任务的修改，只 `git add` 自己改的文件。
3. 本地开发：`cp apps/idp/.dev.vars.example apps/idp/.dev.vars` 并填两个本地随机密钥，`node scripts/oidc-keygen.mjs apps/idp/.dev.vars` 生成 OIDC 签名私钥；`npm ci && npm run build && npm run dev`。

## 硬边界（未经 Jack 当次批准一律不做）

- `wrangler deploy` / `wrangler rollback` / `wrangler secret put|delete` / 改线上 KV / 读线上 KV。
- 新增或改动 GitHub secrets、deploy key、仓库设置、分支保护、required checks。
- 新增任何“创建管理员 / 提升为负责人”的入口（负责人只由 wrangler.toml 的 PRINCIPALS 决定）。
- `git push --force`、`--mirror`、`--all`、`gh pr merge --admin`、`--no-verify`。
- 削弱或跳过 CI 检查以求通过。

## 合并与同步

- staging 合并一律：`gh pr merge --squash --match-head-commit <sha> --author-email 2908005+2mauis@users.noreply.github.com`（不带 `--author-email` 会把作者记成执行合并的账号并附 Co-authored-by）。
- staging → public 只在 box 上手动运行 `scripts/publish-snapshot.sh`；不配置 deploy key，不在 Actions 放推送 public 的 secret。

## 公开仓库与隐私

- 文件、提交信息、PR 正文中不得出现真实 workers.dev 子域、KV / 账号 id、生产 Turnstile sitekey、个人用户名、邮箱、IP、主机名、内网域名、token、密钥、原始线上日志。
- 用 `example.com`、`passkey-demo.example.workers.dev`、`<PLACEHOLDER>`、全 0 的 id；本机用 `localhost`；测试 IP 只用文档保留段 192.0.2.0/24、198.51.100.0/24、203.0.113.0/24。
- 提交前：`node scripts/privacy-scan.mjs`；PR 正文：`node scripts/privacy-scan.mjs --stdin < body.md`。
- 不写 AI 花费、token 用量、模型档位或运行耗时。

## 署名

- 本仓库由 Grok Bot 提交时：author 与 committer 均为 `Grok Bot Friday (for 2mauis) <2908005+2mauis@users.noreply.github.com>`，提交信息末尾 trailer `Agent: grok-code-assistant`。
- 其它代理沿用 docs/workflow-v2.md 的署名表；不加 Co-authored-by。
- 本地钩子：`git config core.hooksPath .githooks`（可选，由用户自己开启）。

## 测试

| 命令 | 内容 |
|---|---|
| `npm run test:unit` | core、workers SDK、IdP 纯函数、workflow 脚本 |
| `node tests/workflow-scripts.mjs` | 隐私扫描 / trailer / spec 检查脚本 |
| `node apps/idp/tests/session.mjs` | 会话预设、step-up、会话吊销、异常登录、强制 UV、challenge 一次性（自启 wrangler dev） |
| `node apps/idp/tests/expiry-roles.mjs` | 账户过期、分级、权限覆盖、模板、审计、恢复 501（自启 wrangler dev） |
| `node apps/idp/tests/admin-ui.mjs` | 管理页角色与越权（自启 wrangler dev） |
| 在 `apps/idp` 里 `npx wrangler dev` + `BASE_URL=http://localhost:8787 node tests/e2e.mjs` | 端到端注册 / 登录 |

自启 wrangler dev 的套件占用 8787 端口，须依次运行。
