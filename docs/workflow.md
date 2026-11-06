# 仓库分层、发布与部署

## 两个仓库

| 仓库 | 可见性 | 用途 |
|---|---|---|
| `2mauis/passkey-demo-staging` | private | 开发、PR、CI、Codex 评审、合并 |
| `2mauis/passkey-demo` | public | 只接收白名单快照（每次一个 orphan 提交，不带开发历史）；CodeQL 在这里运行 |

本地开发仓的旧历史（含线上真实配置与日志）**永远不推送**。staging 是新建的干净历史：main 只有一个脱敏的基础提交；功能通过 feature 分支 + PR 合入。

取舍（参考 box 上的分层调研）：个人 private 仓没有 CodeQL / secret scanning / required reviewers（需 GHAS 或付费组织）；public 仓免费提供。代价：CodeQL 首次结果出现在代码已公开之后——因此发布前必须在 staging 跑完 semgrep、gitleaks、隐私扫描，并人工审查。private 仓 Actions 消耗账户包含分钟数。

## 公开快照（publish）

- 白名单：`.github/publish-allowlist.txt`，逐行 glob，未列出的文件一律不发布（tests/logs、share、shots、.dev.vars、.wrangler 等）。
- `scripts/publish-snapshot.sh <目标仓库目录或 URL> <分支>`：按白名单从 HEAD 导出 → 重新跑 privacy-scan 与 gitleaks → `git init` 新仓库，单个 orphan 提交 → 普通 push 到目标分支（目标分支必须不存在或由上一次快照生成；从不 `--mirror`、`--all`、`--force`）。
- `.github/workflows/publish.yml` 只有 `workflow_dispatch`，引用的 secret 名为 `PUBLIC_REPO_DEPLOY_KEY`（本次**未配置**，workflow 缺少该 secret 时预检退出 0）。
- 首次发布：public 仓为空，推送一个 orphan 单提交。后续同步不 force push：在 public main 之上提交一个“整树替换为新白名单快照”的新提交（父提交只是上一次快照），仍不带 staging 历史。

## 部署权限（已核对 Cloudflare 文档）

来源：https://developers.cloudflare.com/workers/authorization/workers/ 、https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/

| 步骤 | 需要的权限 | 说明 |
|---|---|---|
| `wrangler deploy`（已存在的 Worker） | Account · Workers Scripts:Edit | 等同 Workers 产品范围 Editor |
| versions upload / deploy、`wrangler rollback` | 同上 | |
| `wrangler secret put/delete` | 同上 | CI 不做 |
| KV / DO / Rate Limiting 绑定 | 无额外资源权限 | 绑定随脚本上传 |
| DO 迁移 `new_sqlite_classes` | 文档未单列；**推断**为 Workers Scripts:Edit 覆盖 | 首次部署时验证，若 403 则停止并报告 |
| 新建 Worker | Admin | 不需要（Worker 已存在） |
| routes / 自定义域名 | Zone · Workers Routes:Edit | 不需要（只用 workers.dev） |
| KV 读写 / 备份 | Workers KV Storage | **不给 CI**；备份只在 box 上用已有 wrangler 登录做 |

`CLOUDFLARE_ACCOUNT_ID` 必须显式设置，避免 wrangler 调 `/memberships`（该调用需要额外权限，见 workers-sdk issue #10466）。workflow 不运行 `wrangler whoami`。

## 之后的 CD 步骤（配置在部署时注入；触发仍由 Jack 批准）

公开仓与 staging 提交的 `apps/idp/wrangler.toml` 保持 example 占位（`name = "pkauth-idp"`、`RP_ID` / `ORIGIN` 为 example.com、`PRINCIPALS = "root_example"`、KV id 全 0、Turnstile 测试 sitekey `1x00000000000000000000AA`）。真实值只放在 staging 的 `deploy` environment secrets 里，由 `deploy.yml` 在 runner 上注入工作副本，不提交。

1. Jack 在 Cloudflare 创建 API token：只含 **Account · Workers Scripts:Edit**，账户范围限定为单个账户；不加 Zone、KV、User 权限；设到期时间。
2. 在 staging 的 `deploy` environment 中添加 secrets `CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_ACCOUNT_ID`，以及第 4 步的 `DEPLOY_*`；environment 设 required reviewer = Jack。不要把这些值写入仓库。
3. 在 box 上用现有 wrangler 登录做线上 KV 备份（`wrangler kv key list` + 逐键导出到 box 本地加密目录），不进 CI。
4. 手动触发 `deploy.yml`（workflow_dispatch）。`go=1` 时 workflow 只替换工作副本里的已知占位行：
   - `DEPLOY_WORKER_NAME` → 顶层 `name`。注入只接受已存在的生产 Worker `passkey-demo`（`pkauth-idp` 或其它名字都会失败），因此不会新建 Worker，也不会改写同账户里的另一个脚本。
   - `DEPLOY_RP_ID` → `[vars].RP_ID`
   - `DEPLOY_ORIGIN` → `[vars].ORIGIN`
   - `DEPLOY_RP_NAME` → `[vars].RP_NAME`
   - `DEPLOY_PRINCIPALS` → `[vars].PRINCIPALS`（逗号分隔，用户名规则与页面一致；占位值 `root_example` 会被拒绝）
   - `DEPLOY_KV_ID` → `[[kv_namespaces]]` 里绑定 `KV` 的 `id`（使用已有 namespace，不新建）
   - `DEPLOY_TURNSTILE_SITEKEY` → `[vars].TURNSTILE_SITEKEY`
   任一 `DEPLOY_*` 为空则失败退出。注入后再次检查：若 `name` 仍是 `pkauth-idp`，或 `RP_ID` / `ORIGIN` 仍含 `example.com`，或 KV `id` 仍是全 0，或 `PRINCIPALS` 仍是 `root_example`，或 Turnstile 仍是测试密钥 `1x00000000000000000000AA`，则拒绝部署。限流 `namespace_id` `26102601`–`26102603` 与 Durable Object 绑定 `STATE` / `AuthState`、迁移 tag `v1-authstate` 必须与生产一致；注入不改这些段，也不新增 DO class 或迁移 tag。通过后对注入后的 `apps/idp/wrangler.toml` 先 `wrangler deploy --dry-run`，再 `wrangler deploy`。workflow 不打印 secret 值。
5. 线上自检（`apps/idp/tests/online-checks.mjs` 的只读部分 + 手动注册 / 登录 / step-up）；失败立即 `wrangler rollback` 到上一版本并报告。

`deploy.yml` 在缺少 `CLOUDFLARE_API_TOKEN` 或 `CLOUDFLARE_ACCOUNT_ID` 时预检步骤输出 skip 并以 0 退出，后续步骤全部跳过。
