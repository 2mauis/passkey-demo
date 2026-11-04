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

## 之后的 CD 步骤（今天全部不做，由 Jack 执行或批准）

1. Jack 在 Cloudflare 创建 API token：只含 **Account · Workers Scripts:Edit**，账户范围限定为单个账户；不加 Zone、KV、User 权限；设到期时间。
2. 在 public 仓（或 staging）的 `deploy` environment 中添加 secrets `CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_ACCOUNT_ID`；environment 设 required reviewer = Jack。
3. 在 box 上用现有 wrangler 登录做线上 KV 备份（`wrangler kv key list` + 逐键导出到 box 本地加密目录），不进 CI。
4. 启用 CD：先决定线上配置来源——公开仓的 wrangler.toml 是占位值（example 子域、全 0 KV id），`deploy.yml` 检测到占位值会拒绝部署；需要 Jack 选择在 deploy environment 中生成私有配置或在 staging 保留真实配置（属于重大改动）。然后手动触发 `deploy.yml`（workflow_dispatch）；它先 `wrangler deploy --dry-run`，再 `wrangler deploy`。
5. 线上自检（`tests/online-checks.mjs` 的只读部分 + 手动注册 / 登录 / step-up）；失败立即 `wrangler rollback` 到上一版本并报告。

`deploy.yml` 在缺少 `CLOUDFLARE_API_TOKEN` 时预检步骤输出 skip 并以 0 退出，后续步骤全部跳过。
