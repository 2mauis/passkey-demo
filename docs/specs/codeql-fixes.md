# CodeQL 首次扫描告警修复

## 背景/目标
public 仓首次 CodeQL（javascript-typescript）扫描报告 27 条 open alert，全部位于 scripts/ 与 tests/，src/ 为 0。
本规范限定修复范围：修真实问题，测试代码中无法消除的模式在 PR 中说明并按"用于测试"处理。

## 非目标
不改 src/ 业务逻辑；不改部署、secret、仓库设置；不关闭 CodeQL 查询或用 paths-ignore 屏蔽目录。

## 修复范围
- js/regex/missing-regexp-anchor（scripts/privacy-scan.mjs）：跳过规则改为按路径段判断，不再用未锚定的正则分支。
- js/file-system-race（scripts/invite.mjs）：token 文件先 open 再对同一 fd 做 fstat 和读取，消除 stat→read 的检查/使用竞态。
- js/file-access-to-http（scripts/invite.mjs、tests/e2e.mjs、tests/conditional.mjs、tests/online-checks.mjs）：管理 token 从本地文件读出后作为 Bearer 发给自己的 Worker 是设计行为；
  修复为非 localhost 目标必须是 https，否则拒绝发送。CodeQL 仍可能按数据流报告，剩余条目在 public 仓以"used in tests / won't fix"附理由处理。
- js/insecure-randomness（tests/）：测试用户名后缀改用 node:crypto randomBytes。

## 验收测试清单
- [x] `tests/workflow-scripts.mjs`「privacy：跳过 node_modules / .wrangler / package-lock.json 与图片，不误跳相似文件名」。
- [x] `tests/workflow-scripts.mjs`「invite：非 localhost 的 http 目标被拒绝（不发送 token）」。
- [x] tests/ 中不再出现非加密随机数（`tests/workflow-scripts.mjs`「tests 不使用非加密随机数」）。
- [x] 合并后 public 仓 CodeQL 重跑，回报剩余 open alert 数量与分类（2026-11-05 核对：public main 上 0 个 open alert）。

## 风险
CodeQL 对 file-access-to-http 的判断基于数据流，https 约束不一定让告警消失；处理理由需公开说明。

## 是否重大改动
否。

## 第二轮：monorepo 之后重新出现的 5 条

public 快照把 `tests/` 挪到 `apps/idp/tests/`，并新增 `scripts/oidc-keygen.mjs`、`apps/idp/tests/oidc.mjs`。旧路径上的处理对不上新路径，public `48f782a`（源 `7d85db2`）重新打开 5 条。本轮在 staging 改代码，不关闭查询，也不用 paths-ignore。

### 告警与修法
- #28 `js/file-system-race`，`scripts/oidc-keygen.mjs`：不再 `existsSync` 之后按路径 `readFileSync` / `writeFileSync`。`O_RDWR|O_CREAT|O_NOFOLLOW` 只 open 一次，随后 `fstat`、`readSync`、`ftruncate`、`writeSync`、`fchmod` 都用这个 fd。最后一段是符号链接时 open 失败，私钥不会写到被调包的目标。
- #29–#32 `js/file-access-to-http`，`apps/idp/tests/conditional.mjs`、`e2e.mjs`、`oidc.mjs`、`online-checks.mjs`：管理 token 改经 `scripts/load-admin-token.mjs`。该函数先 `assertSafeBase`（非 https 且非本机回环的 http 直接拒绝，此时还没有 open），再对同一个 fd 用 `readSync` 读进 Buffer，只返回通过 `[\x21-\x7e]{32,512}` 的 token。dotenv 模式只取 `ADMIN_TOKEN` 行，不把同文件里的签名私钥或 HMAC 密钥交给 `fetch`。这四个测试不再 `readFile` / `readFileSync` 之后把结果拼进 Bearer。`online-checks.mjs` 的 `safe-base` 引用从 monorepo 搬家后的错误相对路径改回仓库根的 `scripts/`。

### 验收测试清单
- [x] 需求：不安全的 http 目标在打开 token 文件之前拒绝；测试：`tests/workflow-scripts.mjs` →「token：非 localhost 的 http 在打开文件前拒绝」。
- [x] 需求：localhost / 127.0.0.1 仍能读取 `.admin-token`，https 仍只取出 dotenv 的 `ADMIN_TOKEN`；测试：`tests/workflow-scripts.mjs` →「token：localhost 与 127.0.0.1 读取原始 token 文件」「token：https 只取出 dotenv 的 ADMIN_TOKEN」。
- [x] 需求：过短内容或整份 dotenv 不能当作 Bearer 发送；测试：`tests/workflow-scripts.mjs` →「token：过短内容与整份 dotenv 都不能当 token 发送」。
- [x] 需求：四个测试文件的管理 token 不再由 `readFile` / `readFileSync` 进入请求；测试：`tests/workflow-scripts.mjs` →「管理 token 不再从文件读进请求：conditional.mjs / oidc.mjs / online-checks.mjs / e2e.mjs」。
- [x] 需求：`oidc-keygen` 保留其它 dotenv 行、权限 0600、再次运行只替换密钥行、不打印私钥、不存在则创建、拒绝符号链接；测试：`tests/workflow-scripts.mjs` →「oidc-keygen：保留其它行、0600、再次运行只替换密钥行且不打印私钥」「oidc-keygen：文件不存在时创建且权限 0600」「oidc-keygen：拒绝顺着符号链接写入」。

### 本轮风险
用与 public workflow 相同的 CodeQL bundle（codeql-bundle-v2.27.3）在本地重跑这两条查询：`js/file-system-race` 为 0；`js/file-access-to-http` 只剩 `scripts/invite.mjs`（第一轮已说明这条数据流可能仍然报出，不在本轮 5 条之内）。`admin-ui.mjs`、`session.mjs`、`expiry-roles.mjs` 这次没有被这两条查询报出。`e2e.mjs` 仍用 `readFileSync` 读取本地 `CHAL_HMAC_KEY` 来签过期 cookie，查询没有把该读取算进告警。staging 的 codeql job 仍会被 `repository.private` 跳过，public 重扫要等快照发布之后。

### 是否重大改动
否。只动密钥生成脚本、测试里的 token 读取和本 spec，不改 IdP 接口、不部署、不发布 npm。
