# pkauth P0 仓库重组

## 背景/目标

把 passkey-demo staging 收成 monorepo，并把 `feat/oidc-phase1`（`29d09b1`，已在当前 main 之上）作为 IdP 起点放进 `apps/idp`。不部署、不改线上 KV / D1。

布局：

- `apps/idp`：现有 Worker、页面、OIDC、测试、`wrangler.toml`
- `packages/core`：`@pkauth/core`
- `packages/workers`：`@pkauth/workers`
- `packages/node`、`packages/cli`：P4 之前的最小占位
- `examples/ainews-like`：三行胶水示例

## 非目标

不发布 npm。不执行 KV 备份或 D1 迁移。不合并、不部署。

## 不变量

- 现有 IdP 测试在 `apps/idp` 下仍能启动本地 wrangler（工作目录由测试文件自己解析）。
- 未绑定 `DB` 时账户数据仍在 KV。
- `spec-requires-tests` 同时接受根目录、`apps/idp/tests` 和 `packages/*/tests` 里的测试文件。

## 验收测试清单

- [ ] 需求：纯函数测试在新路径通过；测试：`apps/idp/tests/risk.mjs`、`apps/idp/tests/state-unit.mjs`、`apps/idp/tests/oidc-unit.mjs`；验证面：本地 Node。
- [ ] 需求：spec 检查认新测试路径；测试：`tests/workflow-scripts.mjs`「spec：改 spec 同时改 tests/*.mjs 通过」；验证面：本地 Node。

## 风险

移动路径后，若 CI 仍从仓库根启动 wrangler，会找不到 `wrangler.toml`。工作流已改为在 `apps/idp` 下执行。线上未验证。

## 是否重大改动

是：跨目录重组。合并与部署需 Jack 批准。本变更不部署。
