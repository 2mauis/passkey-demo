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
