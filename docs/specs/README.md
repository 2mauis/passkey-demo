# docs/specs

每个重大功能一份 spec（按 TEMPLATE.md）。CI 的 `spec-requires-tests` 要求：新增或修改 spec 的 PR 同时改动 `tests/*.mjs`、`apps/idp/tests/*.mjs` 或 `packages/*/tests/*.mjs`。删除 spec 不触发；TEMPLATE.md 与本文件豁免。测试质量由评审把关，脚本只检查文件集合。
