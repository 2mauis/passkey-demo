# 兜底恢复（重建管理员）——仅设计，未实现

> **状态：NOT IMPLEMENTED。** 相关接口 `/api/admin/recovery*`、`/api/recovery/redeem` 以及恢复码注册路径一律返回 `501 {disabled:true}`，有测试证明（tests/expiry-roles.mjs「恢复默认关闭…→ 501」与第 7 节）。实现属于重大改动（安全边界），需要 Jack 批准。

## 问题

负责人只来自 PRINCIPALS。若负责人丢失全部 passkey，页面上没有任何人能恢复其管理能力。

## 参考来源

- NIST SP 800-63B-4 账户恢复相关章节：https://pages.nist.gov/800-63-4/sp800-63b.html
- OWASP Forgot Password Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- OWASP Multifactor Authentication Cheat Sheet（恢复与重置）：https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- W3C WebAuthn Level 3：https://www.w3.org/TR/webauthn-3/

## 选择的设计（待批准）

1. **首选：多 passkey。** 负责人注册至少两把 passkey（不同设备 / 同步提供方），这是零新攻击面的方案，已可用。
2. **离线运维路径（不经页面）：** 由持有 Cloudflare 账号权限的人修改 `PRINCIPALS` 或用 `wrangler` 清理该用户的凭据后重新邀请。权限边界即 Cloudflare 账号本身；操作写入运维记录。
3. **（预留，未实现）一次性恢复码：** 由 `RECOVERY_ISSUER_TOKEN` 持有人签发，DO 原子消费、失败计数与锁定、24 小时冷却期内向原账户审计 + 通知、可由原负责人会话取消；兑换后只能注册新 passkey 并吊销全部旧会话。

## 拒绝的方案

- 邮件 / 短信重置：本项目不收集联系方式；且属于弱于 passkey 的降级路径。
- 安全问题：OWASP 明确不推荐。
- 页面上“任何管理员可提升负责人”：等于新增提权入口，违反本次范围。

## Cloudflare 能力

DO 提供原子一次性消费与计数；Workers Rate Limiting 绑定提供按 IP 节流；secret 存签发 token。其它平台对应：Redis/数据库事务 + 行锁、KMS/Secrets Manager。

## 若批准实现，需要

spec（docs/specs/recovery.md）+ 先红后绿测试 + 安全评审 + 部署批准；把 `RECOVERY_IMPLEMENTED` 改为配置项默认关闭。
