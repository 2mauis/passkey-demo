# 自查安全评审（本地，非第三方审计）

| # | 项 | 结论 / 证据 |
|---|---|---|
| 1 | 注册仅限邀请 + Turnstile + 限流 | 已有；tests/e2e.mjs、admin-ui.mjs |
| 2 | 强制 UV，服务端二次核对 UP/UV 标志 | tests/session.mjs「认证器未做用户验证（UV=false）→ 登录失败」 |
| 3 | challenge 一次性（DO 原子消费） | session.mjs「同一 challenge 第二次提交被拒」 |
| 4 | 会话服务端存储、可立即吊销；角色变化吊销 | session.mjs「角色变化：被授予者的所有会话被吊销」 |
| 5 | 绝对 + 空闲过期；收紧单向 | session.mjs「放宽到 relaxed 不会延长已有会话」 |
| 6 | 敏感操作 step-up（5 分钟） | session.mjs「root 未 step-up 切换 → 403 且带 stepUp 标志」 |
| 7 | cookie `__Host-`/HttpOnly/Secure/SameSite=Lax；写接口校验 Origin + 自定义头 | session.mjs「会话 cookie…」；admin-ui 跨站用例 |
| 8 | 异常登录（新环境 step-up、不可能旅行拒绝并吊销） | session.mjs 相关用例；tests/risk.mjs |
| 9 | 审计不含 token / 邀请码 / 原始 IP | expiry-roles「审计日志不含 token / 邀请码明文」；session.mjs「审计不含测试用原始 IP」 |
| 10 | 无新增管理员创建入口；恢复 501 | docs/roles-and-templates.md「已关闭的入口」 |
| 11 | SAST（semgrep）、gitleaks、隐私扫描 | CI 与 PR 记录 |

已知取舍 / 剩余风险：
- SameSite 从 Strict 改为 Lax，是为了从邮件 / 外链进入时保持登录；CSRF 由 Origin 校验与 `X-PK-Admin` 自定义头承担。
- 风险信号依赖 `request.cf`，VPN 会造成误报（需要 step-up）或漏报。
- 预设配置存 KV（最终一致）：切换后最多约 60 秒内个别边缘仍用旧预设。
- DO 单实例 `global`：演示规模足够；高并发需要按用户分片。
- 本地 miniflare 与线上行为差异（限流、DO 位置）未在线上验证。
