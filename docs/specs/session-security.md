# 会话安全：预设、step-up、会话表、异常登录、强制 UV

## 背景/目标
KV 会话无法立即吊销、challenge 防重放依赖最终一致的 KV；需要强一致会话表、可切换时长预设、敏感操作重新验证与异常登录处理。详见 docs/session.md。

## 非目标
对外发送通知；按用户分片 DO；线上部署。

## 不变量
- 放宽预设不延长已有会话；收紧立即生效。
- 角色变化与不可能旅行吊销该用户全部会话。
- 审计不含原始 IP、token、邀请码。
- 测试头只在 RP_ID=localhost 且 RISK_TEST_HEADERS=1 时生效。

## 验收测试清单
- [x] 三档预设数值；`tests/session.mjs`「推荐：普通 7d/24h、管理员 12h/30m、临时 1d/1h」「NIST AAL2：24h/1h（各档）」「宽松：30d/7d（各档）」；本地 miniflare。
- [x] 分档：「普通账户会话：绝对 ≈ 7 天，空闲 24 小时」「管理员档（root）：绝对 ≈ 12 小时，空闲 30 分钟」「临时档：设了账户过期后，已有会话收紧为 绝对 1 天 / 空闲 1 小时」。
- [x] 角色变化吊销：「角色变化：被授予者的所有会话被吊销（服务端会话表）」。
- [x] 切换权限与 step-up：「非 root 切换预设 → 403」「root 未 step-up 切换 → 403 且带 stepUp 标志」「root step-up 后切换到 aal2 → 200」「未知预设 → 400」。
- [x] 收紧 / 不延长：「已有普通会话被收紧到 min(7 天, 24 小时) 与空闲 1 小时」「放宽到 relaxed 不会延长已有会话（仍 ≤ 24 小时）」。
- [x] UV 与 challenge：「登录 options 要求 userVerification=required」「同一 challenge 第二次提交被拒（DO 原子作废，防重放）」「认证器未做用户验证（UV=false）→ 登录失败」。
- [x] 异常登录：「新 ASN 登录：会话标记 new_env，需要 step-up」「新环境会话添加 passkey（敏感操作）→ 403 stepUp」「step-up 后风险标记清除」「10 分钟内从 TW 到 JP：不可能的旅行 → 登录 403，已有会话全部吊销」；纯函数见 `tests/risk.mjs`。
- [x] OTP 额度与风险拒绝顺序：「OTP 账户不可能的旅行 → 403，且一次性登录额度未被消耗（剩余 1 次）」「OTP 账户回到原地区后仍可用唯一一次登录，之后再登录被拒」（Codex 评审 P2；旧代码下这两项失败，已本地对照验证）。
- [ ] 撤销签发者全部待使用邀请时跟随 KV list cursor 翻页（Codex 评审 P2）：代码已改，>1000 条邀请的场景尚无自动化测试（本地限流下造数成本过高），仅代码审阅。
- [x] 会话上限与清理：`tests/state-unit.mjs`「会话超过上限 50：被挤出索引的最旧会话同时删除」「超过上限后吊销用户：没有任何存活会话」「alarm 删除放弃的过期 challenge，保留未过期的」「alarm 删除过期环境历史与过期会话，并清理空的用户索引」（Codex 评审 P1/P2）。
- [x] 审计与 cookie：「审计：session.preset / session.stepup / risk.new_env / risk.impossible_travel / role.set」「审计不含测试用原始 IP」「风险事件带 notify 标记（供通知通道消费）」「会话 cookie：__Host-、HttpOnly、Secure、SameSite=Lax」。

## 风险
线上未验证；DO 迁移需批准；VPN 误报。回退：wrangler rollback（DO 迁移不回滚）。

## 是否重大改动
是：安全边界与存储迁移。代码合入 staging 已获本次任务授权；**部署未获批准，未执行**。
