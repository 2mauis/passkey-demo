# 会话、重新验证（step-up）与异常登录

## 存储

会话存在 Durable Object `AuthState`（SQLite 存储，单实例 `idFromName('global')`），不再用 KV：KV 最终一致，吊销可能延迟最多约 60 秒，而 DO 是强一致的，删除立即生效。cookie 只携带随机 sid：`__Host-` 前缀、`HttpOnly`、`Secure`、`SameSite=Lax`、`Path=/`。

会话记录：`username, createdAt, lastSeen, absAt, uvAt, risk`，并维护 `us:<user>` 索引（最近 50 个），用于“吊销某用户全部会话”。

## 时长预设（root 可切换，默认 recommended）

| 预设 | 普通账户 绝对/空闲 | 管理员（有角色） | 临时账户（设了过期） |
|---|---|---|---|
| recommended（默认） | 7 天 / 24 小时 | 12 小时 / 30 分钟 | 1 天 / 1 小时 |
| aal2 | 24 小时 / 1 小时 | 同左 | 同左 |
| relaxed | 30 天 / 7 天 | 同左 | 同左 |

依据：NIST SP 800-63B-4（https://pages.nist.gov/800-63-4/sp800-63b.html）第 2 章各保证级别的重新认证要求——AAL2 绝对上限 24 小时、无活动 1 小时；AAL1 绝对上限 30 天且无活动超时为可选（因此 relaxed 的 7 天空闲是本项目自选值，不是标准要求）。passkey + UV 属于 AAL2 级认证器，recommended 对普通账户放宽到 7 天是可用性取舍，已在此记录。

规则：
- 生效值 = min(会话创建时的绝对过期, createdAt + 当前预设绝对时长)。收紧立即作用于已有会话，并写回会话表（单向棘轮）；放宽**不会**延长已有会话。
- 空闲过期按 `lastSeen` 滑动，30 秒节流写回。
- 每次请求都检查账户过期；账户过期立即删除会话。
- 角色变化（授予 / 撤销 / 改级）立即吊销被操作者的全部会话。
- 切换预设：`POST /api/admin/session-preset`，仅 root，需 step-up，写审计 `session.preset`。存 KV `cfg:session_preset`（低频配置，最终一致可接受）。

## step-up（重新验证）

敏感操作要求 5 分钟内有一次带 UV 的 passkey 验证（`uvAt`）：建邀请（会话方式）、授予 / 撤销角色、权限覆盖、添加 passkey、切换预设。否则返回 `403 {stepUp:true}`，前端自动调用 `/api/stepup/options` → `/api/stepup/verify` 后重试。

## 强制 UV 与 challenge 一次性

注册与登录都 `userVerification: 'required'`，服务端 `requireUserVerification: true` 并再次核对 authenticatorData 的 UP/UV 标志。challenge 在 DO 里以 `ch:<c>` 签发、`consume` 原子取出并删除，第二次提交返回 400。

## 异常登录

信号：`request.cf.country`、`request.cf.asn`、IP 前缀（IPv4 /24、IPv6 /48）与 UA 家族的 HMAC 指纹（不存原始 IP）。历史保存 30–90 天（`RISK_RETENTION_DAYS`，默认 60，越界钳制）。
- 新国家或新 ASN：允许登录，但会话 `risk='new_env'`、`uvAt=0`，敏感操作必须 step-up；审计 `risk.new_env {notify:true}`。
- 不可能的旅行：`RISK_TRAVEL_WINDOW_MIN`（默认 60 分钟）内出现不同国家 → 拒绝登录（403）并吊销该用户全部会话，审计 `risk.impossible_travel {notify:true}`；被拒的这次不写入历史。
- `notify:true` 供后续通知通道消费；当前没有对外发送通知。
- 本地测试头 `X-Test-Country/ASN/IP` 仅在 `RP_ID=localhost` 且 `RISK_TEST_HEADERS=1` 时生效。

## 部署步骤（需 Jack 批准，今天不做）

新增 DO 绑定与迁移 `v1-authstate`（`new_sqlite_classes`）是不可回滚到“无 DO”的变更：回滚 Worker 版本时迁移不会撤销。部署前须：KV 备份 → 部署 → 线上自检 → 失败回滚（见 docs/workflow.md「之后的 CD 步骤」）。部署后所有旧 KV 会话失效，用户需要重新登录一次。
