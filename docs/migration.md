# 迁移说明（仅文档，不执行）

## 本版本引入的状态迁移

| 数据 | 旧位置 | 新位置 | 处理 |
|---|---|---|---|
| 会话 | KV `sess:<sid>` | DO `s:<sid>` | 不迁移；部署后旧会话全部失效，用户重新登录 |
| challenge 防重放 | KV `used:<c>` | DO `ch:<c>` 一次性 | 无需迁移（短 TTL） |
| OTP 剩余次数 | KV | DO `otp:<u>` 配额 | 部署前未用完的 OTP 账户需重新套用模板（演示环境可接受） |
| 登录环境历史 | 无 | DO `env:<u>` | 新数据 |
| 用户、凭据、角色、模板、审计 | KV | KV（不变） | 无 |

## 步骤（需 Jack 批准）

1. 线上 KV 备份（在 box 上用已有 wrangler 登录导出，不进 CI）。
2. `wrangler deploy` 带 `[[migrations]] tag="v1-authstate"`。
3. 线上自检（注册、登录、step-up、预设读取）。
4. 失败：`wrangler rollback` 到上一版本；DO 迁移本身不会被回滚，但旧版本不读 DO，因此功能上等价回退；KV 未改动。

## KV → D1（P1 代码路径，不在本仓库执行）

用户、凭据、邀请、角色、拒绝项、过期、模板、审计可以由 `apps/idp/src/store.js` 的 `migrateKvToD1` 从 KV 复制到 D1（表结构见 `apps/idp/schema.sql`）。未绑定 `DB` 时 IdP 仍读写 KV，现有本地测试不变。邀请在绑定 D1 后用单条 `DELETE … RETURNING` 消费。

上线前由 Jack 做 KV 只读备份（命令见上文，导出文件放在仓库外并加密），再在批准后的维护窗口执行迁移。本变更不调用 wrangler、不读不写线上 KV 或 D1。

旧 passkey 不能换 RP ID。过渡用 `POST /api/migrate/ticket`（已登录且 5 分钟内做过 step-up）签发绑定 `userID` 的一次性票据，5 分钟内在新站 `POST /api/migrate/redeem` 消费，之后为同一账户登记新 passkey。

## 迁移到其它平台（平台中立概述）

KV → 任意键值存储；DO → 带事务的数据库（如 PostgreSQL 行锁 / Redis Lua 原子操作）；Rate Limiting 绑定 → 网关限流；Turnstile → 任意人机验证。WebAuthn 依赖 RP ID，换域名意味着全部 passkey 失效，必须重新注册。
