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

## 迁移到其它平台（平台中立概述）

KV → 任意键值存储；DO → 带事务的数据库（如 PostgreSQL 行锁 / Redis Lua 原子操作）；Rate Limiting 绑定 → 网关限流；Turnstile → 任意人机验证。WebAuthn 依赖 RP ID，换域名意味着全部 passkey 失效，必须重新注册。
