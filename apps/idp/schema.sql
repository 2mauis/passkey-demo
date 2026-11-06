-- pkauth IdP：用户、凭据、邀请、角色、拒绝、过期、模板、审计。
-- 会话、challenge、授权码、refresh、配额仍在 Durable Object。tenant_id 单租户固定 default（D10）。
-- 本文件只定义结构。不在 CI 或本 PR 里对任何线上 D1 执行。

CREATE TABLE IF NOT EXISTS records (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  k TEXT NOT NULL,
  v TEXT,
  expiration INTEGER,
  metadata TEXT,
  PRIMARY KEY (tenant_id, k)
);

CREATE INDEX IF NOT EXISTS records_prefix ON records (tenant_id, k);
