#!/usr/bin/env node
// pkauth check-config：校验当前进程环境里的 PKAUTH_*（不连网、不读密钥值到日志）。
import { loadConfig } from '@pkauth/core';

const cfg = loadConfig(process.env);
if (!cfg.ok) {
  console.error(`pkauth check-config: missing or invalid ${cfg.missing.join(', ')}`);
  process.exit(1);
}
console.log('pkauth check-config: ok');
