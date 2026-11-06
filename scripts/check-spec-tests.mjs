#!/usr/bin/env node
// spec-requires-tests：新增或修改 docs/specs/*.md（TEMPLATE.md、README.md 除外）时，
// 同一 diff 必须触及 tests/*.mjs。删除 spec 不触发；重命名按删除 + 新增处理。
// 只检查文件集合，测试质量由评审把关。用法：node scripts/check-spec-tests.mjs BASE_SHA
import { execFileSync } from 'node:child_process';
const TEST_FILE = /^(?:tests|apps\/idp\/tests|packages\/[^/]+\/tests|packages\/[^/]+\/test)\/[^/]+\.mjs$/;
export function checkSpecTests(changed, addedOrModified = changed) {
  const hasSpec = addedOrModified.some((f) => /^docs\/specs\/[^/]+\.md$/.test(f) && !/^docs\/specs\/(TEMPLATE|README)\.md$/.test(f));
  const hasTest = changed.some((f) => TEST_FILE.test(f));
  return !hasSpec || hasTest;
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const [base, ...rest] = process.argv.slice(2);
  if (!base || base.startsWith('-') || rest.length) { console.error('Usage: node scripts/check-spec-tests.mjs BASE'); process.exit(1); }
  try {
    const diff = (flt) => execFileSync('git', ['diff', '--no-ext-diff', '--no-renames', '--name-only', '-z', flt, `${base}...HEAD`, '--'], { encoding: 'utf8' }).split('\0').filter(Boolean);
    if (!checkSpecTests(diff('--diff-filter=ACDMRTUXB'), diff('--diff-filter=AM'))) { console.error('spec-requires-tests: 新增或修改 docs/specs/*.md 时，同一 diff 必须改动 tests/*.mjs'); process.exitCode = 1; }
    else console.log('spec-requires-tests: passed');
  } catch { console.error('spec-requires-tests: 无法计算 BASE...HEAD 的 diff（需要完整历史）'); process.exitCode = 1; }
}
