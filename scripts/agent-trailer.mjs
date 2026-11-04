#!/usr/bin/env node
// 提交署名与 trailer 检查（本地 commit-msg 钩子与 CI 共用）。
// 规则见 docs/workflow-v2.md「署名与贡献者」：author 邮箱必须是 GitHub noreply；
// 提交信息末尾必须有 `Agent: <id>`，id 与 author 名对应；不允许出现 AI 花费 / token 用量字样。
// 用法：node scripts/agent-trailer.mjs --message-file FILE | --range BASE..HEAD
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

export const AGENTS = {
  'grok-code-assistant': /^Grok Bot Friday \(for 2mauis\)$/,
  'grok-friday': /^Grok Bot Friday \(for 2mauis\)$/,
  'claude-code': /^Claude Code \(for 2mauis\)$/,
  codex: /^Codex \(for 2mauis\)$/,
  human: /.+/,
};
export function checkAgentTrailer({ message, authorName, authorEmail }) {
  const errors = [];
  const lines = message.replace(/\s+$/, '').split('\n');
  const tail = []; for (let i = lines.length - 1; i >= 0 && lines[i].trim(); i--) tail.unshift(lines[i]);
  const agent = tail.map((l) => /^Agent:\s*(\S+)\s*$/.exec(l)?.[1]).filter(Boolean);
  if (agent.length !== 1) errors.push('missing-or-duplicate-agent-trailer');
  else if (!AGENTS[agent[0]]) errors.push('unknown-agent');
  else if (authorName !== undefined && !AGENTS[agent[0]].test(authorName)) errors.push('author-does-not-match-agent');
  if (authorEmail !== undefined && !/@users\.noreply\.github\.com$/.test(authorEmail)) errors.push('author-email-not-noreply');
  if (/\b(token usage|tokens used|cost:\s*\$|api cost)\b/i.test(message)) errors.push('ai-cost-or-usage-in-message');
  return errors;
}
const git = (...a) => execFileSync('git', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trimEnd();
function report(sha, errors) { for (const e of errors) console.error(`${sha} ${e}`); if (errors.length) process.exitCode = 1; }
if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const [mode, value, ...rest] = process.argv.slice(2);
    if (!value || rest.length) throw new Error('arguments');
    if (mode === '--message-file') {
      let authorName = process.env.GIT_AUTHOR_NAME, authorEmail = process.env.GIT_AUTHOR_EMAIL;
      try { const m = /^(.*) <([^<>]*)> \d+ [+-]\d+$/.exec(git('var', 'GIT_AUTHOR_IDENT')); authorName ??= m?.[1]; authorEmail ??= m?.[2]; } catch { /* 无身份时只查信息 */ }
      report('HEAD', checkAgentTrailer({ message: readFileSync(value, 'utf8'), authorName, authorEmail }));
    } else if (mode === '--range') {
      if (!/^[^\s.-][^\s]*(?<!\.)\.\.(?!\.)[^\s]+$/.test(value)) throw new Error('range');
      const shas = git('rev-list', '--no-merges', value, '--').split('\n').filter(Boolean);
      for (const sha of shas) {
        const [an, ae, cn, ce, msg = ''] = git('show', '-s', '--format=%an%x00%ae%x00%cn%x00%ce%x00%B', sha).split('\0');
        const errs = checkAgentTrailer({ message: msg, authorName: an, authorEmail: ae });
        if (!/@users\.noreply\.github\.com$|^noreply@github\.com$/.test(ce)) errs.push('committer-email-not-noreply');
        report(sha.slice(0, 12), errs);
      }
      if (!process.exitCode) console.log(`agent-trailer: ${shas.length} 个提交通过`);
    } else throw new Error('arguments');
  } catch { report('HEAD', ['check-failed']); }
}
