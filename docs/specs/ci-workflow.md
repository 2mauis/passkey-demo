# CI 与发布流程

## 背景/目标
private staging 上跑确定性检查；public 仓只接收白名单快照。详见 docs/workflow.md、docs/workflow-v2.md。

## 非目标
CD（deploy.yml 缺 token 时跳过）；配置 secrets、分支保护、仓库设置。

## 不变量
不 --mirror / --all / force push；快照发布前重扫；检查只读、不调用 AI。

## 验收测试清单
- [x] 隐私规则：`tests/workflow-scripts.mjs`「privacy：普通邮箱命中」「privacy：公网 IPv4 命中」「privacy：真实 workers.dev 子域命中，example 放行」「privacy：32 位十六进制 id 命中，全 0 放行」「privacy：Turnstile 生产 sitekey 命中」「privacy：GitHub token 样式命中」。
- [x] trailer：「trailer：正确署名通过」「trailer：缺 Agent 失败」「trailer：非 noreply 邮箱失败」「trailer：author 与 Agent 不匹配失败」。
- [x] spec-requires-tests：「spec：改 spec 不改测试失败」「spec：改 spec 同时改 tests/*.mjs 通过」「spec：TEMPLATE.md 豁免；删除 spec 不触发」。

## 风险
正则扫描漏报；CodeQL 在公开后才运行。

## 是否重大改动
是（发布流程）。按本次任务授权执行。
