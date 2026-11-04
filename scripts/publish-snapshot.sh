#!/bin/sh
# 按白名单生成公开快照并推送到目标仓库分支（单个提交，不带开发历史）。
# 用法：scripts/publish-snapshot.sh <目标 git URL 或本地 bare 仓路径> [分支=main]
# 不使用 --mirror / --all / --force。目标分支已存在时，在其之上提交一个整树替换的新提交。
set -eu
TARGET=$1; BRANCH=${2:-main}
ROOT=$(git rev-parse --show-toplevel); SRC=$(git -C "$ROOT" rev-parse HEAD)
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/tree"
# 1. 白名单导出（只取已跟踪文件）
grep -v '^\s*#' "$ROOT/.github/publish-allowlist.txt" | sed '/^\s*$/d' > "$WORK/globs"
git -C "$ROOT" ls-files -z | xargs -0 -n1 sh -c 'f=$1; while read -r g; do case "$f" in $g) printf "%s\n" "$f"; break;; esac; done < "'"$WORK/globs"'"' _ > "$WORK/files"
[ -s "$WORK/files" ] || { echo "白名单为空" >&2; exit 1; }
(cd "$ROOT" && tar -cf - -T "$WORK/files") | tar -xf - -C "$WORK/tree"
# 2. 在快照上重新扫描
cd "$WORK/tree"
git init -q -b "$BRANCH" .
git add -A
node scripts/privacy-scan.mjs
if command -v gitleaks >/dev/null 2>&1; then gitleaks dir --config .gitleaks.toml --redact --no-banner --exit-code 1 .; else echo "缺少 gitleaks，停止" >&2; exit 1; fi
# 3. 单提交；目标分支已存在则以其为父（整树替换），否则 orphan
ID='Grok Bot Friday (for 2mauis)'; EM='2908005+2mauis@users.noreply.github.com'
MSG="snapshot: 公开快照（源提交 ${SRC%"${SRC#????????????}"}）

Agent: grok-code-assistant"
if git fetch -q "$TARGET" "refs/heads/$BRANCH" 2>/dev/null; then
  git reset -q --soft FETCH_HEAD
  if git diff --cached --quiet FETCH_HEAD; then echo "无变化，不推送"; exit 0; fi
fi
git -c user.name="$ID" -c user.email="$EM" commit -q -m "$MSG"
echo "快照文件数：$(wc -l < "$WORK/files")，提交数：$(git rev-list --count HEAD)"
git push "$TARGET" "HEAD:refs/heads/$BRANCH"
