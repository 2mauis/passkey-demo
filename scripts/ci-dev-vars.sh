#!/bin/sh
# CI 专用：由 apps/idp/.dev.vars.example 生成 .dev.vars，两个本地密钥每次运行随机生成（不进日志、不入库）。
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
APP="$ROOT/apps/idp"
cd "$APP"
k() { node -e "process.stdout.write(require('crypto').randomBytes(32).toString('base64'))"; }
sed -e "s|^CHAL_HMAC_KEY=.*|CHAL_HMAC_KEY=$(k)|" -e "s|^ADMIN_TOKEN=.*|ADMIN_TOKEN=$(k)|" .dev.vars.example > .dev.vars
chmod 600 .dev.vars
node "$ROOT/scripts/oidc-keygen.mjs" .dev.vars >/dev/null
