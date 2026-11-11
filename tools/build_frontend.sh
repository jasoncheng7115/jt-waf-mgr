#!/bin/sh
# Build the Vue UI into jtwafmgr/static/.
# Uses jt-ipam's already-installed Vite/Vue (read-only) until this project has its own
# node_modules (that needs an npm download -> ask the user first).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NM=${JTWAF_NODE_MODULES:-/opt/jt-ipam/frontend/node_modules}
export JTWAF_NODE_MODULES="$NM"
cd "$ROOT/frontend"
node "$NM/vite/bin/vite.js" build --config "$ROOT/frontend/vite.config.mjs" "$@"
python3 "$ROOT/tools/check_i18n.py"
python3 "$ROOT/tools/check_ui.py"
