#!/usr/bin/env bash
# Run the real protocol demo, record its trace, and serve the animated web demo.
#   ./scripts/web-demo.sh [port]      (default 14080) → http://127.0.0.1:14080
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${1:-14080}"
cargo run -q -p chp-sim --example demo -- --json web/trace.json > /dev/null
echo "trace: web/trace.json ($(python3 -c 'import json;print(len(json.load(open("web/trace.json"))))') items)"
echo "open http://127.0.0.1:${PORT}"
exec python3 -m http.server "$PORT" --bind 127.0.0.1 --directory web
