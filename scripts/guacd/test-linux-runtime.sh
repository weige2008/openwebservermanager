#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNTIME_DIR="${1:-$REPO_ROOT/runtime/guacd/linux}"
PORT="${GUACD_TEST_PORT:-24822}"
GUACD="$RUNTIME_DIR/bin/guacd"

[[ -x "$GUACD" ]] || { echo "guacd was not found at $GUACD" >&2; exit 1; }
export PATH="$RUNTIME_DIR/bin:$PATH"
export LD_LIBRARY_PATH="$RUNTIME_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export FREERDP_PLUGIN_PATH="$RUNTIME_DIR/usr/lib/freerdp2"
export HOME="$RUNTIME_DIR/home"
mkdir -p "$HOME"

log_file="$RUNTIME_DIR/guacd-smoke.log"
"$GUACD" -b 127.0.0.1 -l "$PORT" -f -L debug >"$log_file" 2>&1 &
guacd_pid=$!
cleanup() {
  kill "$guacd_pid" 2>/dev/null || true
  wait "$guacd_pid" 2>/dev/null || true
  rm -f "$log_file"
}
trap cleanup EXIT

for _ in $(seq 1 80); do
  if (echo >/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
    break
  fi
  sleep 0.1
done
kill -0 "$guacd_pid"

read_args() {
  local protocol="$1"
  local response
  exec 3<>/dev/tcp/127.0.0.1/"$PORT"
  printf '6.select,%s.%s;' "${#protocol}" "$protocol" >&3
  IFS= read -r -t 15 -d ';' response <&3 || true
  exec 3<&-
  exec 3>&-
  [[ "$response" == 4.args,*8.hostname* ]] || {
    echo "$protocol plugin did not return a valid args instruction: $response" >&2
    exit 1
  }
  sleep 0.25
  kill -0 "$guacd_pid"
}

read_args rdp
read_args vnc
echo "Linux guacd RDP/VNC smoke test passed on port $PORT"
