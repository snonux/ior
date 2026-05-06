#!/usr/bin/env bash
# One-tape wrapper: starts the background workload, runs vhs <tape>, kills the
# workload. Tapes themselves don't need to know about the workload — they just
# launch ior and drive the TUI.
#
# vhs is invoked with cwd set to the repo root, so all paths inside tapes
# (Output, Screenshot, the ./ior binary) are repo-relative.
#
# Usage: run-tape.sh <path-to-tape>

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <tape-file>" >&2
    exit 2
fi

TAPE="$(realpath "$1")"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKLOAD="${ROOT}/demo/scripts/workload.sh"

if [ ! -f "$TAPE" ]; then
    echo "tape not found: $TAPE" >&2
    exit 2
fi

# Pre-flight: vhs and ttyd must be on PATH; sudo timestamp must be live.
command -v vhs >/dev/null || { echo "vhs not on PATH (run: mage installDemoTools)" >&2; exit 3; }
command -v ttyd >/dev/null || { echo "ttyd not on PATH (run: mage installDemoTools)" >&2; exit 3; }
sudo -n true 2>/dev/null || { echo "sudo timestamp expired (run: sudo -v)" >&2; exit 4; }

# Start workload in its own session/process group so we can kill the whole tree.
setsid "$WORKLOAD" </dev/null >/dev/null 2>&1 &
WL_PID=$!

cleanup() {
    if kill -0 "$WL_PID" 2>/dev/null; then
        # The workload runs `setsid` so its PID == its PGID.
        kill -TERM -- "-$WL_PID" 2>/dev/null || true
        sleep 0.5
        kill -KILL -- "-$WL_PID" 2>/dev/null || true
    fi
    # Best-effort: stop any straggling ior processes from this tape.
    sudo -n pkill -TERM -f '/ior$' 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Give the workload a moment to spool up before recording.
sleep 2

cd "$ROOT"
vhs "$TAPE"
