#!/usr/bin/env bash
# One-tape wrapper: starts the background workload, runs vhs <tape>, kills the
# workload. Tapes themselves don't need to know about the workload — they just
# launch ior and drive the TUI.
#
# vhs is invoked from the repo root so Output/Screenshot paths are repo-relative.
# The recorded shell uses IOR_DEMO_DIR, with ./ior linked to the built binary.
#
# Usage: run-tape.sh <path-to-tape>

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <tape-file>" >&2
    exit 2
fi

TAPE="$(realpath "$1")"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WORKLOAD="${ROOT}/docs/tutorial/scripts/workload.sh"

if [ ! -f "$TAPE" ]; then
    echo "tape not found: $TAPE" >&2
    exit 2
fi

# Pre-flight: vhs and ttyd must be on PATH; sudo timestamp must be live.
command -v vhs >/dev/null || { echo "vhs not on PATH (run: mage installDemoTools)" >&2; exit 3; }
command -v ttyd >/dev/null || { echo "ttyd not on PATH (run: mage installDemoTools)" >&2; exit 3; }
sudo -n true 2>/dev/null || { echo "sudo timestamp expired (run: sudo -v)" >&2; exit 4; }

# Each tape gets an isolated working directory with a portable ./ior command.
IOR_DEMO_DIR="$(mktemp -d -t ior-demo-XXXXXX)"
export IOR_DEMO_DIR
WL_PID=""

cleanup() {
    if [ -n "$WL_PID" ]; then
        # The workload runs `setsid` so its PID == its PGID.
        kill -TERM -- "-$WL_PID" 2>/dev/null || true
        sleep 0.5
        kill -KILL -- "-$WL_PID" 2>/dev/null || true
        wait "$WL_PID" 2>/dev/null || true
    fi
    rm -rf -- "$IOR_DEMO_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ln -s "$ROOT/ior" "$IOR_DEMO_DIR/ior"
# Start workload in its own session/process group so we can kill the whole tree.
setsid "$WORKLOAD" </dev/null >/dev/null 2>&1 &
WL_PID=$!

# Give the workload a moment to spool up before recording.
sleep 2
if ! kill -0 "$WL_PID" 2>/dev/null; then
    echo "demo workload exited before recording" >&2
    exit 5
fi

cd "$ROOT"
vhs "$TAPE"
