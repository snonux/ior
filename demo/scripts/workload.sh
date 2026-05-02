#!/usr/bin/env bash
# Background workload for demo tapes. Generates a steady mix of file I/O
# (open/read/close), big writes (fsync/dd), stat-heavy traffic, and ioworkload
# scenarios so every TUI tab has something interesting to display.
#
# Designed to be killed via `kill $!` from the tape wrapper. All children are
# placed in this script's process group so a single signal cleans them up.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IOWORKLOAD="${ROOT}/../ioworkload"
SCRATCH="$(mktemp -d -t ior-demo-workload-XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

cleanup() {
    trap - TERM INT
    # Kill the entire process group so all background loops stop.
    kill -- -$$ 2>/dev/null || true
    exit 0
}
trap cleanup TERM INT

# A) walk /usr and read first byte of each file: tons of openat/read/close + varied paths.
(
    while true; do
        find /usr/share /usr/lib -maxdepth 4 -type f 2>/dev/null \
            | shuf -n 800 \
            | xargs -r -I{} sh -c 'head -c 1 "{}" >/dev/null 2>&1' || true
        sleep 1
    done
) &

# B) periodic large write with fsync via dd: fills the latency tab with slow writes.
(
    while true; do
        dd if=/dev/zero of="${SCRATCH}/big.bin" bs=1M count=20 conv=fsync status=none 2>/dev/null || true
        sleep 3
        rm -f "${SCRATCH}/big.bin"
    done
) &

# C) stat-heavy directory crawl: feeds the syscall tab with newfstatat/getdents.
(
    while true; do
        find /etc /var/log -maxdepth 3 >/dev/null 2>&1 || true
        sleep 2
    done
) &

# D) ioworkload scenario rotation if the binary exists: gives us syscall variety
# beyond what the shell utilities trigger (mmap, dup, fcntl, sync, rename, link).
if [ -x "$IOWORKLOAD" ]; then
    (
        scenarios=(
            open-basic
            readwrite-basic
            stat-basic
            stat-statx
            mmap-basic
            sync-basic
            dup-basic
            fcntl-dupfd
            rename-basic
            link-basic
            dir-basic
        )
        while true; do
            for s in "${scenarios[@]}"; do
                "$IOWORKLOAD" --scenario="$s" >/dev/null 2>&1 || true
            done
        done
    ) &
fi

# Idle until killed.
wait
