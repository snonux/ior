#!/usr/bin/env bash
# Record and compare ior performance baselines.
#
#   scripts/perf-baseline.sh record [label]   benchmark the current commit
#                                             (a dirty tree always gets a
#                                             "-dirty" label suffix)
#   scripts/perf-baseline.sh compare OLD NEW   benchstat + static-metric diff
#   scripts/perf-baseline.sh static            print the static metrics only
#
# OLD/NEW are labels (e.g. a short commit hash) or paths to perf/bench-*.txt.
#
# A baseline is two files under perf/, both committed so a later change can be
# judged against the exact numbers that motivated it:
#
#   perf/bench-<label>.txt    raw `go test -bench` output (benchstat format)
#   perf/static-<label>.txt   deterministic metrics of the BPF side: event
#                             struct sizes and per-handler clock reads and
#                             buffer memsets, which no userspace benchmark
#                             can see and which need no root to measure
#
# Environment:
#   PERF_COUNT      samples per benchmark        (default 8)
#   PERF_BENCHTIME  -benchtime per sample         (default 1s)
#   PERF_BENCH      benchmark regexp              (default: the focused set)
#   LIBBPFGO        libbpfgo checkout             (default ../libbpfgo)
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly repo_root
readonly perf_dir="$repo_root/perf"

# The focused set: the end-to-end pipeline mixes plus the per-stage component
# benchmarks they are made of, and the downstream row/stats/parquet stages
# (BenchmarkNew is streamrow.New). Scaling/TUI/flamegraph benchmarks are left to
# `mage benchCompare`; they take far longer and do not move with the event
# hot path.
readonly default_bench='^Benchmark(Pipeline(ReadHeavy|WriteHeavy|MetadataHeavy|DiverseAllTypes|HeadlessParquetCapture)|Deserialize.*|RawHandlerLookup|TracepointEntered|TracepointExited|Handle(Open|Fd|Path|Name|Null|Fcntl|Dup3)Exit|FdTrackerGetSet|CommResolverCachedHit|EventPoolGetPut|New|SyscallAccumulatorSnapshot|WriterThroughput|RecorderQueueHandoff)$'
readonly bench_packages=(./internal ./internal/streamrow ./internal/statsengine ./internal/parquet)

die() {
    echo "perf-baseline: $*" >&2
    exit 1
}

go_env() {
    local libbpfgo=${LIBBPFGO:-$(cd "$repo_root/../libbpfgo" 2>/dev/null && pwd)}
    [ -n "$libbpfgo" ] || die "libbpfgo checkout not found; set LIBBPFGO (see AGENTS.md)"
    export LIBBPFGO=$libbpfgo
    export CGO_CFLAGS="-I$libbpfgo/output -I$libbpfgo/selftest/common"
    export CGO_LDFLAGS="-lelf -lzstd $libbpfgo/output/libbpf/libbpf.a"
    export GOOS=linux GOARCH=amd64
}

# tree_dirty reports whether the tree differs from HEAD outside perf/, i.e.
# whether a recording would measure code that HEAD does not contain.
tree_dirty() {
    ! git -C "$repo_root" diff --quiet HEAD -- . ':!perf'
}

default_label() {
    git -C "$repo_root" rev-parse --short HEAD
}

# static_metrics prints numbers that are a pure function of the source tree.
static_metrics() {
    python3 - "$repo_root" <<'PY'
import re, sys
root = sys.argv[1]

types_h = open(f"{root}/internal/c/types.h").read()
sizes = {"__u8": 1, "__s8": 1, "__u16": 2, "__s16": 2, "__u32": 4, "__s32": 4,
         "__u64": 8, "__s64": 8, "char": 1}
consts = dict(re.findall(r"#define (\w+) (\d+)", types_h))

def size_of(struct):
    """Natural-alignment size of a struct from types.h."""
    m = re.search(r"struct " + struct + r" \{(.*?)\};", types_h, re.S)
    offset, max_align = 0, 1
    for ctype, _name, arr in re.findall(r"^\s*(\w+) (\w+)(?:\[(\w+)\])?;", m.group(1), re.M):
        size = sizes.get(ctype)
        if size is None:
            continue
        max_align = max(max_align, size)
        offset = (offset + size - 1) // size * size
        offset += size * (int(consts.get(arr, arr)) if arr else 1)
    return (offset + max_align - 1) // max_align * max_align

print("# event struct sizes in bytes (internal/c/types.h, natural alignment)")
for name in re.findall(r"^struct (\w+) \{", types_h, re.M):
    print(f"struct_size {name} {size_of(name)}")

gen = open(f"{root}/internal/c/generated_tracepoints.c").read()
handlers = {}
for part in re.split(r"(?=^/// sys_)", gen, flags=re.M):
    m = re.match(r"/// (sys_\w+) is a struct (\w+)", part)
    if m:
        handlers[m.group(1)] = (m.group(2), part)

filter_c = open(f"{root}/internal/c/filter.c").read()
def hook_clock_reads(name):
    m = re.search(r"static __always_inline \w+ " + name + r"\(.*?\n}\n", filter_c, re.S)
    return m.group(0).count("bpf_ktime_get_boot_ns(") if m else 0

print("\n# clock helper calls on the path of one traced syscall (handler body + inlined hook)")
for name, hook in (("sys_enter_read", "ior_on_syscall_enter"), ("sys_exit_read", "ior_on_syscall_exit")):
    body = handlers[name][1].count("bpf_ktime_get_boot_ns(")
    print(f"clock_reads {name} {body + hook_clock_reads(hook)}")

print("\n# bytes reserved in the ring buffer for one syscall pair, by representative syscall")
for sc in ("read", "close", "openat", "newfstatat", "renameat2", "close_range",
           "eventfd2", "memfd_create", "mmap", "epoll_wait", "futex"):
    enter, exit_ = handlers.get(f"sys_enter_{sc}"), handlers.get(f"sys_exit_{sc}")
    if enter and exit_:
        print(f"pair_bytes {sc} {size_of(enter[0]) + size_of(exit_[0])}")

print("\n# full-buffer memsets emitted across all generated handlers")
memsets = re.findall(r"__builtin_memset\(&\(ev->(\w+)\), 0, ([^;]+)\);", gen)
by_field = {}
for field, expr in memsets:
    by_field[(field, expr.strip())] = by_field.get((field, expr.strip()), 0) + 1
for (field, expr), count in sorted(by_field.items()):
    print(f"memset_sites ev->{field} [{expr}] {count}")
print(f"memset_sites_total {len(memsets)}")
print(f"handlers_total {len(handlers)}")
PY
}

record() {
    local label=${1:-$(default_label)} dirty=""
    # A dirty tree is marked whatever the label: the header names HEAD, which
    # is not what was measured, so both the file name and the commit line say so.
    if tree_dirty; then
        dirty=" +uncommitted changes"
        [[ $label == *-dirty ]] || label+="-dirty"
    fi
    local bench_file="$perf_dir/bench-$label.txt"
    local static_file="$perf_dir/static-$label.txt"
    local count=${PERF_COUNT:-8} benchtime=${PERF_BENCHTIME:-1s}
    local bench=${PERF_BENCH:-$default_bench}

    mkdir -p "$perf_dir"
    go_env
    cd "$repo_root"

    {
        # benchstat ignores lines it cannot parse, so the provenance travels
        # inside the same file as the numbers.
        echo "# ior performance baseline"
        echo "# label:      $label"
        echo "# commit:     $(git rev-parse HEAD) ($(git log -1 --format=%s))$dirty"
        echo "# date:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# kernel:     $(uname -r)"
        echo "# cpu:        $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs) x$(nproc)"
        echo "# clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo unknown)"
        echo "# go:         $(go version | cut -d' ' -f3-)"
        echo "# settings:   count=$count benchtime=$benchtime"
        echo "# loadavg:    $(cut -d' ' -f1-3 /proc/loadavg) (at start; keep the host idle while recording)"
        echo
    } > "$bench_file"

    echo "perf-baseline: recording $label ($count samples x $benchtime) ..." >&2
    go test "${bench_packages[@]}" -run '^$' -bench "$bench" -benchmem \
        -count "$count" -benchtime "$benchtime" 2>&1 \
        | grep -Ev '^(#|.*warning:|.*\^|\s*[0-9]+ \||[0-9]+ warnings? generated)' \
        | tee -a "$bench_file" | grep -E '^(ok|FAIL|---)' >&2 || true

    grep -q '^Benchmark' "$bench_file" || die "no benchmark results were recorded; see $bench_file"
    if grep -Eq '^(FAIL|--- FAIL)' "$bench_file"; then
        die "a benchmark package failed; see $bench_file"
    fi

    static_metrics > "$static_file"
    echo "perf-baseline: wrote ${bench_file#"$repo_root"/} and ${static_file#"$repo_root"/}" >&2
}

resolve() { # label-or-path, kind
    local ref=$1 kind=$2
    if [ -f "$ref" ]; then
        local dir base
        dir=$(dirname "$ref")
        base=$(basename "$ref")
        base=${base#bench-}
        base=${base#static-}
        echo "$dir/$kind-$base"
    else
        echo "$perf_dir/$kind-$ref.txt"
    fi
}

compare() {
    [ $# -eq 2 ] || die "usage: compare OLD NEW"
    local old_bench new_bench old_static new_static
    old_bench=$(resolve "$1" bench)
    new_bench=$(resolve "$2" bench)
    old_static=$(resolve "$1" static)
    new_static=$(resolve "$2" static)
    [ -f "$old_bench" ] || die "missing $old_bench"
    [ -f "$new_bench" ] || die "missing $new_bench"

    local benchstat=${BENCHSTAT:-benchstat}
    if ! command -v "$benchstat" >/dev/null 2>&1; then
        benchstat="$(go env GOPATH)/bin/benchstat"
        [ -x "$benchstat" ] || die "benchstat not found: go install golang.org/x/perf/cmd/benchstat@latest"
    fi

    echo "== benchmarks (benchstat: old -> new; '~' means no significant change) =="
    "$benchstat" "$old_bench" "$new_bench"

    if [ -f "$old_static" ] && [ -f "$new_static" ]; then
        echo
        echo "== static BPF metrics (only lines that changed) =="
        if diff <(grep -v '^#' "$old_static") <(grep -v '^#' "$new_static") >/dev/null; then
            echo "unchanged"
        else
            diff -u --label "$1" --label "$2" \
                <(grep -v '^#' "$old_static") <(grep -v '^#' "$new_static") \
                | grep -E '^[+-][^+-]' || true
        fi
    fi
}

main() {
    local cmd=${1:-}
    [ $# -gt 0 ] && shift
    case "$cmd" in
    record) record "$@" ;;
    compare) compare "$@" ;;
    static) static_metrics ;;
    *) die "usage: $0 record [label] | compare OLD NEW | static" ;;
    esac
}

main "$@"
