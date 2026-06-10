# Process-Tree Following ("Follow Forks"): Implementation Plan

Status: **planned, not implemented.** This document is a design/implementation
plan only. No code in this plan has been written yet.

## Motivation

Today ior traces exactly one TGID. `internal/c/filter.c` `filter()` accepts a
syscall only when the current process group id equals the load-time
`PID_FILTER` global (or `-1` for trace-all). Children that a workload forks/execs
have a different TGID and are dropped **in-kernel**, before any userspace comm
filtering can see them.

This blocks any workload that does meaningful work in child processes:

- `landlock_restrict_self` integration coverage (task `ci0`): the syscall
  irreversibly sandboxes its calling process, so it can only be exercised in a
  short-lived child; that child's syscalls are currently filtered out.
- More broadly: shells, `make`, CI pipelines, and forking servers cannot be
  traced as a unit.

Following forks makes ior trace a target PID **and all its descendants** as a
tree, while leaving the default single-PID behavior unchanged.

## Requirements

1. Opt-in via a new `-follow-forks` flag. Default OFF → existing behavior and all
   existing tests are byte-for-byte unaffected.
2. When ON, trace the root PID and every descendant created after attach
   (fork/clone), including across `exec` (which preserves the TGID).
3. **Syscall-count aggregation must still cover the whole followed tree.** The
   per-syscall aggregate counts/durations/histograms in `syscall_aggregate_map`
   (maintained by `ior_update_syscall_aggregate` in `filter.c`) must roll up
   syscalls issued by descendants, not just the root. Note the existing
   invariant to preserve: aggregate counting is independent of per-event
   sampling — `ior_on_syscall_exit` calls `ior_update_syscall_aggregate`
   regardless of the sampling/`emit_event` decision, so even syscalls in
   aggregate-only (sampling-rate 0) mode still count. Following forks must not
   regress this: a descendant whose individual events are sampled down must
   still contribute to the counts.
4. Bounded resource use: descendant set lives in a fixed-size BPF map, reclaimed
   on process exit; pathological fork storms degrade gracefully (best-effort),
   they do not crash the tracer.

## Design overview

A new BPF hash map holds the set of traced TGIDs. Two `sched` tracepoints keep it
current (add child on fork, remove on process exit). `filter()` consults the set
when a new `FOLLOW_FORK` global is on. The whole feature is gated off by default.

```
                sched_process_fork                 sched_process_exit
                (parent ctx, pre-child)            (leader exit only)
                        │ add child tgid                │ delete tgid
                        ▼                               ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                      traced_pid_map (hash)                     │
   │                key: __u32 tgid   value: __u8                   │
   └──────────────────────────────────────────────────────────────┘
                        ▲ seeded with root PID at startup
                        │ consulted (one lookup) per syscall when
                        │ FOLLOW_FORK == 1
                   filter()  →  ACCEPT / FILTER
                        │
                        ▼ ACCEPT covers BOTH event emission AND
                          ior_update_syscall_aggregate (count rollup)
```

Because `sched_process_fork` fires in the parent's context **before the child
runs**, the child is enrolled in the map before it executes its first syscall.
This is what makes following reliable. `exec` does not change the TGID, so a
re-exec'd child keeps its membership — exactly what the `ci0` landlock case
needs.

Putting the descendant check inside `filter()` (the single gate in front of both
event emission and `ior_update_syscall_aggregate`) is what satisfies requirement
3 for free: any accepted descendant flows into the same aggregate-counting path
as the root.

## Changes by layer

### 1. BPF data plane (`internal/c/`)

- **`maps.h`** — add `traced_pid_map`:
  `BPF_MAP_TYPE_HASH`, key `__u32` (tgid), value `__u8`, `max_entries` ~8192
  (resizable like `event_map`). Consider `BPF_MAP_TYPE_LRU_HASH` as a safety
  valve against fork-storm exhaustion (auto-evicts coldest entries instead of
  failing inserts).

- **New `follow_fork.c`** (or appended into `filter.c`):
  - `const volatile __u32 FOLLOW_FORK;` global (set at load time, mirrors
    `PID_FILTER`).
  - `SEC("tracepoint/sched/sched_process_fork")`: read `child_pid` from the
    tracepoint context (use the tracepoint format / CO-RE as the syscall
    handlers already do); if the parent's TGID is in `traced_pid_map`, insert
    the child TGID. Only act when `FOLLOW_FORK == 1`.
  - `SEC("tracepoint/sched/sched_process_exit")`: delete the TGID, but **only on
    thread-group-leader exit** (`pid == tgid`) so per-thread exits don't evict a
    still-live process.

- **`filter()`** — when `FOLLOW_FORK == 1`, additionally `ACCEPT` if
  `bpf_map_lookup_elem(&traced_pid_map, &tgid)` hits. Keep the existing
  `IOR_PID_FILTER` self-exclusion and the `PID_FILTER == -1` trace-all path.
  This is one extra hot-path lookup, gated by the flag (negligible when off).

### 2. BPF control plane (Go, `internal/`)

- **`bpfsetup.go`** — set the `FOLLOW_FORK` global in `setBPFGlobals` (mirror
  `PID_FILTER`); add `traced_pid_map` to `resizeBPFMaps` if made resizable.
- **Seeding** — after `BPFLoadObject`, when follow-forks is on, insert the root
  `cfg.PidFilter` into `traced_pid_map` via the libbpfgo `Map.Update`. New small
  helper, called from `setupBPFModule`.
- **Attach the sched hooks** — in `setupBPFModule`, after `mgr.AttachAll`,
  directly attach the two programs via
  `GetProgram(...).AttachTracepoint("sched", "sched_process_fork" / "sched_process_exit")`.
  Keep them out of the syscall selector / TUI probe state (they are always-on
  plumbing, not user-selectable). Retain their `Link`s for clean teardown.

### 3. Userland filter (`internal/flags/`)

- **`flags.go`** — add `FollowFork bool` (default false) and a `-follow-forks`
  CLI flag.
- **`tracefilter.go`** — when `FollowFork` is on, **do not** set the userland PID
  `Eq` filter (currently `tracefilter.go:26`, `cfg.PidFilter > 0`). The kernel
  already scopes to the tree; a userland `pid == root` equality filter would
  wrongly drop legitimate descendant records.

### 4. Test harness (`integrationtests/`)

- **`harness.go`** — add an opt-in run mode that passes `-follow-forks` (via the
  existing `extraIorArgs` path) and seeds the root with the workload PID.
- **`expectations.go`** — add a tree/comm-aware assertion, e.g.
  `AssertPidsWithinTree(result, rootPID, allowedComms...)` or a comm-scoped
  `AssertOnlyComm(result, "ioworkload")`, since descendant PIDs are legitimately
  `!= root`. The existing `AssertNoUnexpectedPID` (expectations.go:81) stays
  as-is for normal (non-tree) tests.

### 5. Feature validation + `ci0`

- **New `follow_fork_test.go`** — a scenario that forks+execs a child issuing a
  distinctive syscall. Assert:
  - **with** follow-forks: the child's syscall **is** captured, and the child's
    syscalls contribute to the syscall-count aggregate (requirement 3);
  - **without** follow-forks: the child's syscall is **not** captured (proves the
    default is unchanged).
- **`ci0`** — scenario re-execs an ioworkload child subcommand that does
  `landlock_create_ruleset → landlock_restrict_self(rf, 0) → exit`; the parent is
  never sandboxed. The test runs with follow-forks and a comm-scoped assertion
  for `enter_landlock_restrict_self`. ~30 min once the infra above exists.

## Effort estimate: ~2.5–4 days

| Piece | Est. |
|---|---|
| BPF map + 2 sched hooks + filter change | 0.5–1d |
| Go: flag, global, map seeding, attach, userland filter bypass | 0.5d |
| Harness mode + tree/comm assertions + feature integration test | 0.5–1d |
| `ci0` scenario + test | 0.25d |
| Verifier / edge-case buffer (thread-vs-process exit, fork tracepoint field offsets, map sizing) | 0.5–1d |

## Risks & mitigations

- **Behavior regression** → default-off `FOLLOW_FORK` global; zero change to
  existing code paths when off. Gate sign-off on the full suite staying green.
- **`sched_process_fork` field extraction** (`child_pid` offset) → use the
  tracepoint format / CO-RE, consistent with the existing syscall handlers.
- **Thread vs process exit eviction** → guard the delete on `pid == tgid`
  (leader only) so a thread exit never drops a live process.
- **Map exhaustion under heavy forking** → bounded hash with exit-hook reclaim;
  optionally `LRU_HASH`. Best-effort is acceptable for a tracer.
- **Verifier cost** → a single extra map lookup on the hot path, flag-gated; low.
- **Count-aggregation correctness (requirement 3)** → keep the descendant check
  inside `filter()` so accepted descendants share the root's
  `ior_update_syscall_aggregate` path; add an explicit assertion in
  `follow_fork_test.go` that descendant syscalls increment the aggregate counts.

## Sequencing

1. BPF map + `filter()` `FOLLOW_FORK` branch (off by default) + Go global →
   confirm the suite is still green.
2. Add the sched hooks + map seeding + attach.
3. Feature integration test (on/off, including the count-rollup assertion) →
   proves the mechanism.
4. Userland filter bypass + harness tree mode + assertions.
5. `ci0` scenario + test.

Steps 1–3 deliver the reusable feature; steps 4–5 consume it. Each step is
independently verifiable.

## Source-of-truth references

- `internal/c/filter.c` — `filter()`, `ior_on_syscall_exit`,
  `ior_update_syscall_aggregate` (the count path that must cover the tree).
- `internal/c/maps.h` — map declarations (where `traced_pid_map` is added).
- `internal/bpfsetup.go` — `setBPFGlobals` (`PID_FILTER` etc.), `resizeBPFMaps`.
- `internal/ior_bpfsetup.go` — `setupBPFModule` attach flow; `AttachTracepoint`.
- `internal/flags/flags.go`, `internal/flags/tracefilter.go` — flag surface and
  userland PID filtering.
- `integrationtests/harness.go`, `integrationtests/expectations.go` —
  `AssertNoUnexpectedPID` and the run modes a tree-aware test needs.
