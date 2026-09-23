# Process-Tree Following ("Follow Forks"): Implementation Plan

Status: **planned, not implemented.** The command line has no `-follow-forks` flag yet.
This is a design sketch; check the kernel and libbpfgo details before implementing it.

## Motivation

With a PID selected, `internal/c/filter.c` accepts only that TGID. `PID_FILTER=-1`
traces all processes. A child has a different TGID, so a trace scoped to its
parent drops the child's syscalls in the kernel, before userspace filtering.

This blocks any workload that does meaningful work in child processes:

- `landlock_restrict_self` integration coverage (task `ci0`): the syscall
  irreversibly sandboxes its calling process, so it can only be exercised in a
  short-lived child; that child's syscalls are currently filtered out.
- More broadly: shells, `make`, CI pipelines, and forking servers cannot be
  traced as a unit.

Following forks makes ior trace a target PID **and all its descendants** as a
tree, while leaving the default single-PID behavior unchanged.

## Requirements

1. Opt in with a new `-follow-forks` flag. Keep it off by default and test the
   existing single-PID behavior.
2. When ON, trace the root PID and every descendant created after attach
   (fork/clone), including across `exec` (which preserves the TGID).
3. **Syscall-count aggregation must still cover the whole followed tree.** The
   per-syscall aggregate counts/durations/histograms in `syscall_aggregate_map`
   (maintained by `ior_update_syscall_aggregate` in `filter.c`) must roll up
   syscalls issued by descendants, not just the root. Note the existing
   invariant to preserve: aggregate counting and per-event emission *partition*
   the invocations — `ior_on_syscall_exit` calls
   `ior_update_syscall_aggregate` exactly when the sampling decision says the
   event is not emitted (`emit_event == 0`), and userspace merges the aggregate
   rows for every syscall whose rate is not 1, so aggregate + emitted = the
   true count. Following forks must not regress this: a descendant whose
   individual events are sampled down must still contribute to the counts
   through both halves of that partition.
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

The fork hook should add the child before it runs its first syscall. Verify that
ordering on the target kernels. `exec` keeps the TGID, so a child that re-execs
should keep its membership.

The descendant check belongs in `filter()`, which gates event emission and
aggregate counting. Tests still need to prove that sampled descendant calls
contribute to the total.

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
  - `SEC("tracepoint/sched/sched_process_exit")`: reclaim TGIDs when the whole
    process exits. A thread exit must not remove a still-live TGID; check whether
    leader exit alone is sufficient when other threads remain.

- **`filter()`** — when `FOLLOW_FORK == 1`, additionally `ACCEPT` if
  `bpf_map_lookup_elem(&traced_pid_map, &tgid)` hits. Keep the existing
  `IOR_PID_FILTER` self-exclusion and the `PID_FILTER == -1` trace-all path.
  This adds one map lookup on the enabled path; measure its cost.

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

## Rough effort estimate: 2.5–4 days

| Piece | Est. |
|---|---|
| BPF map + 2 sched hooks + filter change | 0.5–1d |
| Go: flag, global, map seeding, attach, userland filter bypass | 0.5d |
| Harness mode + tree/comm assertions + feature integration test | 0.5–1d |
| `ci0` scenario + test | 0.25d |
| Verifier / edge-case buffer (thread-vs-process exit, fork tracepoint field offsets, map sizing) | 0.5–1d |

## Checks before shipping

- Run the full suite with the flag off to catch changes to single-PID tracing.
- Read `child_pid` using the tracepoint format and test it on the oldest
  supported kernel.
- Remove a TGID only after its last thread exits. A leader can exit while other
  threads remain.
- Bound the map and reclaim entries on exit. Test what happens when inserts fail
  during a fork storm.
- Measure the enabled map lookup and check that the verifier accepts both modes.
- Assert that sampled child syscalls contribute to aggregate counts as well as
  emitted rows.

## Sequencing

1. BPF map + `filter()` `FOLLOW_FORK` branch (off by default) + Go global →
   confirm the suite is still green.
2. Add the sched hooks + map seeding + attach.
3. Feature integration test (on/off, including the count-rollup assertion) →
   proves the mechanism.
4. Userland filter bypass + harness tree mode + assertions.
5. `ci0` scenario + test.

Run the on/off integration test before adding the landlock scenario.

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
