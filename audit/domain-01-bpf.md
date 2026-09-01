# Audit Report — Domain 1: BPF Kernel-Side Correctness

**Project**: I/O Riot NG (ior) at `/home/paul/git/ior`
**Audit plan**: `PLAN-PROJECT-AUDIT.md`, section "Domain 1 — BPF Kernel-Side Correctness" (items 1.1, 1.2, 1.3)
**Date**: 2026-09-01
**Auditor environment**: Linux 5.14.0-687.36.1.el9_8.x86_64 (RHEL 9 family), **no root** (`sudo -n true` fails). `/sys/kernel/tracing` is **not readable** as non-root:

```
$ ls /sys/kernel/tracing/events/syscalls/
ls: cannot access '/sys/kernel/tracing/events/syscalls/': Permission denied
```

**Method**: static source audit of `internal/c/{ior.bpf.c,filter.c,maps.h,types.h,flags.h,generated_tracepoints.c}`, the generators in `internal/generate/`, the generated Go artifacts, and the BPF wiring in `internal/{bpfsetup.go,ior_bpfsetup.go,bpfembed.go}`; plus a read-only verification harness (`audit/check/main.go`, run with `go run ./audit/check`) that re-derives the generated Go artifacts in memory and cross-checks the (working-tree-deleted) `docs/syscall-tracing-plan.md` from git HEAD against the generated tracepoint maps. `mage build`/`mage test` were NOT re-run (orchestrator already ran them; result quoted where relevant). No source files were modified.

**Verdict legend**: PASS / FAIL / N-A / BLOCKED-needs-root (with static verification performed wherever possible).

---

## Item 1.1 — Tracepoint Coverage & Accuracy

### 1.1.a — "Verify that `internal/tracepoints/generated_tracepoints.go` contains the exact set of tracepoints listed in `docs/syscall-tracing-plan.md`"

**Verdict: PASS** (with a recorded known issue: the doc is deleted in the working tree, so the drift tests that enforce this cannot run — see Finding F1)

`docs/syscall-tracing-plan.md` is deleted in the working tree (`git status`: ` D docs/syscall-tracing-plan.md`), so the comparison was performed against the git HEAD version of the doc (`git show HEAD:docs/syscall-tracing-plan.md`), which is the content the drift tests enforce.

The verification harness (`go run ./audit/check`) parsed the doc's two list sections and the generated Go maps and compared them as sets, per group:

```
== Families (doc @HEAD vs generated) ==
  group keys: identical (12 groups)          ← no per-group mismatch lines printed
== Kinds (doc @HEAD vs generated) ==
  group keys: identical (33 groups)           ← no per-group mismatch lines printed
```

- Families: doc "## Traced Syscalls by Family" (12 groups: AIO, FS, IPC, Memory, Misc, Network, Polling, Process, Sched, Security, Signals, Time) ⇔ `syscallFamilies` (`internal/tracepoints/generated_tracepoints.go:738`) — identical keys and identical per-group syscall sets.
- Kinds: doc "## Traced Syscalls by TracepointKind" (33 kinds) ⇔ `syscallKinds` (`internal/tracepoints/generated_tracepoints.go:1108`) — identical.
- `List` (`internal/tracepoints/generated_tracepoints.go:4`) has 731 entries: 367 `sys_enter_*` + 364 `sys_exit_*`. The three noreturn syscalls (`exit`, `exit_group`, `rt_sigreturn`) intentionally appear enter-only (`List` lines 699, 735, …), matching the generator's documented suppression of exit handlers for noreturn syscalls (`internal/generate/codegen.go:152-176`, `noreturnSyscalls`; see also `internal/c/filter.c:86-96` comment).

The byte-classification section of the doc also matches `retClassifications` in `internal/generate/classify.go` (3 groups, identical sets).

The invariants above are exactly what the (now-broken) drift tests enforce: `internal/generate/docs_drift_test.go:17` (`TestSyscallTracingPlanBytesClassificationStaysInSync`) and `internal/tracepoints/docs_drift_test.go:22,37` (families/kinds). All three fail solely because the doc file is absent — content-wise the generated artifacts still match the doc as of HEAD (verified above). See Finding F1 (recorded, not fixed, per audit instructions).

### 1.1.b — "Cross-check each generated tracepoint handler in `internal/c/generated_tracepoints.c` against the kernel's `syscalls/sys_enter_*` / `sys_exit_*` tracepoint layouts using `/sys/kernel/tracing/events/syscalls/`"

**Verdict: BLOCKED-needs-root** (live tracefs comparison impossible; strong static cross-check performed instead)

- Live check: `/sys/kernel/tracing/events/syscalls/` → `Permission denied` (shown above). `mage generate`'s input path also requires root: `readSyscallFormats()` (Magefile.go:773-780) runs `sudo -n sh -c 'find /sys/kernel/tracing/events/syscalls …'`, which fails without a sudo timestamp.
- Static cross-check performed: the generator derives every handler's argument index from the kernel `format` files (field order after `__syscall_nr`), via `Format.FieldNumber` (`internal/generate/format.go:27-36`) and the per-kind emitters (`internal/generate/bpfhandler.go`). I spot-checked >25 generated handlers against the documented x86-64 syscall signatures (syscall tracepoint `args[]` order == syscall argument order). **All match.** Examples (from `internal/c/generated_tracepoints.c`):

| Handler | Generated capture | x86-64 ABI | Match |
|---|---|---|---|
| `sys_enter_openat` (:11160) | filename←args[1], flags←args[2] | openat(dfd, filename, flags, mode) | ✓ |
| `sys_enter_open` | filename←args[0], flags←args[1] | open(filename, flags, mode) | ✓ |
| `sys_enter_execveat` | dirfd←args[0], filename←args[1], flags←args[4] | execveat(dfd, filename, argv, envp, flags) | ✓ |
| `sys_enter_renameat2` | oldname←args[1], newname←args[3] | renameat2(olddirfd, oldpath, newdirfd, newpath, flags) | ✓ |
| `sys_enter_fcntl` | fd←args[0], cmd←args[1], arg←args[2] | fcntl(fd, cmd, arg) | ✓ |
| `sys_enter_socketpair` | family/type/protocol←args[0..2], usockvec←args[3] | socketpair(family, type, protocol, sv) | ✓ |
| `sys_enter_dup3` | fd←args[0], flags←args[2] | dup3(oldfd, newfd, flags) | ✓ |
| `sys_enter_epoll_ctl` | epfd/op/fd←args[0..2], events deref←args[3] | epoll_ctl(epfd, op, fd, event*) | ✓ |
| `sys_enter_select` | nfds←args[0], timeout deref←args[4] | select(nfds, r, w, e, timeout*) | ✓ |
| `sys_enter_poll` / `ppoll` | nfds←args[1], timeout←args[2] (ms / timespec deref) | poll(fds, nfds, timeout) | ✓ |
| `sys_enter_clock_nanosleep` | flags←args[1], timespec deref←args[2], TIMER_ABSTIME guarded | clock_nanosleep(clk, flags, req*, rem) | ✓ |
| `sys_enter_nanosleep` | timespec deref←args[0] | nanosleep(req*, rem*) | ✓ |
| `sys_enter_pipe2` | upipefd←args[0], flags←args[1] | pipe2(pipefd*, flags) | ✓ |
| `sys_enter_perf_event_open` | attr deref←args[0], pid←args[1], cpu←args[2], group_fd←args[3], flags←args[4] | perf_event_open(attr*, pid, cpu, group_fd, flags) | ✓ |
| `sys_enter_ptrace` (:18603) | request←args[0], target_pid←args[1], data←args[3] | ptrace(request, pid, addr, data) | ✓ |
| `sys_enter_move_mount` | fd_a←args[0], fd_b←args[2], extra←args[4] | move_mount(from_dfd, from_path*, to_dfd, to_path*, flags) | ✓ |
| `sys_enter_kcmp` | fd_a←args[3], fd_b←args[4], extra←args[2] | kcmp(pid1, pid2, type, idx1, idx2) (documented override, `bpfhandler.go` `twoFdOverrides`) | ✓ |
| `sys_enter_mq_open` | name←args[0], oflag←args[1] | mq_open(name*, oflag, …) | ✓ |
| `sys_enter_keyctl` / `add_key` / `request_key` | option/key_serial/value per documented overrides | keyctl(option, …) / add_key(type*, desc*, payload*, plen, keyring) / request_key(type*, desc*, callout*, dest) | ✓ |
| `sys_enter_sendto` | fd←args[0] | sendto(fd, …) | ✓ |

- The context struct choice is deliberate and documented for this exact RHEL 9 kernel family: `internal/generate/bpfhandler.go:20-29` explains handlers use `struct syscall_trace_enter/exit` (present in `internal/c/vmlinux.h:137788-137800`, `args[]` flexible array at offset 16) rather than the BTF `trace_event_raw_sys_*` alias, because on RHEL 9's 5.14 rt-merge kernel the alias grows by 8 bytes (`preempt_lazy_count`) and trips the verifier's `max_ctx_offset` check (attach fails EACCES). `ctx->args[0..4]` accesses (max index used is 4) are within the 6-argument syscall context.

Residual risk (not verifiable without root): whether the committed tracepoint-ID constants (`#define SYS_ENTER_READ 851` etc., generated from the `ID:` lines of a specific kernel's format files) match this host's kernel IDs. Note these IDs are used purely as internal correlation keys (handlers hardcode them; the kernel's `__syscall_nr` is never read), and the Go side maps them via the generated `TraceId` tables, so ID drift across kernels does not affect correctness — but a full layout cross-check still requires reading tracefs as root.

### 1.1.c — "Confirm that `enter` handlers record `pid`, `tid`, `timestamp`, `trace_id`, and syscall-specific arguments (e.g., `fd`, `path`, `size`, `flags`)"

**Verdict: PASS** (one wording-level plan drift noted: `size` arguments are intentionally not captured)

The audit harness checked **all 731 handler bodies**:

```
== handler body checks over 731 handlers ==
  missing fields: map[]           ← every handler sets ev->pid, ev->tid, ev->time,
                                     ev->trace_id, ev->event_type
  filter() not first: []           ← filter() precedes all state/emission in every handler
```

- Every enter handler emits an event struct whose base header is `event_type, trace_id, time, pid, tid` (`internal/c/types.h:52-56` for `null_event`, similarly for all 23 event structs), populated from the single `filter(&pid,&tid)` call and `bpf_ktime_get_boot_ns()` (e.g., `internal/c/generated_tracepoints.c:9615-9637` for `sys_enter_read`; generator template `renderHandler`, `internal/generate/bpfhandler.go:60-87`).
- Kind-specific arguments are captured per kind (fd, filename/pathname/oldname+newname, flags, dirfd, family/type/protocol, mem addr/len/flags, poll nfds/timeout_ns, sleep requested_ns, keyctl option/key/value, ptrace request/target/data, perf attr, two-fd, dup3 flags, fcntl fd/cmd/arg, …) — spot-checked against the ABI in 1.1.b.
- Plan wording drift: input `size`/`count` arguments (e.g., `read(fd, buf, count)`) are deliberately **not** captured; payload bytes are classified from the **return value** instead (`retClassifications`, `internal/generate/classify.go`; documented in the tracing plan's "Bytes vs Non-Bytes Classification" section and in the plan note for 3.1). The plan's "e.g. … size" is illustrative; the code's behavior is the documented design. Not a bug.
- Related minor gap: `sys_enter_openat2` cannot capture `flags` (they live behind the `struct open_how *` pointer at args[2]) and emits the `-1` sentinel with the comment `// Probably OK` (`internal/c/generated_tracepoints.c:11213-…`; `internal/generate/bpfhandler.go:229`). See Finding F4.

### 1.1.d — "Confirm that `exit` handlers capture the return value (`ret`) and complement the `enter` event with the same `pid`/`tid` identity"

**Verdict: FAIL** (narrow, concrete: 3 of 364 exit handlers drop the return value)

- `pid`/`tid` identity: PASS for all 364 exit handlers — the same `filter()` call supplies pid/tid on both sides (same thread executes enter and exit, so tid is identical), and the harness verified every exit handler sets `ev->pid`/`ev->tid`.
- Return value capture: 361/364 exit handlers capture `ctx->ret`:
  - 339 emit `struct ret_event` with `ev->ret = ctx->ret` (+ `ret_type` classification), e.g. `sys_exit_read` (`internal/c/generated_tracepoints.c:9640-9661`), including null-kind/futex-kind/proc-kind exits (`sys_exit_clock_gettime`, `sys_exit_futex`, `sys_exit_bpf`, `sys_exit_timer_create`, `sys_exit_prctl`, `sys_exit_clone`, `sys_exit_kcmp` — all verified).
  - 22 emit their own ret-carrying structs: 17 `eventfd_event` (eventfd family + `pidfd_open`), 2 `accept_event`, 2 `pipe_event`, 1 `socketpair_event` — all set `ev->ret = ctx->ret` (generators `generateExtraSocketpair/Accept/Pipe/Eventfd`, `internal/generate/bpfhandler.go:316-371`).
  - **3 emit `struct null_event` with no `ret` field**: `sys_exit_seccomp` (:13391), `sys_exit_delete_module` (:14917), `sys_exit_init_module` (:14964). Harness output:

    ```
    exit handlers NOT capturing ctx->ret: [sys_exit_seccomp sys_exit_delete_module sys_exit_init_module]
    ```

    These handlers still pass `ctx->ret` into `ior_on_syscall_exit(...)` (so the kernel-side aggregate map records duration/errors, `internal/c/filter.c:98-121`), but the ring-buffer event loses the return value: downstream `streamrow.New` only populates `RetVal`/`IsError` when `pair.ExitEv` is a `*types.RetEvent` (`internal/streamrow/row.go:152-155`), so stream/CSV/Parquet rows for `seccomp`, `init_module`, `delete_module` always report `ret=0`, `is_error=false`, even on failure. Root cause: name-based classification maps the exit formats to `KindSeccomp`/`KindModule` (`internal/generate/classify.go:396-401`), whose registry entries use `structName: "null_event"` (`internal/generate/kindregistry.go:44-45`); generic exits that fall through to field-based classification correctly become `KindRet` (`ret_event`). See Finding F2 for severity/repro/fix.

### 1.1.e — "Verify that `internal/generate/` regenerates the exact same `generated_tracepoints.c` and Go files when run against the target kernel's tracing directory (`mage generate`)"

**Verdict: BLOCKED-needs-root** (C regeneration needs tracefs via `sudo -n`; the two Go artifacts were proven deterministic without root)

- `mage generate` → `GenerateTracepointsC` → `readSyscallFormats()` (Magefile.go:773-780) → `sudoOutput` (Magefile.go uses `sudo -n`): fails without root, and re-running it would rewrite generated sources (prohibited for this audit anyway).
- What could be verified root-free — **byte-exact in-memory regeneration of both Go artifacts** from their committed inputs, replicating the Mage targets:

  ```
  == determinism: generated_tracepoints.go reproduces byte-identical from
     generated_tracepoints.c + result.txt ==
  == determinism: generated_types.go reproduces byte-identical from
     types.h + generated_tracepoints.c ==
  ```

  (harness `audit/check/main.go`, calling `generate.ExtractTracepointsWithKinds` and `generate.ParseCTypesInput`/`GenerateTypesGo`/`AddTypesImports` exactly as `Magefile.go:400-446` does).
- Additionally, `mage generate` has a built-in drift guard: `writeTracepointsResult` (Magefile.go, `generateTracepointsC(strict=true)`) `diff -u`s the regenerated tracepoint-kind list against the committed `internal/c/generated_tracepoints_result.txt` and fails on drift.
- Cross-checks that the three committed artifacts are mutually consistent: 731 `List` entries ⇔ 731 `SEC("tracepoint/syscalls/…")` handlers, no entries in either direction missing (harness output in 1.1.a/appendix), and `generated_types.go`'s `TraceId` tables (731 IDs) regenerate byte-identically from the same C file.

---

## Item 1.2 — BPF Map & Ring Buffer Integrity

### 1.2.a — "Inspect `internal/c/maps.h` for map definitions: ring buffer (`event_map`), enter-state map (`syscall_enter_state_map`), aggregate map (`syscall_aggregate_map`), sampling-rate map (`syscall_sampling_rate_map`), and context maps (`socketpair_ctx_map`, `pipe_ctx_map`, `eventfd_flags_map`)"

**Verdict: PASS**

All seven maps are defined in `internal/c/maps.h` (the only `SEC(".maps")` definitions in the BPF code):

| Map | Definition | Type / max_entries | Value struct |
|---|---|---|---|
| `event_map` | maps.h:3-7 | RINGBUF, `1 << 24` (compile-time default) | — (per-event structs) |
| `socketpair_ctx_map` | maps.h:32-38 | HASH, 8192, key `__u32` (tid) | `socketpair_ctx` (maps.h:16-21) |
| `pipe_ctx_map` | maps.h:40-46 | HASH, 8192, key tid | `pipe_ctx` (maps.h:23-26) |
| `eventfd_flags_map` | maps.h:48-53 | HASH, 8192, key tid | `__s32` |
| `syscall_enter_state_map` | maps.h:60-65 | HASH, 32768, key tid | `syscall_enter_state` (maps.h:9-13) |
| `syscall_aggregate_map` | maps.h:67-72 | **PERCPU_HASH**, 4096, key `__u32` (enter trace ID) | `syscall_aggregate` (maps.h:15-…, 8-bucket histogram) |
| `syscall_sampling_rate_map` | maps.h:74-79 | HASH, 4096, key enter trace ID | `__u32` rate |

Every defined map is used: `event_map` (731 `bpf_ringbuf_reserve`), enter-state + aggregate + sampling in `internal/c/filter.c` (lookups at :60, :34, :104; updates at :77, :55), context maps in the generated handlers (socketpair 1, pipe 2, eventfd-family 17 enter/exit pairs). The Go side references the same names: `syscall_aggregate_map` / `syscall_sampling_rate_map` (`internal/syscall_aggregate_consumer.go:18-19`), `event_map` (`internal/bpfsetup.go:29`, `internal/ior_bpfsetup.go:102`). The per-CPU aggregate map is decoded correctly user-side (per-CPU stride decode, min-of-mins / max-of-maxes / summed counters, `internal/syscall_aggregate_consumer.go:150-200`).

### 1.2.b — "Verify that the ring buffer map size (`EventMapSize`) matches the value wired through `flags.Config` and `bpfsetup.go`" (plan note: maps.h default `1 << 24`, overridden at load time)

**Verdict: PASS** — the wiring is exactly as the plan describes

- Compile-time default: `maps.h:5` `__uint(max_entries, 1 << 24)`.
- Load-time override: `resizeBPFMaps` (`internal/bpfsetup.go:26-29`) calls `resizeBPFMap(bpfModule, "event_map", uint32(cfg.EventMapSize))`, which `SetMaxEntries` and **verifies** the applied size (`internal/bpfsetup.go:32-46`, error if `MaxEntries() != size`).
- Call order is load-safe: `setupBPFModule` → `loadBPFModule()` (opens object from embedded `ior.bpf.o`, `internal/bpfembed.go:23-31`) → `resizeBPFMaps` → `setBPFGlobals` → `BPFLoadObject()` → `applySyscallSamplingRates` → attach (`internal/ior_bpfsetup.go:49-90`). Resize happens **before** `BPFLoadObject`, so the ring buffer is created with the configured size.
- Config default: `flags.Config.EventMapSize = appconfig.DefaultEventMapSize` (`internal/flags/flags.go:108`), `DefaultEventMapSize = DefaultChannelBufferSize * 16 = 65536` (`internal/config/buffers.go:8-13`); CLI override `-mapSize` (`internal/flags/flags.go:186`) with validation `mapSize > 0` (`internal/flags/flags.go:302-305`).
- Consumer wiring matches the map name: `bpfModule.InitRingBuf("event_map", ch)` with channel capacity `DefaultChannelBufferSize` (4096) and `rb.Poll(300)` (`internal/ior_bpfsetup.go:95-107`).

### 1.2.c — "Check that map lookups and updates in BPF code use `BPF_ANY` semantics (not `BPF_NOEXIST`/`BPF_EXIST`) … verify `BPF_ANY` is appropriate for each call site"

**Verdict: PASS**

- `grep -rn 'BPF_ANY|BPF_NOEXIST|BPF_EXIST' internal/c/*.c internal/c/*.h`: the only flags used are **`BPF_ANY` at all 22 update sites** — 2 in `filter.c` (`syscall_aggregate_map` :55, `syscall_enter_state_map` :77) and 20 in the generated handlers (17 `eventfd_flags_map`, 2 `pipe_ctx_map`, 1 `socketpair_ctx_map`). `BPF_NOEXIST`/`BPF_EXIST` appear only as enum values inside `vmlinux.h:1226-1227` (kernel BTF), never used by ior.
- Appropriateness per call site:
  - `syscall_enter_state_map` (`filter.c:77`): `BPF_ANY` is correct — a per-tid enter state must **overwrite** any stale entry (e.g., enter events whose exit tracepoint was missed, or noreturn suppression); `BPF_NOEXIST` would fail the update and lose the new syscall's state. The exit path deletes the entry (`filter.c:117`), keeping the bounded 32768-entry map reclaimable; noreturn syscalls skip the write entirely (`filter.c:86-96`, `ior_on_noreturn_syscall_enter`) precisely to avoid unreclaimable entries.
  - `syscall_aggregate_map` (`filter.c:55`): fresh-insert with `BPF_ANY` after a failed lookup — correct upsert pattern; in-place mutation is used when the entry exists (`filter.c:34-46`).
  - context maps (`socketpair/pipe/eventfd`): keyed by tid, overwritten per enter, deleted on exit (`bpf_map_delete_elem` in each exit handler) — `BPF_ANY` correct; a stale entry from a previous same-tid syscall must be replaced.
- Map-update return codes are ignored at all 22 sites. This is benign degradation, not corruption: if the enter-state update fails (32768-entry cap exceeded), the exit path's lookup miss makes `ior_on_syscall_exit` return "emit anyway" (`filter.c:104-105`), so the ring-buffer pair is still emitted and Go-side pairing/duration (from event timestamps) is unaffected; only the kernel-side aggregate for that syscall is missed. Context-map update failure degrades the exit event to sentinel values (`-1`).

### 1.2.d — "Confirm that `internal/c/filter.c` enforces PID and TID filtering at the kernel side via global variables (`PID_FILTER`, `TID_FILTER`, `IOR_PID_FILTER`) before events are emitted to the ring buffer" (plan note: comm/path filtering is user-side only)

**Verdict: PASS**

- Globals: `internal/c/flags.h:3-5` declares `const volatile u32 IOR_PID_FILTER = -1; PID_FILTER = -1; TID_FILTER = -1;` (u32 `-1` = trace-all sentinel). User-space sets them before load: `setBPFGlobals` (`internal/bpfsetup.go:13-24`) sets `IOR_PID_FILTER = os.Getpid()`, `PID_FILTER = uint32(cfg.PidFilter)`, `TID_FILTER = uint32(cfg.TidFilter)`; Go defaults are `-1`/`-1` (`internal/flags/flags.go:106-107`), matching the C sentinel. There are **no BPF maps for PID filtering** — exactly as the plan notes.
- `filter()` (`internal/c/filter.c:131-146`): unconditionally excludes ior's own pid (`if (*pid == IOR_PID_FILTER) return FILTER;`, :136-138) — the tracer never traces itself even with no `-pid`; then accepts only when `-1 == PID_FILTER || *pid == PID_FILTER` **and** `-1 == TID_FILTER || *tid == TID_FILTER` (:141-144). Single-TGID gate, no fork-following — documented in the comment at :123-129.
- Enforcement point: `filter(&pid, &tid)` is the **first statement in all 731 handlers**, before any state-map write, sampling decision, or `bpf_ringbuf_reserve` (harness check `filter() not first: []`; template `renderHandler` in `internal/generate/bpfhandler.go:66-68`). Non-matching tasks emit nothing to the ring buffer.
- Comm/path filtering is confirmed **not** in BPF: `filter.c` and the generated handlers contain no comm/pathname matching logic; paths are captured (for later user-space filtering) but never filtered kernel-side — matching the plan note (`globalfilter` is Go-side, outside this domain).

---

## Item 1.3 — BPF Verifier & Safety

### 1.3.a — "Build the BPF object (`mage build`) and confirm zero verifier warnings on kernels 5.x, 6.x, and the CI/development kernel"

**Verdict: BLOCKED-needs-root** (verifier confirmation requires loading BPF; the compile half is verified)

- Compile: verified without re-running mage. `internal/c/ior.bpf.o` is a current build artifact (`file`: `ELF 64-bit LSB relocatable, eBPF … with debug_info`; mtime 2026-08-31 22:12, newer than every BPF source incl. `filter.c`/`generated_tracepoints.c` from 2025-06-11), and `mage test` — already run green by the orchestrator — has `mg.Deps(BpfBuild)` (Magefile.go:109-117), which compiles the object with `clang -g -O2 -Wall -fpie -target bpf -D__TARGET_ARCH_amd64 …` (Magefile.go:648-651) and embeds it (`internal/bpfembed.go:17`). So the BPF object compiles cleanly from the audited sources.
- Verifier at load time: requires root/CAP_BPF; `sudo -n` fails on this host → **BLOCKED-needs-root**. The same applies to the multi-kernel (5.x / 6.x / CI) verification, which additionally needs other hosts. Static evidence in lieu: the handlers contain no loops, all pointer results are NULL-checked, all user-memory reads are fixed-size and guarded (1.3.b), and the one deliberate RHEL-9-specific context-struct workaround is documented (`internal/generate/bpfhandler.go:20-29`), all of which are the usual verifier-failure sources.

### 1.3.b — "Audit `internal/c/ior.bpf.c` and `filter.c` for unbounded loops, null-pointer dereferences, or out-of-bounds memory accesses"

**Verdict: PASS** (one uninitialized-field hygiene issue found — Finding F3)

- **Loops**: zero `for`/`while`/`do` loops in the entire BPF codebase (`ior.bpf.c`, `filter.c`, `generated_tracepoints.c`, `maps.h`, `types.h`; `grep -cE '\bfor *\(|\bwhile *\(' → 0`). No bounded-loop verifier feature needed.
- **Null-pointer derefs**:
  - `bpf_ringbuf_reserve` result NULL-checked in **731/731** handlers (`grep -c 'if (!ev)' = 731`).
  - `bpf_map_lookup_elem` results NULL-checked at all sites: `filter.c` (:34 aggregate, :60 sampling rate, :104 enter state) and the 3 generated context-map lookups (socketpair/pipe/eventfd exit handlers), each guarding use of the pending value.
  - User-pointer reads are guarded: `if (ctx->args[N] != 0)` before every `bpf_probe_read_user` (epoll events, poll/select/ppoll timeouts, sleep timespecs, perf attr, socketpair sv, pipe pipefd).
- **Out-of-bounds**:
  - Histogram index: `ior_histogram_bucket_index` (`filter.c:7-23`) returns 0..7 and `ior_update_syscall_aggregate` additionally clamps `bucket_idx >= 8 → 7` (`filter.c:36-38`) before `existing->duration_histogram[bucket_idx]` — array is `[8]` (`maps.h:20`). Bounded.
  - All `bpf_probe_read_user` calls read compile-time fixed sizes (`sizeof(sv)`=8, `sizeof(pipefd)`=8, `sizeof(ts)`=16, `sizeof(tv)`=16, `sizeof(user_events)`=4, `sizeof(attr)`=16) — 10 call sites, all with `== 0` return checks (verified via `internal/generate/bpfhandler.go` emitters and the generated file).
  - Context `args[]` max index used is 4 (well within the 6-arg syscall context).
  - **One gap**: `struct ptrace_event._pad` (`internal/c/types.h:288`) is never written by `handle_sys_enter_ptrace` (`internal/c/generated_tracepoints.c:18615-18622` writes event_type, trace_id, pid, tid, time, request, target_pid, data — not `_pad`), so 4 bytes of stale ring-buffer memory are submitted and decoded user-side into `PtraceEvent.Pad` (`internal/types/fastdecode.go:477`). This is stale trace data from a previously submitted record, not kernel-memory disclosure, and the verifier does not require full initialization of ringbuf records — but it is an uninitialized-data hygiene defect. See Finding F3.
- Every other event struct's fields are fully initialized before `bpf_ringbuf_submit` (generator analysis of all 23 kinds; e.g., socketpair/pipe exits initialize sv0/sv1/fd0/fd1/flags/ret to sentinels before conditional overwrite, `internal/generate/bpfhandler.go:316-371`).

### 1.3.c — "Confirm that all helper calls use the correct return-code handling … BPF uses `bpf_ktime_get_boot_ns`; verify the Go-side reader uses matching clock semantics"

**Verdict: PASS**

Helper-by-helper (all call sites audited):
- `bpf_get_current_pid_tgid` (filter.c:132), `bpf_ktime_get_boot_ns` (731 handlers + filter.c:74,:108), `bpf_get_prandom_u32` (filter.c:66): no error returns; used correctly. Prandom is used as `(bpf_get_prandom_u32() % rate) == 0` for 1-in-N sampling with `rate==0` (aggregate-only) and `rate==1` (all) special-cased first (`filter.c:58-69`).
- `bpf_probe_read_user` (10 sites): all check `== 0` before using the data (poll/select/ppoll timeouts, sleep timespecs, perf attr, socketpair sv, pipe fds, epoll events).
- `bpf_probe_read_user_str` (79 sites): return value not checked — safe by construction: each destination is zeroed by `__builtin_memset` before the read (72 memsets: 8 filename+comm, 2 exec filename+comm, 57 pathname, 5 oldname+newname pairs …) and the size argument is the destination `sizeof`, so a failed read leaves an empty string, never uninitialized data.
- `bpf_get_current_comm` (8 sites: open/mq_open/exec family): return ignored, but the comm buffer is memset first and the write is bounded by `sizeof(ev->comm)`=16 — failure leaves zeros.
- `bpf_ringbuf_reserve`: NULL-checked 731/731. `bpf_ringbuf_submit`: void. `bpf_map_update_elem`/`bpf_map_delete_elem`: return ignored (benign degradation, analyzed in 1.2.c).
- **Clock semantics**: BPF uses `bpf_ktime_get_boot_ns` exclusively — 733 call sites, zero `bpf_ktime_get_ns`. Enter state stores `start_ns` from boot clock (`filter.c:74`), exit computes `duration = now - state->start_ns` with an explicit `now >= start_ns` guard (`filter.c:108-111`). Go side treats `Event.GetTime()` as an opaque uint64 and only ever subtracts BPF timestamps from BPF timestamps: `Pair.CalculateDurations` computes `Duration = exitTime - enterTime` and `DurationToPrev = enterTime - prevExitTime`, each with uint64-underflow guards for non-monotonic timestamps (`internal/event/pair.go:88-113`). No mixing of `time.Now()` (CLOCK_REALTIME/MONOTONIC) with BPF timestamps occurs anywhere in the duration path; the only wall-clock use in the row path is an independent warning-row timestamp (`internal/streamrow/row.go:174`) and parquet file metadata (`internal/parquet/schema.go:52-64`). Consequence (informational, not a bug): the exported `time_ns` field (stream rows / parquet `time_ns`) is raw boot-clock ns, not Unix epoch — consumers must not interpret it as wall-clock time; latency math is unaffected and consistent.

### 1.3.d — "Verify that string reads from user space (`filename` in `open_event`, `comm` in event structs) are bounded by `MAX_FILENAME_LENGTH` (256) and `MAX_PROGNAME_LENGTH` (16)"

**Verdict: PASS**

- Constants: `internal/c/types.h:3-4` (`#define MAX_FILENAME_LENGTH 256`, `#define MAX_PROGNAME_LENGTH 16`); struct fields use them directly (`open_event.filename/comm`, `exec_event.filename/comm`, `name_event.oldname/newname`, `path_event.pathname`).
- All 79 `bpf_probe_read_user_str` calls pass the destination's `sizeof` as the size — tally by destination:

  ```
  8  bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), …)
  57 bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), …)
  7  bpf_probe_read_user_str(ev->oldname,  sizeof(ev->oldname),  …)
  7  bpf_probe_read_user_str(ev->newname,  sizeof(ev->newname),  …)
  ```

  → filename/pathname/oldname/newname all bounded at 256. No hardcoded or oversized length arguments exist (`grep` for `_user_str` lines without `sizeof(` returns nothing).
- `comm` is populated by `bpf_get_current_comm(&ev->comm, sizeof(ev->comm))` at all 8 sites — bounded at 16 (kernel truncates `TASK_COMM_LEN` names anyway).
- Each string field is zeroed by `__builtin_memset` before the read (e.g., `generateExtraOpenWithFields`, `internal/generate/bpfhandler.go:222-232`: `memset(&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm))` — the two arrays are contiguous in the struct), so events never carry uninitialized string bytes even when the user pointer is invalid.

---

## Findings

### F1 (known issue, recorded — NOT fixed, per audit instructions) — Working-tree deletion of `docs/syscall-tracing-plan.md` breaks three doc-drift tests, not one

- **Severity**: Medium (build/CI hygiene; no runtime impact — generated artifacts remain mutually consistent and still match the doc content as of git HEAD).
- **Evidence / repro**:
  ```
  $ git status --short
   D docs/clickhouse-streaming-plan.md
   D docs/syscall-tracing-plan.md
  $ go test ./internal/generate/    -run TestSyscallTracingPlan -count=1
  --- FAIL: TestSyscallTracingPlanBytesClassificationStaysInSync
      docs_drift_test.go:20: read syscall tracing plan: open …/docs/syscall-tracing-plan.md: no such file or directory
  $ go test ./internal/tracepoints/ -run TestSyscallTracingPlan -count=1
  --- FAIL: TestSyscallTracingPlanFamiliesStayInSyncWithGeneratedMap   (docs_drift_test.go:22)
  --- FAIL: TestSyscallTracingPlanKindsStayInSyncWithGeneratedMap      (docs_drift_test.go:37)
  ```
- **Correction to the audit's known-failure list**: the orchestrator reported only `TestSyscallTracingPlanBytesClassificationStaysInSync` (internal/generate); in fact **three** tests across **two** packages fail, all with the same root cause (the missing doc file). Content-wise there is **no drift**: my harness proved the generated `syscallFamilies`/`syscallKinds`/`retClassifications` sets still exactly match the doc as of git HEAD (1.1.a).
- **Suggested fix**: restore the doc (`git checkout -- docs/syscall-tracing-plan.md`) or, if the removal is intentional, delete the three drift tests together with it. (Not performed per audit instructions.)

### F2 (confirmed bug) — `sys_exit_seccomp`, `sys_exit_init_module`, `sys_exit_delete_module` drop the syscall return value from ring-buffer events

- **Severity**: Low–Medium (data accuracy: error status is silently wrong for these syscalls in stream/CSV/Parquet outputs; kernel-side aggregates are unaffected).
- **Location**: handlers `internal/c/generated_tracepoints.c:13391` (`sys_exit_seccomp`), `:14917` (`sys_exit_delete_module`), `:14964` (`sys_exit_init_module`) — emit `struct null_event` (no `ret` field). Root cause in the generator: name-based classification pins the *exit* formats to `KindSeccomp`/`KindModule` (`internal/generate/classify.go:396-401`), whose kindRegistry entries map to `struct null_event` (`internal/generate/kindregistry.go:44-45`); every generic exit that is not name-pinned falls through to field-based classification and correctly becomes `KindRet` → `ret_event` with `ev->ret = ctx->ret`.
- **Impact**: `streamrow.New` populates `RetVal`/`IsError` only when the exit event is a `*types.RetEvent` (`internal/streamrow/row.go:152-155`), so every `seccomp`/`init_module`/`delete_module` row reports `ret=0`, `is_error=false` even when the syscall failed (`ctx->ret` is still passed to `ior_on_syscall_exit`, so the BPF aggregate map does count the error — `internal/c/filter.c:98-121`). This also contradicts the audit plan's 1.1.d expectation and the stale comment in `internal/event/interface_assertions.go:25` ("`*types.RetEvent` is the exit-side event for **all** syscalls").
- **Repro (static)**: `grep -n 'EXIT_NULL_EVENT' internal/c/generated_tracepoints.c` → exactly the three handlers above; harness output: `exit handlers NOT capturing ctx->ret: [sys_exit_seccomp sys_exit_delete_module sys_exit_init_module]`.
- **Suggested fix** (do not apply): in `classify.go`, restrict the `sys_exit_seccomp` / `sys_exit_init_module` / `sys_exit_delete_module` name-pins to the *enter* side (or remove the exit pins so the exit formats classify as `KindRet`), then run `mage generate`; alternatively give these kinds a ret-carrying exit struct. Add a generator test asserting every exit handler captures `ctx->ret`.

### F3 (confirmed bug) — `ptrace_event._pad` is never initialized in BPF; stale ring-buffer bytes are submitted and decoded

- **Severity**: Low (data hygiene; leaks 4 bytes of a previously submitted record into `PtraceEvent.Pad`; no kernel-memory disclosure, no verifier rejection).
- **Location**: struct field `internal/c/types.h:288` (`__s32 _pad;`); handler writes everything except `_pad` (`internal/c/generated_tracepoints.c:18615-18622`); generator never emits it (`generateExtraPtrace`, `internal/generate/bpfhandler.go:586-588`); user-space decodes the stale bytes (`internal/types/fastdecode.go:477` → `PtraceEvent.Pad`, exposed in `PtraceEvent.String()`/`Equals`, `internal/types/generated_types.go:2313-2331`).
- **Repro (static)**: the handler body above lists all written fields; `_pad` is absent (`grep '_pad' internal/c/generated_tracepoints.c` → no matches).
- **Suggested fix**: either delete `_pad` and read `data` via a fixed offset that keeps the struct's 48-byte layout intact for the Go decoder, or emit `ev->_pad = 0;` in `generateExtraPtrace` (preferred — no Go-side change needed). A belt-and-braces fix would memset the reserved event as a matter of policy.

### F4 (design gap) — `openat2` enter event never captures flags (always `-1` sentinel)

- **Severity**: Low (metadata accuracy; flags live behind the `struct open_how *` pointer at args[2] and are not dereferenced).
- **Location**: `internal/c/generated_tracepoints.c:11213-…` — `ev->flags = -1; // Probably OK`; generator fallback `internal/generate/bpfhandler.go:229`.
- **Suggested fix**: `bpf_probe_read_user` the `open_how.flags` field (offset 8 within `struct open_how { u64 flags; u64 mode; u64 resolve; }`) guarded by a NULL-pointer check, mirroring the existing perf-attr pattern; or document the limitation in the tracing plan.

### F5 (documentation drift, informational) — stale comments vs. code

- `internal/event/interface_assertions.go:25-27` claims `*types.RetEvent` is the exit-side event for **all** syscalls. Reality: 339 ret_event exits + 22 ret-carrying kind-specific exits (accept/pipe/socketpair/eventfd/pidfd) + 3 null_event exits without ret (F2). Comment predates the ret-carrying kinds.
- The plan's 1.1.c mentions `size` among captured enter arguments; the documented design classifies payload bytes from the return value instead (see 1.1.c) — plan wording drift, not a code defect.
- Plan 1.1.d's blanket "exit handlers capture the return value" is false for exactly the 3 handlers in F2.

---

## Plan-vs-code drift summary (Domain 1 scope)

| Plan statement | Code reality | Assessment |
|---|---|---|
| 1.1.a generated list == doc list | True vs doc@HEAD; doc file deleted in working tree | drift is *file removal*, not content (F1) |
| 1.1.b cross-check vs tracefs layouts | Arg indexes verified against ABI statically; live check needs root | BLOCKED, mitigated |
| 1.1.c enter records pid/tid/time/trace_id/args(+size) | All but `size` (by design) | wording drift only |
| 1.1.d exit captures ret + same pid/tid | 361/364 capture ret; all carry pid/tid | narrow FAIL (F2) |
| 1.2 ringbuf size note (1<<24 vs 65536 override) | Exactly as described; resize pre-load with post-check | accurate |
| 1.2 comm/path not in BPF | Confirmed | accurate |
| 1.3 boot-ns clock + Go reader | Confirmed consistent (deltas only, underflow-guarded) | accurate |

## Coverage gaps (root-blocked, carry into future audits)

1. Live verifier run (`ior` attach) on the dev kernel and on 5.x/6.x kernels — needs root/hosts.
2. Live tracefs layout cross-check (`/sys/kernel/tracing/events/syscalls/*/format`) and tracepoint-ID comparison against this host's kernel — needs root.
3. `mage generate` end-to-end on the target kernel (C artifact regeneration + result.txt drift diff) — needs root (`sudo -n find /sys/kernel/tracing …`).

---

## Domain 1 Summary

Domain 1 (BPF Kernel-Side Correctness) was audited statically against the plan's 13 checklist bullets, with every root-dependent experiment marked BLOCKED and replaced by the strongest available static verification (including a byte-exact in-memory regeneration of both generated Go artifacts and an automated audit of all 731 handler bodies). **Verdict counts: 9 PASS, 1 FAIL, 0 N-A, 3 BLOCKED-needs-root** (1.1.b tracefs cross-check, 1.1.e C regeneration via `mage generate`, 1.3.a verifier-at-load/multi-kernel). The kernel side of ior is in good shape: all seven documented maps exist and are wired correctly (ring buffer resized from `cfg.EventMapSize` = 65536 before load, `BPF_ANY` upserts throughout, PID/TID/IOR-self filtering enforced as the first statement of every handler), timestamps use `bpf_ktime_get_boot_ns` consistently with the Go reader's same-clock delta arithmetic, all user-space string reads are bounded at 256/16 bytes with memset fallbacks, and there are no loops, unchecked pointer dereferences, or unbounded memory accesses in any BPF program. The single FAIL is a narrow, low-severity accuracy bug: three exit handlers (`seccomp`, `init_module`, `delete_module`) emit `null_event` and therefore lose the syscall return value and error status for ring-buffer consumers (F2), compounded by an uninitialized `_pad` field in ptrace events (F3) and the `openat2` flags gap (F4). The pre-existing working-tree deletion of `docs/syscall-tracing-plan.md` breaks three doc-drift tests across two packages (F1 — broader than the single failure the orchestrator reported), though the generated tracepoint sets provably still match the deleted doc's content at git HEAD. None of the findings indicate verifier-hostile code, ring-buffer corruption, or filter bypass; the domain is fit for purpose subject to the root-blocked live verifications being performed on a privileged host.