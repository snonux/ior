# Domain 7 — Build, Generation & CO-RE Portability (Audit Report)

> Historical audit evidence for the commit named below. Use [README.md](../README.md) and [AGENTS.md](../AGENTS.md) for current behavior.

**Project**: ior (I/O Riot NG) at `/home/paul/git/ior`
**Audit basis**: `PLAN-PROJECT-AUDIT.md` (repo root), section "## Domain 7 — Build, Generation & CO-RE Portability", items 7.1–7.3 (10 checklist bullets).
**Commit audited**: working tree at `b170575` ("audit(domain-06): filtering & sampling verification report", HEAD) plus the known uncommitted deletions of `docs/syscall-tracing-plan.md` / `docs/clickhouse-streaming-plan.md` (pre-existing, left exactly as found per audit constraints; they cause the 3 known drift-test failures recorded below).
**Date**: 2026-09-01. **Host**: `rocky`, kernel `5.14.0-687.36.1.el9_8.x86_64` (RHEL 9), user `paul` (uid 1000), go1.26.2, mage v1.17.2, clang (system), libbpfgo checkout at `../libbpfgo` verified pinned at `v0.9.2-libbpf-1.5.1` with the static toolchain (`output/libbpf/libbpf.a` present).

**Environment facts that shaped the audit**:

- No interactive root (`sudo -n true` → "a password is required"). However, this audit host has **purpose-scoped sudoers NOPASSWD rules for user paul** (verified via `sudo -n -l`):
  - `(root) NOPASSWD: /usr/bin/sh -c LC_ALL=C find /sys/kernel/tracing/events/syscalls -maxdepth 2 -mindepth 2 -name format | sort | xargs cat` — the exact command `mage generate` uses to read tracefs (Magefile `readSyscallFormats`). So **generation could run without a root prompt**.
  - `(root) NOPASSWD: /usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c` — the exact command `ensureVMLINUX()` uses to regenerate `internal/c/vmlinux.h` (verified working).
  - `(root) SETENV: NOPASSWD: /home/paul/git/ior/integrationtests.test` and `/home/paul/git/ior/ior` — enabling the root-gated integration suite to run non-interactively (absolute paths — see Finding F3).
- `docker` is a **rootless podman 5.8.2 emulation** (`Emulate Docker CLI using podman`); the rootful podman socket (`/var/run/docker.sock` → `/run/podman/podman.sock`) is root-only. Local image store is **empty** (no `ior-builder:rocky9/8` images).
- All evidence logs are under `audit/check/` (this report cites them as `audit/check/NN-*.log`); audit helpers live under `audit/check/_gosizes/` and `audit/check/cevidence/`. No source files were modified; the only working-tree actions were the instructed `git checkout --` reverts of generated files (tree verified pristine at the end, see §Hygiene).

---

## Item 7.1 — Code Generation Determinism

### 7.1.1 "Run `mage generate` on a clean tree and confirm `git diff` shows no changes (or only expected changes if the kernel tracepoint set differs)"

**Verdict: FAIL** (diff appeared on a clean tree → reverted per audit instructions; root cause is the documented kernel-tracepoint-set difference; **per-kernel determinism itself PASSES** — see below).

Evidence (`audit/check/01-generate.log`, `audit/check/01b-generate-run2.log`):

```
$ mage generate                      # run 1, clean tree (only the 2 known doc deletions)
exit: 1
Generating tracepoint and type artifacts...
Generating C tracepoints...
Reading syscall format files...
Reading syscall format files with one sudo call...     # sudoers NOPASSWD rule matched
Parsing syscall formats...
Writing generated C tracepoints...                      # C file OVERWRITTEN here (see F2)
Error: running "diff -u internal/c/generated_tracepoints_result.txt
        internal/c/generated_tracepoints_result.txt.new" failed with exit code 1
```

The strict diff gate rejected the regenerated result file: the **committed artifacts were generated on a newer kernel** than this host. On `5.14.0-687.36.1.el9_8`, 32 handlers (16 syscalls, enter+exit) present in the committed set do not exist:

```
sys_enter/exit_{file_getattr,file_setattr,getxattrat,listmount,listns,listxattrat,
lsm_get_self_attr,lsm_list_modules,lsm_set_self_attr,mseal,open_tree_attr,removexattrat,
setxattrat,statmount,uprobe,uretprobe}   # 16 names × enter+exit = 32 lines removed
```

`git diff --stat` after the failed run:

```
 internal/c/generated_tracepoints.c | 2712 +++++++++++++---------------------
 3 files changed, 930 insertions(+), 3516 deletions(-)   # incl. the 2 known doc deletions
```

**Per instructions, the generated file was reverted** (`git checkout -- internal/c/generated_tracepoints.c`; the gitignored `generated_tracepoints_result.txt.new` transient was removed). `internal/types/generated_types.go` and `internal/tracepoints/generated_tracepoints.go` were **never touched** (the strict-gate failure aborts `SerialDeps` before those targets run). The known doc deletions were not touched at any point.

**Per-kernel determinism check** (run 2 after revert, same host):

```
$ mage generate                      # run 2 → same strict-gate failure, exit 1
$ diff -q gen-run1-generated_tracepoints.c gen-run2-generated_tracepoints.c
  RUN1 == RUN2 (C file byte-identical)
$ diff -q gen-run1-result.txt gen-run2-result.txt
  RUN1 == RUN2 (result file byte-identical)
$ strict-gate diff content identical across runs
```

Conclusion: the generator is **deterministic for a fixed kernel** (two runs byte-identical, ordering forced by `LC_ALL=C find | sort`), but the committed generated artifacts are **not reproducible on this audit host** because the tracepoint set differs (newer generation kernel). The plan itself anticipates "expected changes if the kernel tracepoint set differs", but per the audit instructions a diff on a clean tree is recorded as a finding (F4), plus the pre-gate overwrite hazard (F2).

### 7.1.2 "Verify that `internal/generate/` reads from `/sys/kernel/tracing` and that the generated C handlers are syntactically valid (compile with `mage build`)"

**Verdict: PASS**

Evidence:

- Code: `Magefile.go` `readSyscallFormats()` reads the kernel tracepoint formats via
  `sudo -n sh -c 'LC_ALL=C find /sys/kernel/tracing/events/syscalls -maxdepth 2 -mindepth 2 -name format | sort | xargs cat'`, feeding `generate.ParseFormats` / `generate.GenerateTracepointsC` (package `internal/generate`). Test fixtures in `internal/generate` are documented as taken "verbatim from /sys/kernel/tracing/events/syscalls/…".
- Empirical: the read itself **succeeded** via the scoped sudoers rule (both runs parsed a full syscall format set — see 7.1.1 transcripts). Direct user-level access is denied (`ls /sys/kernel/tracing/events/syscalls/` → `Permission denied`), i.e. generation is genuinely root-gated by design; the sudoers provisioning made it exercisable here.
- Syntactic validity: `internal/c/ior.bpf.c` `#include`s `generated_tracepoints.c` (and `filter.c`), and `mage build` compiles the whole BPF translation unit with `clang -g -O2 -Wall -fpie -target bpf` — **exit 0** (see 7.3.1/02-build.log). The only warnings originate in the bpftool-dumped `vmlinux.h`, not in generated or hand-written ior BPF code (F7). Additionally, the regenerated-this-kernel C file from run 1 (saved under `audit/check/cevidence/`) is byte-stable across runs, and the committed file contains e.g. `sys_enter_mseal`/`sys_enter_statmount` handlers (newer-kernel set), all compiling cleanly.

### 7.1.3 "Confirm that `internal/types/generated_types.go` maps C struct fields to Go fields with correct sizes and alignments"

**Verdict: PASS**

Method: cross-checked three ways using audit helpers (C: `gcc -Wall` program including `internal/c/types.h` printing `sizeof`/`offsetof`, saved at `audit/check/cevidence/csizes.c`; Go: `unsafe.Sizeof`/`binary.Size` probe at `audit/check/_gosizes/main.go`, run via `go run -tags audit_sizes`, underscore dir + build tag keep it out of `./...`), against the kernel-payload size constants in `internal/types/fastdecode.go`. Full transcript: `audit/check/05-sizes.log`.

Results — **all 23 event structs** (`open, exec, null, fd, ret, name, path, fcntl, dup3, open_by_handle_at, socket, socketpair, accept, pipe, eventfd, epoll_ctl, poll, mem, sleep, two_fd, keyctl, ptrace, perf_open`):

- `unsafe.Sizeof(Go struct) == sizeof(C struct)` for **23/23** (304, 304, 24, 32, 40, 536, 280, 40, 32, 32, 40, 56, 40, 48, 40, 40, 40, 56, 32, 40, 40, 48, 56).
- `binary.Size(Go struct)` (the packed wire format of the generated `Bytes()`/`New*()` `encoding/binary` codecs) == the `*SizeV1` constants in `fastdecode.go` for every struct that has them (e.g. open 300, ret 36, socketpair 52, accept 36, pipe 44, poll 36, ptrace 48).
- `sizeof(C struct)` == the kernel-payload `*Size` constants (`openEventSize=304`, `retEventSize=40`, `acceptEventSize=40`, `pipeEventSize=48`, …) — i.e. the constants really are the ring-buffer reservation sizes (`bpf_ringbuf_reserve(..., sizeof(struct X), 0)`).
- C alignment padding is **explicitly and correctly** handled: `offsetof` verification of the special-cased fast-decoder offsets — `accept_event.ret @ 32`, `socketpair_event.ret @ 48`, `pipe_event.ret @ 40`, `eventfd_event.ret @ 32`, `poll_event.timeout_ns @ 32`, `ptrace_event.data @ 40` (the C struct's explicit `__s32 _pad` is mirrored as a Go `Pad int32` field, keeping packed==C layout for ptrace), `open_event.filename @ 28` — all match `NewXxxEventFast`'s size-gated offset logic (e.g. `NewAcceptEventFast`: `retOffset = 32` for 40-byte kernel payloads, 28 for 36-byte V1/test payloads). `fastdecode.go`'s header comment documents exactly this design (kernel `sizeof` includes internal+trailing padding; Go `binary.Write` produces the unpadded V1 layout; fast decoders accept both).

Example transcript (`audit/check/05-sizes.log`):

```
sizeof(struct accept_event ) = 40      offsetof(accept_event, ret)          = 32
sizeof(struct socketpair_event) = 56   offsetof(socketpair_event, ret)      = 48
Go AcceptEvent      unsafe.Sizeof=40   binary.Size=36
Go SocketpairEvent  unsafe.Sizeof=56   binary.Size=52
```

Caveat noted: the repo's own tests (`internal/types`) only verify Go-side roundtrips (`TestSerialization`, `TestFastDecodersMatchGeneratedDecoders`) — the C↔Go size/alignment parity is not asserted by any in-repo test; it was verified here by the external helpers (and end-to-end by the 192 passing root integration tests, 7.3.4).

---

## Item 7.2 — Static Linking & Portability

### 7.2.1 "Run `mage buildDocker` and confirm the resulting `ior` binary is fully static (`ldd ior` → `not a dynamic executable`)"

**Verdict: N-A** (docker present but insufficient: the build requires a **rootful** docker daemon / true `--privileged`; only rootless podman is reachable). Supplementary static-linking evidence below still confirms the property.

Evidence (`audit/check/04-docker.log`):

```
$ docker info          → exit 0 (Client/Server: Podman Engine 5.8.2, rootless,
                          runRoot /run/user/1000/containers)
$ ls -la /var/run/docker.sock /run/podman/podman.sock
  /var/run/docker.sock -> /run/podman/podman.sock   (root-only: Permission denied)
$ docker images        → REPOSITORY/TAG: <none>  (image store empty — ior-builder images never built here)
$ docker pull docker.io/library/alpine:3           → OK (network works)
$ docker run --rm --privileged -v /sys/kernel/tracing:/sys/kernel/tracing \
      alpine:3 ls /sys/kernel/tracing/events/syscalls/
  ls: /sys/kernel/tracing/events/syscalls/: Permission denied     (exit 1)
$ docker run --rm --privileged --user 0:0 -v /sys/kernel/tracing:… alpine:3 cat …/format
  Permission denied                                                 (exit 1)
$ docker run --rm --privileged -v /sys/kernel/btf:/sys/kernel/btf alpine:3 ls -la /sys/kernel/btf/
  total 0   (bind-mounted BTF dir appears EMPTY under rootless podman)
```

`Dockerfile`'s CMD is `IOR_FORCE_GENERATE=1 mage generate && mage all` and relies on "The container runs as root so bpftool and /sys/kernel/tracing are used directly" (comment in `scripts/build-with-docker.sh`). Under rootless podman the container's root maps to host uid 1000, so the tracefs mount stays unreadable and the BTF mount is empty — the in-container `mage generate` would fail exactly as above. Hence `buildDocker`/`buildDockerEl8` require a rootful daemon that cannot be reached in this environment → **N-A** per audit instructions.

**Supplementary static-linking evidence** (`audit/check/03-static.log`):

- Native `mage build` binary (built this audit, see 7.3.1): `file ior` → *"ELF 64-bit LSB executable, x86-64, statically linked"*; `ldd ior` → *"not a dynamic executable"*; `readelf -d` → *"There is no dynamic section in this file"*; `readelf -l` → no `INTERP` segment (no dynamic loader). This matches the expectation (`-ldflags '-w -extldflags "-static"'`, `-tags netgo`) and AGENTS.md.
- Pre-existing docker-path artifacts in the repo root (not rebuilt here): `ior` (earlier build) and **`ior.el8`** (from a prior `mage buildDockerEl8`) are both `file` → "statically linked" and `ldd` → "not a dynamic executable". So both documented docker build paths have historically produced fully static binaries; the fresh-verification of that specific path is what is N-A.
- The binary carries the BPF object embedded (`//go:embed c/ior.bpf.o` in `internal/bpfembed.go`), so a single static file contains the CO-RE program — consistent with the "copy to any BTF-enabled host" deployment model.

### 7.2.2 "Copy the binary to a different kernel version (with BTF enabled) and run `sudo ./ior -duration 5 -plain`; confirm it starts and emits events without recompilation"

**Verdict: BLOCKED-needs-root** (running any trace mode requires root — the mode registry's EUID gate; only the purpose-scoped sudoers commands are permitted, `sudo ./ior` is not among them — and no second host with a different kernel exists in this environment).

Partial supporting evidence gathered anyway (CO-RE load on this host, different from the generation kernel):

- The root integration run (7.3.4) executed the freshly built `./ior` **as root via sudoers** 200+ times on this 5.14 kernel: the BPF object — compiled from the *committed, newer-kernel* `generated_tracepoints.c` against this host's regenerated `vmlinux.h` — loaded and attached ~570 tracepoints, and ior **gracefully degraded** for the 32 tracepoints that don't exist on this kernel:
  `ior: skipping tracepoint for mseal: attach sys_enter_mseal: failed to attach tracepoint sys_enter_mseal to program handle_sys_enter_mseal: no such file or directory` (one line per missing tracepoint, then continue).
- `./ior --help` runs and exits 0 without root (flag/validation paths only).

The literal cross-kernel copy test (different kernel version host, `sudo ./ior -duration 5 -plain`) could not be performed.

### 7.2.3 "Repeat the portability test on the `ior.el8` binary (`mage buildDockerEl8`) on a Rocky Linux 8 host"

**Verdict: N-A** (same rootless-docker blocker for `mage buildDockerEl8` as 7.2.1; additionally no Rocky Linux 8 host exists in this audit environment, and running the binary would be root-gated as in 7.2.2).

Documented in lieu of execution: the pre-existing `ior.el8` (prior `buildDockerEl8` output) is fully static (`ldd ior.el8` → "not a dynamic executable", `file` → "statically linked"), i.e. the el8 artifact class matches the static-linking expectation; runtime portability on an actual EL8 host remains unverified.

---

## Item 7.3 — CI / Test Coverage

### 7.3.1 "Run `mage world` and confirm it completes with zero errors (`clean` → `generate` → `test` → `build`)"

**Verdict: FAIL** (as a single target on this host it cannot complete: it aborts at `generate`'s strict gate; the constituent steps were executed piecewise — build PASS, generate FAIL per 7.1.1, test step covered by the orchestrator's prior plain `mage test` = green except the 3 known drift failures).

Evidence (`audit/check/06-world.log`, `audit/check/06b-world-rebuild.log`):

```
$ mage world
exit: 1
World: cleaning...        # removed ./ior, internal/c/ior.bpf.o, internal/c/vmlinux.h (all gitignored)
World: generating...
  ... Reading syscall format files with one sudo call ... Writing generated C tracepoints ...
Error: running "diff -u internal/c/generated_tracepoints_result.txt
        internal/c/generated_tracepoints_result.txt.new" failed with exit code 1
                           # → world aborts before its test and build stages
```

Recovery/restoration performed immediately after (also serving as build re-verification): `git checkout -- internal/c/generated_tracepoints.c`; `mage build` → **exit 0**, which exercised `ensureVMLINUX()` → the scoped sudoers `bpftool btf dump` rule regenerated `internal/c/vmlinux.h` (2,765,039 bytes, this host's BTF — vs. the pre-existing 3,526,774-byte newer-kernel file, restored from backup at audit end to leave the tree byte-identical), rebuilt `internal/c/ior.bpf.o` and `./ior`. Note the regenerated-from-host `vmlinux.h` + committed `generated_tracepoints.c` combination is exactly what the subsequent root integration run validated (192 passes).

Additional observation (F6): `mage clean`/`world` deletes the gitignored `internal/c/vmlinux.h`, whose only regeneration path is root (`sudo bpftool btf dump`); on hosts without such provisioning a failed `world` leaves the tree unbuildable.

### 7.3.2 "Run `mage testRace` and confirm no data races are detected"

**Verdict: FAIL** — a **genuine, reproducible data race** was detected (Finding F1). All packages other than the TUI integration host package are race-clean.

Evidence:

`$ mage testRace` (as instructed; `-race -failfast -timeout=90m`; `audit/check/07-testrace.log`) → **exit 1**:

```
ok   ior/cmd/ioworkload  1.017s          ok  ior/integrationtests  2.111s (skips, non-root)
FAIL ior/internal        2.758s   --- FAIL: TestTUIIntegration_TabNav_NumberKeys (0.42s)
                                     testing.go:1712: race detected during execution of test
--- FAIL: TestSyscallTracingPlanBytesClassificationStaysInSync (0.00s)   [KNOWN drift, internal/generate]
ok: benchutil, event, export, file, flags, flamegraph, globalfilter … then -failfast stops
```

Because `-failfast` truncates the suite at the known drift failures, a **full non-failfast race sweep** was run additionally (env replicating Magefile `goEnv()` with absolute libbpfgo paths, as AGENTS.md prescribes; `audit/check/07d-testrace-full.log`):

```
$ go test -race ./... -count=1 -timeout=60m     → exit 1
ok  : cmd/ioworkload, integrationtests, internal/{benchutil,event,export,file,flags,
     flamegraph,globalfilter,globalfilter/parser,globalfilter/presenter,parquet,
     probemanager,statsengine,streamrow,tui,tui/common,tui/dashboard,tui/eventstream
     (236.6s),tui/export,tui/flamegraph,tui/pidpicker,tui/probes,tui/tracefilter,types}
FAIL: ior/internal (TUI races + 0 others), ior/internal/generate (1 known drift),
      ior/internal/tracepoints (2 known drift)
```

- **Total `WARNING: DATA RACE` reports: 20**, every one with the same writer: `ior/internal/tui/common.ApplyPalette()` (`styles.go:94–122`, writes ~20 package-level style/color globals) reached via `tui.newModelWithRuntimeConfig` (`tui.go:403`); readers are bubbletea render goroutines in `Model.View()` → `dashboard.Model.View` (`model.go:1196`), `renderSyscallBox` (`overview.go:57/78`), `common/table.go:36/38`, `flamegraph/renderer.go:782`, `controls.go:118` — i.e. the render loop of a *previous* teatest session still reading the globals while the next test's model construction rewrites them.
- **9 TUI integration tests fail under `-race`** with "race detected during execution of test": TabNav_NumberKeys, HelpOverlay_Toggle, Flame_ZoomInOut, Flame_MatchNextPrev, Stream_FilterModal_OpenCancel, Stream_RowsRender, ProbesModal_NavSearchToggleClose, Live_FlamegraphUpdatesOverTime, Live_PauseFreezesUpdates.
- **100% reproducible**: focused reruns `go test ./internal -race -run TestTUIIntegration -count=1` twice → **15 races / 8 failures in both** (`audit/check/07c-tui-race-repro-{1,2}.log`).
- **Production exposure (not just a test artifact)**: `tui.go:521-522` `case tea.BackgroundColorMsg: m.applyTheme(msg.IsDark())` → `applyTheme` (`tui.go:1153`) → `common.ApplyPalette(isDark)` runs **inside the Update path while the renderer concurrently calls View()** — the OSC 11 background-color reply arrives asynchronously after rendering has started, and any runtime terminal theme change re-fires it. The globals are mutated unsynchronized (no lock/atomic), which is a Go memory-model violation with torn-palette rendering as the visible symptom.
- The 3 remaining failures are **exactly the known drift tests** (`no such file or directory … docs/syscall-tracing-plan.md`): `TestSyscallTracingPlanBytesClassificationStaysInSync` (internal/generate) + `TestSyscallTracingPlanFamiliesStayInSyncWithGeneratedMap` / `TestSyscallTracingPlanKindsStayInSyncWithGeneratedMap` (internal/tracepoints) — pre-existing, caused by the uncommitted doc deletions, not fixed per constraints.

### 7.3.3 "Run `mage bench` and record baseline numbers; ensure no benchmark panics"

**Verdict: N-A** (deferred) — per orchestrator instruction a separate audit task owns the benchmark/bench-profiling domain; skipped here to save resources. Not run; no evidence recorded.

### 7.3.4 "Run `mage integrationTest` and confirm all integration tests pass"

**Verdict: FAIL** — the **`mage integrationTest` target itself is broken** (invocation path bug, Finding F3); the underlying suite, run via the sudoers-intended invocation, is **192 PASS / 1 SKIP / 9 FAIL as root**, with all 9 failures environment/kernel-caused (none are ior code defects).

Evidence:

```
$ mage integrationTest                 # audit/check/08-integration.log
exit: 1
  … BPF build + static go build (only the benign warnings of F7) …
Building ioworkload binary...
Running integration tests in parallel (requires root, parallel=2)...
Error: exit status 1                  # ← child's stdout/stderr are discarded (see F3)
```

Root cause demonstrated empirically:

```
$ ls integrationtests/integrationtests.test          # where the runner looks (cmd.Dir="integrationtests")
  ls: cannot access 'integrationtests.test': No such file or directory
$ ls integrationtests.test                           # where `go test -c -o integrationtests.test` put it
  20915904 … (repo root)
$ cd integrationtests && sudo -n -E /home/paul/git/ior/integrationtests.test -test.list '.*'
  TestAioSetup … (202 tests listed, exit 0)          # intended invocation works (matches sudoers)
```

The suite itself (`audit/check/08b-integration-root.log`; `sudo -n -E` from `integrationtests/` cwd so the harness's `../ior`/`../ioworkload` resolve; args mirroring the mage target — `-test.count=1 -test.timeout=30m -test.parallel 2`, `IOR_INTEGRATION_PARALLEL=1` — plus `-test.v` for the audit inventory, `-test.failfast` dropped to get full counts):

```
$ sudo -n -E /home/paul/git/ior/integrationtests.test -test.v …
exit: 1        PASS: 192 | SKIP: 1 | FAIL: 9   (of 202 tests)
```

The 9 failures, all classified from the log:

| Test | Failure | Classification |
|---|---|---|
| TestXattrGetxattrat, …Setxattrat, …Removexattrat, …Listxattrat | `workload: exit status 1: scenario … failed: {get,set,remove,list}xattrat: function not implemented` | ENOSYS — syscalls are Linux 6.13+ (per the test's own doc comment); absent on 5.14 host |
| TestXattrSetxattr | same `xattr-getxattrat` scenario ENOSYS (test intentionally **reuses** that scenario — `xattr_test.go:79`) | collateral of the above (setxattr itself exists; see F8) |
| TestIouringSetup/Enter/Register | `workload: exit status 1: scenario … failed: io_uring_setup: operation not permitted` | EPERM — RHEL 9 disables io_uring by policy |
| TestMountFsManagementSyscalls | `expected event not found: {Tracepoint:enter_statmount/listmount/listns …}` | tracepoints don't exist on 5.14; ior logged graceful `skipping tracepoint …` and continued |

The 1 root-run SKIP: `TestPosixMqBasic` — `mq syscalls unavailable in this environment: … mq_open: permission denied` (environment). Non-root behavior (root-gating design): direct run of the test binary as `paul` → **24 PASS / 178 SKIP ("requires root for BPF") / 0 FAIL, exit 0** — exactly the documented `t.Skip` semantics.

---

## Findings

**F1 — Data race on TUI style globals (`ApplyPalette`) — HIGH (CI-blocking; production-latent)**
- What: `internal/tui/common.ApplyPalette()` (`styles.go:91–135`) rewrites ~20 package-level style/color globals (`ColorBackground`, `ScreenStyle`, `TabActiveStyle`, `TableSelectedCellStyle`, …) with no synchronization. Writers: every model construction (`tui.newModelWithRuntimeConfig`, `tui.go:403`) and the runtime theme switch `Model.applyTheme` (`tui.go:1153`, triggered by `tea.BackgroundColorMsg` at `tui.go:521-522`). Readers: bubbletea's render goroutine via `Model.View()` (`dashboard/model.go:1196`, `overview.go:57/78`, `common/table.go:36/38`, `flamegraph/renderer.go:782`, `controls.go:118`).
- Repro: `mage testRace` (fails at `ior/internal`), or focused: with the goEnv CGO env — `go test ./internal -race -run 'TestTUIIntegration' -count=1` → 15 `WARNING: DATA RACE`, 8–9 test failures, 100% over 2+ invocations (logs 07/07c/07d).
- Impact: `mage testRace` can never be green; in production the async OSC 11 background-color reply (or a terminal theme change) rewrites the palette mid-render → undefined behavior per the Go memory model; visible symptom at best torn palette. Consecutive teatest sessions overlap because `t.Cleanup(func(){ _ = tm.Quit() })` does not await full render-loop termination.
- Suggested fix (do not apply per audit constraints): make the palette immutable per model (construct styles in `NewModel` and pass them down / store on the `Model`), or guard the globals with `atomic.Pointer[Palette]`/RWMutex; and make teatest cleanup wait for program termination before the next model is constructed.

**F2 — `mage generate` dirties the tree even when it (correctly) fails — MEDIUM**
- What: `generateTracepointsC` writes `internal/c/generated_tracepoints.c` (and `generated_tracepoints_result.txt.new`) **before** running the strict diff gate; on gate failure mage exits 1 but the C file stays overwritten (observed: 2712-line diff after an exit-1 run on this kernel), silently leaving kernel-specific artifacts in the checkout. The gate only protects the result file, not the C file.
- Repro: `mage generate` on any host whose tracepoint set differs from the generation kernel → exit 1 + `git status` shows ` M internal/c/generated_tracepoints.c`.
- Suggested fix: render to a temp file, run the strict gate, then atomically replace (and remove the `.new` transient); or `git restore` the file on gate failure.

**F3 — `mage integrationTest` invocation is broken (path + discarded output) — MEDIUM**
- What: `compileIntegrationTestBinary` builds `integrationtests.test` at the **repo root** (`go test -c ./integrationtests/... -o integrationtests.test`), but `runIntegrationTestBinary` execs `./integrationtests.test` with `cmd.Dir = "integrationtests"` → resolves to `integrationtests/integrationtests.test`, which never exists → the target always fails with an opaque `Error: exit status 1` (the child's stdout/stderr are not wired, so the cause is invisible). It also leaves the 20.9 MB **untracked** `integrationtests.test` at the repo root (not covered by `mage clean`). The provisioned sudoers entry (`/home/paul/git/ior/integrationtests.test`, absolute) confirms the intended form.
- Repro: `mage integrationTest` on this host (build steps succeed, run step exits 1 without a message).
- Suggested fix: use the absolute binary path (`filepath.Abs`) in `runIntegrationTestBinary` (or `-o integrationtests/integrationtests.test`), wire `cmd.Stdout/Stderr` through to mage's output, and add the test binary to `mage clean`.

**F4 — Committed generated artifacts are kernel-specific and not reproducible on older hosts — MEDIUM (environment/doc)**
- What: `internal/c/generated_tracepoints.c`, `internal/tracepoints/generated_tracepoints.go`, `internal/types/generated_types.go` (and the gitignored `internal/c/vmlinux.h`, 3.53 MB) were generated on a **newer kernel** than this audit host; regenerating on `5.14.0-687.36.1.el9_8` removes 32 handlers (16 syscalls: mseal, statmount, listmount, listns, {get,set,remove,list}xattrat, lsm_*, uprobe/uretprobe, open_tree_attr, file_getattr/setattr) and fails the strict gate (by design). Downstream consequences observed: 32 tracepoints skipped at attach on this host (graceful), 9 integration-test failures (7.3.4). By design, `Dockerfile` CMD runs `IOR_FORCE_GENERATE=1 mage generate` against the container host's kernel, so `mage buildDocker` on a machine with a different kernel **rewrites the checkout's committed generated files** (documented in the Dockerfile comment as intentional).
- Suggested fix: record the generation kernel version alongside the artifacts (stamp file / doc), and/or surface a clear error message from the drift gate naming the kernel mismatch; consider committing the expected-kernel stamp into `generated_tracepoints_result.txt`.

**F5 — `IOR_FORCE_GENERATE` env contract bug — LOW**
- What: `Magefile.go` `Generate()`: `force := EqualFold(forceEnv,"1") || EqualFold(forceEnv,"yes") || forceEnv != ""` — the last clause makes **any non-empty value force generation**, including `IOR_FORCE_GENERATE=0`, `no`, or `false`, contradicting the documented "If IOR_FORCE_GENERATE=1 is set" contract. A user trying to explicitly *disable* forcing silently gets the force path.
- Suggested fix: strict parsing (accept only `1`/`yes`/`true`).

**F6 — `mage clean`/`world` deletes `internal/c/vmlinux.h`, recoverable only with root — LOW**
- What: `cleanBPFArtifacts()` removes the gitignored `internal/c/vmlinux.h`; `ensureVMLINUXX()` regenerates it only via `sudo bpftool btf dump …`. A `mage world` that then fails at `generate` (as on this host) leaves the tree without `vmlinux.h` — unbuildable on hosts without root or the scoped sudoers rule. (Here recovery was verified via the sudoers rule; the regenerated file differs from the original because the BTF source kernel differs — 2.77 MB vs 3.53 MB — and the pre-audit file was restored from backup at audit end.)
- Suggested fix: regenerate-before-delete, or fail fast with an actionable message when root is unavailable, or vendor a baseline `vmlinux.h`.

**F7 — Build warnings (benign, documented for completeness) — INFO**
- clang `-Wmissing-declarations` ×5 during `BpfBuild` — all inside the bpftool-dumped `internal/c/vmlinux.h` (forward declarations in BTF C dumps); none from ior's own BPF or generated code.
- Static-glibc NSS linker warnings ×5 (`getgrouplist/getgrgid_r/getgrnam_r/getpwnam_r/getpwuid_r … requires at runtime the shared libraries from the glibc version used for linking`) during the static Go link. Dormant: `grep os/user` over `internal/ cmd/` finds no importer (and `-tags netgo` is used), so no NSS lookups occur. They are a standing portability hazard if `os/user` is ever adopted in the static binary.
- No BPF *verifier* output exists at build time by design (verification happens at load); the effective load-time verification evidence is the 192-test root integration run with zero verifier rejections beyond the graceful missing-tracepoint skips.

**F8 — Integration-test scenario coupling on older kernels — INFO**
- `TestXattrSetxattr` intentionally reuses the `xattr-getxattrat` scenario (`integrationtests/xattr_test.go:79`, comment explains the reuse); that scenario's `ioworkload` hard-fails (`exit status 1`) on the first ENOSYS `getxattrat` call, so `setxattr` — which exists on 5.14 and would pass — fails collaterally. Suggested fix: have the workload tolerate ENOSYS per-syscall (skip-and-continue) or split the scenarios.

## Plan-vs-code drift notes

- Plan 7.3 lists `mage bench` under this domain; per orchestrator instruction it is owned by a separate audit task → recorded N-A, not a code drift.
- Plan 7.2's `ldd ior` expectation ("not a dynamic executable") matches observed behavior for the native `mage build` output; the plan's assumption that `mage buildDocker` is runnable anywhere docker exists is optimistic — it needs a **rootful** daemon (rootless podman cannot read tracefs/BTF mounts), worth documenting in AGENTS.md/README.
- `Magefile.go` `checkDockerAvailable()` (used by `mage parquetValidate`) only checks `docker info`, which **succeeds** under rootless podman even though privileged builds cannot work — same class of false-positive availability as F3's silent failure.
- The `runIntegrationTests` README comment claims default parallelism `NumCPU * 2`; the code caps at `min(NumCPU, 2)` ("Conservative default for stability") — doc/code drift (cosmetic).
- Audit environment note (not repo state): the scoped sudoers rules on this host enabled `mage generate` and the root integration run without interactive root; on an unprovisioned host both would be BLOCKED-needs-root.

## Tree hygiene (end of audit)

- Working tree matches the pre-audit state exactly: only the two known doc deletions (` D docs/clickhouse-streaming-plan.md`, ` D docs/syscall-tracing-plan.md` — untouched as required), untracked `PLAN-PROJECT-AUDIT.md`, and this audit's untracked evidence under `audit/check/`. All three generated files verified identical to HEAD (`git diff HEAD --stat -- …` empty). `internal/c/vmlinux.h` restored byte-identical from backup. The stray 20.9 MB `integrationtests.test` left by the broken `mage integrationTest` was removed; `./ior`, `./ioworkload`, `internal/c/ior.bpf.o` remain as normal (gitignored) mage build outputs. Nothing staged, nothing committed.

## Domain summary

Domain 7 verdicts across the 10 checklist bullets: **2 PASS** (7.1.2 generation-pipeline validity, 7.1.3 C↔Go type size/alignment parity — the latter verified 23/23 by purpose-built C and Go helpers, including all alignment-padding special cases), **4 FAIL** (7.1.1 generation determinism-on-clean-tree — committed artifacts are newer-kernel-specific and a failed generate still dirties the tree; 7.3.1 `mage world` cannot complete zero-error on this host; 7.3.2 `mage testRace` — a genuine, 100%-reproducible, production-exposed data race on `tui/common` style globals (F1, 20 race reports, 9 TUI tests failing under `-race`, all other packages race-clean); 7.3.4 `mage integrationTest` — the target's invocation is broken (F3), while the suite itself runs 192/202 green as root with all 9 failures kernel/policy-caused (ENOSYS/EPERM/missing tracepoints) and ior's CO-RE degrade path (graceful tracepoint skipping) working as designed), **3 N-A** (7.2.1 `buildDocker`, 7.2.3 `buildDockerEl8`/EL8 host — rootful docker daemon unreachable under rootless podman; 7.3.3 bench — deferred to the dedicated benchmark task), and **1 BLOCKED-needs-root** (7.2.2 cross-kernel portability run). The build pipeline itself is sound — static linking is fully confirmed on the native build (and on the pre-existing docker artifacts), the BPF object embeds cleanly, and generation is deterministic per-kernel — but the domain is carried by three real tooling/CI defects (race F1, generate-ordering F2, integration-runner F3) plus the kernel-pinning of committed generated artifacts (F4), which together mean `mage world`/`testRace`/`integrationTest` cannot all be green on a host whose kernel differs from the generation kernel.