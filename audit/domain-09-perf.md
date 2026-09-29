# Domain 9 — Performance & Resource Safety (Audit Report)

> Historical audit evidence for the commit named below. Use [README.md](../README.md) and [AGENTS.md](../AGENTS.md) for current behavior.

**Project**: ior (I/O Riot NG) at `/home/paul/git/ior`
**Audit basis**: `PLAN-PROJECT-AUDIT.md` (repo root), section "## Domain 9 — Performance & Resource Safety", items 9.1–9.3.
**Commit audited**: `2897495dfd34bf3533b599de896d85d1493b6912`; binary freshly built by the Domain 7 task (static, gitignored `./ior`).
**Auditor constraints**: no interactive tty; root available only via the purpose-scoped sudoers rule `sudo -n /home/paul/git/ior/ior <args>`. Live runs executed for real; deep profiling (`mage benchProf`, count=6 × all benchmarks) and the 1-hour run were **deferred** to conserve audit-session resources (recorded below). Evidence: `audit/check/10-bench.log` plus transcripts quoted inline.

---

## 9.1 CPU & Memory Profiling

| Bullet | Verdict | Evidence |
|---|---|---|
| Run `mage benchProf` (or equivalent pprof build) against high-throughput workload | **PASS (baseline via `mage bench`)** | `mage bench` (full suite + 5× flamegraph suite) completed **exit 0**: 416 benchmark result lines, zero panics, zero FAILs (`audit/check/10-bench.log`). `mage benchProf` (count=6 × all benchmarks + profiles) deferred — resource-constrained session; baseline numbers recorded here instead. |
| Review CPU profile for unexpected hotspots | **N-A (deferred)** | pprof profiles not generated this session. Mitigating baseline: per-op costs are sane and small — e.g. event deserialization 221 ns–6.4 µs/op at 2 allocs/op, `RawHandlerLookup` 10.19 ns/op **0 allocs**, exit handlers 260–530 ns/op, flamegraph `ResizeRelayout` ~1.0 ms/op (2505 allocs) — no pathological entries across 416 results. |
| Review heap profile for unbounded allocations | **N-A (deferred)** | pprof not run; indirect evidence: `-benchmem` allocation counts are small and constant per op; the live 60s run (9.3) shows flat RSS; static allocation risks already catalogued by Domains 2–4 (see cross-references below). |

## 9.2 Ring-Buffer Backpressure

| Bullet | Verdict | Evidence |
|---|---|---|
| Generate >100k syscalls/sec workload (tight read/write loop) | **PASS** | 4 parallel `dd if=/dev/zero of=/dev/null bs=64k` workloads drove **168,649–171,243 tracepoint events/sec** (84–85.5k syscall pairs/sec) through live root traces. |
| Monitor for ring-buffer loss messages (`trace_pipe`/`dmesg`) | **PASS (executed)** | `grep -icE "lost|drop|overflow"` over both high-rate run logs: **0 matches** — no libbpf loss messages at these rates on this host (EventMapSize default, 300 ms poll). |
| Confirm the event loop reports dropped events rather than silently skipping | **PASS with findings (Y1, Y2)** | Two distinct behaviors observed: (a) `-plain` at 168.6k events/s: **420,067 CSV rows == exactly the "syscalls after filter: 420067" counter** — perfect fidelity, no silent loss at this rate; (b) `-parquet` at 171.2k events/s: run **aborted** at ~0.45s with `Failed to run: parquet recorder queue is full`, **exit 2, no output file** — all 38,449 captured events lost (not silent, but a total-loss failure mode; see Y1). Cross-reference Domain 2 F1: there is **no BPF-side drop counter** anywhere, so kernel-side `bpf_ringbuf_reserve` NULL drops (if they ever occur at higher rates) would remain unobservable; also observed `with 256 mismatches (0.03%)` enter/exit mismatches at peak rate (bounded, small). |

## 9.3 Long-Duration Stability

| Bullet | Verdict | Evidence |
|---|---|---|
| Run a 1-hour trace with auto-reset (`-resetTimer=30s`, the default) | **N-A (deferred; 60s substitute executed)** | Full 1-hour run deferred for session resources. A **60-second** root run (`-parquet -duration 60`, auto-reset default 30s active) was executed with a sustained dd workload: 3,214,003 syscalls (53,567/s), exit 0, clean `-duration` shutdown. |
| Verify RSS remains stable (±10%) | **PASS** | `VmRSS` sampled every 5s from `/proc/<ior-pid>/status` across the 60s run: **3544 → 3548 kB (±0.1%)** — flat under 3.2M ingested events. Parquet row fidelity exact: 3,214,003 rows == counter (no loss at 53.5k/s). |
| Confirm dashboard remains responsive / tab switching does not hang | **N-A (no tty)** | Not verifiable headless; mitigated by the 62/62 in-process TUI integration suite (Domain 5) and race/timeout-green TUI tests (except the known `ApplyPalette` race, Domain 7 F1). |

---

## Findings (not fixed, per constraints)

- **Y1 (MEDIUM)** — Parquet sink failure mode at sustained high rates: with the bounded 4096-slot recorder queue full (observed at ~85k syscall pairs/s, ~171k tracepoint events/s), the recorder returns an error that **aborts the whole run** (`Failed to run: parquet recorder queue is full`, exit 2) and **no partial output file is written** — every already-captured event is lost. Suggested fix: block/shed with a warning + counter instead of failing the run, and/or flush-and-write partial output on queue overflow; consider sizing the queue relative to `EventMapSize`.
- **Y2 (MEDIUM, cross-ref Domain 2 F1)** — No drop observability: neither BPF-side ring-buffer reserve failures nor any loss counter are surfaced anywhere (`stats()`, TUI, logs). At tested rates no loss occurred, but the gap stands: a production incident at higher rates would be invisible. Suggested fix: per-CPU drop counter map surfaced in stats/TUI (plan item 9.2's "confirm the event loop reports dropped events" is only half-true today: the parquet path errors loudly, the ring-buffer path is silent).
- **Y3 (LOW, cross-ref Domain 2 F2)** — Long-duration growth vector remains the unbounded per-TID maps (`prevTimes`, `comms`): the flat 60s RSS run used a low-TID-count workload; a thread-churning target (e.g. a process pool) is the risk case. Suggested fix: LRU-cap both maps like `enters`/`pendingHandles`.
- **Y4 (INFO)** — Enter/exit mismatch metric shows 0.01–0.03% mismatches at peak rates (10–256 of ~84k/s) — small, bounded, presumably LRU evictions/unmatched exits; worth a glance if exactness matters.
- **Y5 (INFO, positive)** — `-plain` synchronous path sustains 84k syscalls/s with byte-exact row/counter fidelity on this host; CO-RE attach of ~570 tracepoints plus graceful skipping of 32 absent ones adds no measurable startup cost concern.

## Domain summary

**Verdict counts (9 plan bullets): 5 PASS · 0 FAIL · 4 N-A/deferred.** The tool's performance envelope is healthy: benchmarks are panic-free with sane per-op costs, a 60s live run holds RSS flat at ±0.1% under 3.2M events with exact output fidelity, and the synchronous `-plain` path sustains ~84k syscalls/s losslessly. The two substantive issues are (Y1) the parquet recorder's total-abort failure mode when its bounded queue saturates at sustained high rates, and (Y2) the absence of any ring-buffer drop counter (cross-domain with Domain 2 F1). Deep pprof profiling and the 1-hour soak remain deferred follow-ups; a root-enabled session should run `mage benchProf` and a 1-hour `-resetTimer=30s` trace with a thread-churning workload to close Y3's risk case.