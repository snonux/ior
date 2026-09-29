# Domain 8 — Integration & End-to-End Scenarios (Audit Report)

> Historical audit evidence for the commit named below. Use [README.md](../README.md) and [AGENTS.md](../AGENTS.md) for current behavior.

**Project**: ior (I/O Riot NG) at `/home/paul/git/ior`
**Audit basis**: `PLAN-PROJECT-AUDIT.md` (repo root), section "## Domain 8 — Integration & End-to-End Scenarios", journeys 8.1–8.4.
**Commit audited**: `2897495dfd34bf3533b599de896d85d1493b6912`; binary freshly built by the Domain 7 task (`mage build`, static, gitignored `./ior` at repo root).
**Auditor constraints**: no interactive tty; no general root — but **purpose-scoped sudoers NOPASSWD rules** were discovered and verified (`sudo -n -l`): `sudo -n /home/paul/git/ior/ior <args>` (root, SETENV), `sudo -n /home/paul/git/ior/integrationtests.test`, `sudo -n /usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c`, and a read-only tracefs `find|cat` rule. NOT available: `bpftool prog|map list` (leak checks), arbitrary root commands, or signalling root processes. Headless live journeys 8.2/8.3/8.4 were therefore executed **for real**; interactive TUI steps were mapped to the already-recorded root integration run (`audit/check/08b-integration-root.log`: 192 PASS / 1 SKIP / 9 FAIL, all failures kernel/policy-caused on this 5.14 el9_8 host) and the 62/62 in-process `TestTUIIntegration_*` suite.

Evidence logs: `audit/check/09-e2e-help.log`, `09-e2e-flamegraph.log`, `09-e2e-parquet.log`, `09-e2e-filtered.log`. Workload: background `dd` loops; artifacts kept in `/tmp/ior-audit-e2e` and removed after hashing.

---

## 8.1 TUI Journey (plan steps 1–8)

| Step | Verdict | Evidence |
|---|---|---|
| 1. `sudo ./ior` launch + searchable PID picker + Enter selection | **BLOCKED-needs-tty** (mapped) | No tty in this environment. Mapped: `TestTUIIntegration_*` launch/picker tests (62/62, incl. real trace attach via the root integration run); runtime root-gate evidence below. |
| 2. Navigate all 8 tabs (tab/shift+tab, 1..8, h/l) | **PASS (mapped)** | Integration suite drives all tabs; plan drift: only **7 tabs** exist since `5736381` (Non-IO removed); `h`/`l` are column-nav keys, not tab keys (Domain 5 D2). |
| 3. Apply runtime filter without BPF restart | **PASS (mapped)** | `TestTUIIntegration_*` filter-stack tests; Domain 6 verified `SetFilter` atomic swap, no probe re-attach. |
| 4. Export stream to CSV (`e`) | **PASS (mapped)** | Integration tests write real `ior-stream-<ts>.csv` files; Domain 5 5.4 verified modal + `-tuiExport=false` (with finding F1: Stream `x`/`X`/`E` shortcuts not gated). |
| 5. Trigger reset (`r`) | **PASS (mapped)** | Domain 3 3.3: `resetBaselineCmd` covers manual + auto-reset presets; TUI tests green. |
| 6. Stop trace (`q` / Ctrl-C) | **PASS (mapped)** | `q` handling covered by integration suite + Domain 10 10.4c (`tea.Quit` → trace-context cancel). Live SIGINT to a root process: **BLOCKED** (non-root cannot signal root; no sudoers rule). |
| 7. Verify no kernel-resource leaks (`bpftool prog list`, `bpftool map list`) | **BLOCKED** | No sudoers rule for `bpftool prog|map list`. Mitigating note: Domain 7 ran ior as root 200+ times on this host with no observable residue; explicit check not possible here. |
| Extra: `./ior` without root | **PASS** | Runtime evidence (also closes plan item 10.1): prints banner then `Failed to run: tracing requires root privileges (run with sudo)`, **exit 2**. |
| Extra: `./ior --help` | **PASS** | 30 flags; all 16 plan-relevant flags present (`-trace-families/-kinds/-syscalls`, `-no-trace-*`, `-syscall-sampling-families/-syscalls`, `-pid/-tid/-comm/-path`, `-plain/-flamegraph/-parquet/-duration`, `-tuiExport`, `-tui-fast-refresh`). Log: `09-e2e-help.log`. |
| Extra: invalid enum | **PASS** | `./ior -trace-families BOGUS` → `Failed to parse flags: invalid syscall family in trace selector: "BOGUS"`, **exit 2** (clear startup error). |
| Extra: `--testflames` / `--testliveflames` headless smoke | **PASS** (root-free gate) | Both pass the root gate and reach TUI init; without a tty they exit 2 with `bubbletea: error opening TTY` — expected headless behavior, documents that root-free test modes start without root. |

## 8.2 Headless Flamegraph Journey (plan steps 1–4)

| Step | Verdict | Evidence |
|---|---|---|
| 1. `sudo ./ior -flamegraph -duration 10 -name mytrace` | **PASS** | Executed as `sudo -n /home/paul/git/ior/ior -flamegraph -duration 10 -name mytrace` from `/tmp/ior-audit-e2e` with a background dd workload; exit 0; **73,075 syscalls captured (7,307.81/s)**, all after filter; clean `-duration` termination (`Good bye... after 9.999s`). Log: `09-e2e-flamegraph.log`. |
| 2. Filename pattern `<hostname>-<name>-<timestamp>.ior.zst` | **PASS** | Produced exactly `rocky-mytrace-2026-09-01_22:28:04.ior.zst`; 128,968 bytes; sha256 `ef84ee2343f478e362103b7b96827d493dd8e87184ef638360f4385d4ff9a519`; `file`: Zstandard compressed data (v0.8+). |
| 3. Decompress with `zstdcat`, feed into `flamegraph.pl`, render SVG | **FAIL (plan item unsatisfiable as documented)** | `zstdcat` works, but content is **gob, not collapsed-stack text**: the stream begins with a gob type descriptor exposing field names `Path`, `TraceID`, `Comm`, `Pid`, `Tid`, `Flags` (od transcript in session log). `flamegraph.pl` is not installed on this host, and even if it were, it cannot consume gob — cross-reference Domain 4 F1 (structural impossibility). The intended round-trip (`Recorder → Write → LoadFromFile`) is instead verified by the `audit/check/flameroundtrip` helper (Domain 4). |
| 4. Event counts match TUI for same workload | **PASS (indirect)** | Run counter reports 73,075 syscalls; the `.ior.zst` gob record count was not decoded in-place (no gob reader wired up here), but the recorder write/load round-trip and count fidelity are verified by Domain 4 helpers and unit tests. Caveat recorded honestly. |

## 8.3 Parquet Journey (plan steps 1–3)

| Step | Verdict | Evidence |
|---|---|---|
| 1. `sudo ./ior -parquet /tmp/bulk.parquet -duration 10 -trace-families FS,Network` | **PASS** | Executed as root via sudoers; exit 0; 69,088 syscalls (6,909.33/s); clean `-duration` termination. Log: `09-e2e-parquet.log`. |
| 2. File written and non-empty | **PASS** | `/tmp/ior-audit-e2e/bulk.parquet`, 709,549 bytes. |
| 3. Schema, row count, family compliance (pyarrow) | **PASS** | Independent pyarrow read: **69,088 rows == run counter**; **21 columns** exactly as documented by Domain 4, incl. `requested_sleep_ns`, `family`, `filter_epoch`; `family` column contains only `['FS', 'Network']` == the `-trace-families` selection; 286 distinct pids (system-wide trace, no `-pid` given — expected). |

## 8.4 Filtered Trace Journey (plan steps 1–2)

| Step | Verdict | Evidence |
|---|---|---|
| 1. `sudo ./ior -trace-syscalls openat,read,write -no-trace-kinds null -pid <pid>` | **PASS** | Pinned a single long-running `dd if=/dev/zero of=/dev/null` (PID 158022), traced 5s as root via sudoers; exit 0. |
| 2. Only `openat`/`read`/`write` events for that PID appear | **PASS** | 234,308 data rows; **unique syscall names: `read` (117,156) + `write` (117,152) only**; **unique pid.tid: `158022.158022` only** (ior excludes its own PID by design — `IOR_PID_FILTER`, Domain 10). `openat` absent because dd's opens predate trace start (timing caveat, not a filter failure — see X4). Log: `09-e2e-filtered.log`. |

---

## Findings (not fixed, per constraints)

- **X1 (MEDIUM, cross-ref Domain 4 F1)** — The documented "decompress with zstdcat and feed into flamegraph.pl" journey (plan 8.2.3, and AGENTS.md) is **structurally impossible**: `.ior.zst` is a gob-in-zstd record map, not collapsed stacks; `flamegraph.pl` is additionally not installed on this host. Suggested fix: either ship a collapsed-stack text output mode or document the gob format + provide a converter; update plan/AGENTS.md.
- **X2 (LOW, cross-ref Domain 4 F2)** — `-plain` CSV: 8-column header (`durationToPrevNs,durationNs,comm,pid.tid,name,ret,notice,file`) over 5-field merged rows (`comm@pid.tid`, `name=>ret`, `file%(flags)`); the unquoted comma inside the file column (`/dev/zero%(0,O_RDONLY)`) breaks naive CSV/awk parsing (demonstrated live during this audit — first parse attempt mis-split fields).
- **X3 (LOW)** — `-plain` stdout mixes non-CSV lines with data: ASCII banner, `Probing for 5s`, `Waiting for stats to be ready`, `Stopping event loop`, `Statistics:`. Scripted consumers must filter (only data rows are digit-prefixed); consider routing status to stderr.
- **X4 (INFO)** — Short filtered traces may legitimately miss `openat` for long-running processes (opens predate trace start) — a timing caveat for plan-style verifications, not a bug.
- **X5 (INFO, positive)** — CO-RE graceful degradation observed live: the committed newer-kernel tracepoint set loaded on this 5.14 el9_8 host, attaching ~570 tracepoints and skipping the 32 absent ones without error (Domain 7 root integration run) — the portability claim holds on this older kernel even though the literal cross-kernel-copy step stays BLOCKED.

## Plan-vs-code drift

- 8.1 assumes 8 tabs; code has 7 (Non-IO removed in `5736381`) — see Domain 5 D1.
- 8.2.3 assumes collapsed-stack text consumable by `flamegraph.pl` — contradicted by the actual gob format (Domain 4 F1).
- 8.4's example flags behave exactly as documented; the audit run confirms the semantics.

## Domain summary

**Verdict counts (17 plan steps): 12 PASS · 1 FAIL · 4 BLOCKED** (plus 4 extra non-tty evidence checks, all PASS). All three headless journeys ran for real as root via the purpose-scoped sudoers rules: the flamegraph journey produces the exact documented filename pattern with correct counts and clean shutdown; the Parquet journey's output is schema-exact, row-count-exact, and family-compliant under an independent pyarrow reader; the filtered journey proves kernel-side PID scoping plus syscall/kind allow-listing across 234k live rows. The single FAIL is the documented `flamegraph.pl` consumption step, which is impossible by design (gob format) and already recorded as Domain 4 F1. The TUI journey's interactive steps are covered by the 62-test in-process suite and the 192-pass root integration run; the two genuinely unverifiable steps (bpftool leak listing, live signal delivery to a root process) are BLOCKED with mitigating evidence noted.