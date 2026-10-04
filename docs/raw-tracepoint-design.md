# Raw Tracepoint Syscall Dispatch: Design and Prototype

Status: **prototype + gate 3 answered for direction (tasks 703, g23).**
`IOR_RAW_SYSCALLS` switches on a read/write-only prototype; without it ior
behaves exactly as before. This page holds the design, the prototype's
measurements (classic vs raw vs fentry) and the recommended plan. Gate 3
**prefers fentry over raw for the build-out** on trampoline kernels, with
classic as default/fallback; full-set attach cost and el9 remain open
(see "Gate 3"). Gates 1 (el8/el9) and 2 (skip loss under contention) are
still open. Check the kernel details marked *unverified* before
implementing.

## Where the cost goes today

Every traced syscall has two classic tracepoint programs, `handle_sys_enter_<n>`
and `handle_sys_exit_<n>` (generated into `internal/c/generated_tracepoints.c`,
730 programs on the generation kernel, 176k BPF instructions in all, the largest
456). The probe manager attaches and detaches them per syscall.

A classic syscall tracepoint is a perf event. The kernel's `perf_syscall_enter`
is registered on the raw tracepoint `raw_syscalls:sys_enter` as soon as any
`syscalls:sys_enter_*` perf event exists, and from then on runs for **every
syscall of every task**: it reads the syscall number, tests it in its enable
bitmap, and for a traced syscall reserves a perf trace buffer, copies all six
arguments into it (`syscall_get_arguments`) and calls `trace_call_bpf`
(`perf_syscall_exit` likewise for the return value). A raw tracepoint program
on `sys_enter`/`sys_exit` is called directly from the same tracepoint with the
task's `struct pt_regs *` and the syscall number (enter) or return value
(exit) and nothing is copied.

Measured earlier with bpftrace (task 3s2; dd `bs=1 count=3M` = 6M read+write
syscalls, a filter that rejects them): untraced 0.64 s, four classic hooks
1.38 s (~125 ns/syscall), two raw hooks 0.80 s (~27 ns/syscall). Repeated for
this page with instruction counts, the gap is a factor 2 to 2.5, not 4.5
(see "Measurements").

That is the floor, not ior's cost: an ior handler that emits a record runs
~1300 BPF/kernel instructions per syscall (filter, two clock reads, enter/exit
hooks, restart hook, ring-buffer reserve and submit, the task 603 file identity
walk). The prototype measures both: the cost a syscall pays when ior's filter
rejects it (every syscall of every process outside `-pid`/`-tid`, the host-wide
overhead) and the cost of an emitted record.

## Prototype

Files: `internal/c/rawsyscall.c` (BPF), `internal/rawsyscall_proto.go` (Go),
hooks in `internal/ior_bpfsetup.go` (`loadBPFObject`, `attachSessionProbes`,
`attachRestartSigreturnProbe`) and `internal/ior.go`
(`configureEventLoopOutput`).

- `IOR_RAW_SYSCALLS=tailcall`: raw `sys_enter`/`sys_exit` dispatchers that
  `bpf_tail_call` into a `BPF_MAP_TYPE_PROG_ARRAY` indexed by syscall number;
  slots 0 and 1 hold raw-tracepoint versions of the read/write handlers.
- `IOR_RAW_SYSCALLS=switch`: one program per side; an `ARRAY` indexed by
  syscall number says "traced", and a `switch` runs the inlined handler body.
- `IOR_RAW_SYSCALLS=fentry` (task g23): four trampoline programs
  (`?fentry`/`?fexit` on `__x64_sys_{read,write}`), attached through
  libbpf's `AttachGeneric` seam and listed under the classic
  `sys_enter_*`/`sys_exit_*` names so the restart-fold skip counter finds
  them. Arguments arrive as BTF-typed `struct pt_regs *` (the syscall
  wrappers take that); the shared helpers read them the same way as the
  raw handlers (`regs->di` / `BPF_CORE_READ(regs, di)`, not
  `PT_REGS_PARM*_SYSCALL` — see the comment on `ior_raw_arg0` in
  `rawsyscall.c`). No raw dispatcher. The classic
  `handle_restart_sigreturn` hand probe stays attached, so a classic
  `syscalls:sys_enter_*` still arms `perf_syscall_enter` host-wide: an
  untraced syscall pays about the same as under classic ior (~153 insn),
  not the bpftrace-floor zero of a pure fentry attach. Converting that
  hand probe is a build-out residual.
- A `-probe` suffix (`tailcall-probe`, `switch-probe`) reads the registers
  with `bpf_probe_read_kernel` (what el8 would run) instead of the direct,
  `bpf_rdonly_cast`-typed loads used where the kernel has the kfunc (6.2+).
  `fentry` has no `-probe` variant (rejected at parse time).
- The handler bodies are those of the generated
  `handle_sys_{enter,exit}_{read,write}`: same `filter()`, same
  `ior_on_syscall_enter`/`ior_on_syscall_exit` hooks (sampling, enter
  state, restart fold), same `fd_event`/`ret_event` records and trace IDs,
  same file identity. A dd traced both ways gives the same rows.
- The programs are in `?` sections (libbpf autoload off). Without the variable
  no new program is loaded; only three small maps are created.
- With a **raw** mode on, read and write leave the probe manager (not
  registered, not in the probes modal; the active-probe row filter lets them
  through), the dispatchers attach as hand probes, and the classic
  `handle_restart_sigreturn` hand probe is replaced by the dispatcher (any
  classic `syscalls:*` tracepoint keeps `perf_syscall_enter` running for every
  syscall, which would hide the gain). With **fentry**, the same leave of
  the probe manager applies for read/write, but restart_sigreturn stays the
  classic hand probe.
- 32-bit syscalls are skipped explicitly in the raw path (see "Compat
  syscalls"); with the check removed, three `int 0x80` calls of compat
  `restart_syscall` (nr 0) showed up as three bogus `read` rows. fentry never
  sees a compat entry: it is attached to the 64-bit wrappers only.

Prototype limitations: x86_64 only, read/write only, no runtime toggling, the
raw dispatchers attach after the probe manager's walk (so the restart fold's
handler-depth count starts late), full-set fentry attach time (~730
trampolines) is unmeasured, and the TUI does not show the two syscalls.

## Measurements

Kernel 7.2.5-200.fc44.x86_64, i7-1185G7 (4 cores, 8 threads), 2026-10-03,
shortly after a reboot. The host was **not quiet**: two other workers ran Go
unit tests the whole time (load average between 2 and 80, given per table).
`instructions:k` of the pinned dd is nearly immune to that (the best runs of a
configuration agree within 0.1 %); `cycles:k` and above all the wall time are
not, so for those the minimum is the better estimate and the median is given
for the spread. Wall time of the untraced dd was ~1.0 s here against 0.64 s
in task 3s2's run: treat the nanoseconds as relative.

Method, per configuration and round (configurations interleaved within a
round, 7 or 8 rounds):

```sh
# ior, pinned away from the dd's core (CPU 3 and its sibling 7):
sudo -n taskset -c 0-2,4-6 env IOR_RAW_SYSCALLS=<mode> ./ior -plain \
    -trace-syscalls read,write <scope> -mapSize 1073741824 -duration 120 &
# wait for "Probing for", then:
sudo -n perf stat -e instructions:k,cycles:k -o <file> -- \
    taskset -c 3 dd if=/dev/zero of=/dev/null bs=1 count=3000000
# SIGINT to ior; its shutdown statistics give ring buffer drops (0 in every
# run: the 1 GiB ring holds all 12M records) and the skipped probe runs.
```

`<mode>` is empty ("classic", ior as it is today), `tailcall`, `switch`,
`tailcall-probe` or `fentry`. `<scope>` is `-pid 1` (ior's BPF `filter()`
rejects every dd syscall: what every process outside the trace filter pays)
or `-comm nomatch` (no BPF-side filter, every record is emitted and dropped
in userspace: what a traced syscall pays).
Per-syscall figures are (configuration - untraced) / 6,000,000, one "syscall"
being an enter and an exit; `min` uses the minima of both, `med` the medians.

**Traced, rejected by the filter** (`-pid 1`; 7 rounds; load 5.9-9.5):

| config | insn:k, 1e9: med (min-max) | cycles:k, 1e9: med (min-max) | wall s: med (min-max) | insn/syscall med / min | cycles/syscall min | ns/syscall min |
|---|---|---|---|---|---|---|
| untraced | 4.369 (4.368-4.372) | 2.714 (2.084-3.489) | 1.229 (0.991-1.718) | - | - | - |
| classic | 8.610 (8.606-8.616) | 3.976 (3.745-6.868) | 2.033 (1.505-2.726) | 707 / 706 | 277 | 86 |
| tailcall | 7.130 (7.128-7.135) | 3.329 (3.263-5.187) | 1.639 (1.347-2.086) | 460 / 460 | 196 | 59 |
| switch | 6.996 (6.992-6.999) | 4.263 (3.134-5.569) | 2.189 (1.312-2.430) | 438 / 437 | 175 | 53 |
| tailcall-probe | 7.596 (7.593-7.600) | 4.665 (3.473-5.990) | 2.017 (1.434-2.590) | 538 / 538 | 232 | 74 |

**Traced and emitted** (`-comm nomatch`; 8 rounds; load 2.7-5.0, the
quietest stretch):

| config | insn:k, 1e9: med (min-max) | cycles:k, 1e9: med (min-max) | wall s: med (min-max) | insn/syscall med / min | cycles/syscall med / min | ns/syscall med / min |
|---|---|---|---|---|---|---|
| untraced | 4.368 (4.368-4.369) | 2.158 (2.087-2.632) | 1.018 (0.988-1.232) | - | - | - |
| classic | 12.430 (12.429-12.435) | 6.547 (6.095-7.362) | 2.457 (2.274-2.970) | 1344 / 1344 | 732 / 668 | 240 / 214 |
| tailcall | 11.085 (11.083-11.098) | 6.199 (5.810-7.331) | 2.334 (2.175-2.991) | 1120 / 1119 | 674 / 620 | 219 / 198 |
| switch | 10.964 (10.963-10.964) | 5.728 (5.578-5.916) | 2.162 (2.092-2.235) | 1099 / 1099 | 595 / 582 | 191 / 184 |
| tailcall-probe | 12.015 (12.014-12.019) | 6.215 (6.092-6.439) | 2.318 (2.281-2.410) | 1274 / 1274 | 676 / 667 | 217 / 215 |

(A first set of 7 rounds under a load of 4-7 had the same minima within
0.3 % but medians up to 22 % higher.)

**An untraced syscall while ior traces something else** (the dd's read and
write are *not* selected; `-pid 1`; 8 rounds each; load 29-81 for the
`openat` rows, 5-24 for the `read` rows, so only minima are given):

| config | traces | insn:k min, 1e9 | insn/syscall | cycles/syscall | ns/syscall |
|---|---|---|---|---|---|
| untraced | - | 4.368 | - | - | - |
| classic | openat | 5.286 | 153 | 84 | 26 |
| tailcall | openat (classic) + empty dispatchers | 7.340 | 495 | 187 | 61 |
| switch | openat (classic) + empty dispatchers | 7.387 | 503 | 189 | 57 |
| tailcall-probe | openat (classic) + empty dispatchers | 7.796 | 571 | 209 | 64 |
| classic | read only | 6.947 | 430 | 179 | 51 |
| tailcall | read only | 6.864 | 416 | 138 | 43 |
| switch | read only | 6.824 | 409 | 150 | 47 |

The prototype's `openat` rows carry both mechanisms (openat is not a
prototype syscall, so its classic tracepoints keep `perf_syscall_enter/exit`
running: 153 of the 495). The dispatcher pair alone therefore costs an
untraced syscall 342 instructions (tail call; 350 switch, 418 with the probe
read of `orig_ax`); the `read only` rows give the same within 10 % (classic
(706+153)/2 = 430; tail call (460+U)/2 = 416, U = 372). **An untraced
syscall is 2.2-2.4 times as expensive in instructions under the raw pair as
under the classic tracepoints** (about 345 against 153), and no cheaper in
time (roughly 26-35 ns against 26 ns).

**The mechanisms' floor**, bpftrace programs that only test `pid == 1` (6
rounds; load 1.8-2.7), same dd:

| hooks | insn/syscall | cycles/syscall min | ns/syscall |
|---|---|---|---|
| 4 classic `tracepoint:syscalls:sys_{enter,exit}_{read,write}` | 688 | 267 | 88-97 |
| 2 `rawtracepoint:sys_enter,sys_exit` | 340 | 133 | 36-43 |
| 4 `fentry/fexit:vmlinux:__x64_sys_{read,write}` | 304 | 87 | 28 |
| classic, only `openat` hooked (dd untraced) | 153 | 79 | 24 |
| fentry/fexit, only `__x64_sys_openat` hooked (dd untraced) | 0 | 0 | 0 |

So on 7.2 the raw pair halves the mechanism's cost (688 -> 340 instructions,
~90 -> ~40 ns); the 125 ns against 27 ns of task 3s2 (a factor 4.5) did not
reproduce, the factor is 2 to 2.5.

**Skipped probe runs** (`recursion_misses` summed over ior's attached
programs at shutdown). In the benchmark runs above, sum over the rounds:
filter scope classic 12, tailcall 164, switch 849, tailcall-probe 297;
emitting scope classic 23, tailcall 169, switch 24, tailcall-probe 2 (most
runs 0, a few runs carry the sum). Under deliberate contention - the
emitting dd plus a `SCHED_FIFO` task on the same CPU that wakes every 50 us
for 4 s and makes one `write` and one `getppid` per wake-up (6 rounds,
interleaved):

| config | skipped runs per round |
|---|---|
| classic | 9942, 12673, 9752, 12190, 9935, 11053 |
| tailcall | 63863, 65340, 62919, 65154, 62883, 67732 |

Six times as many: with one dispatcher per side, a task that preempts the dd
inside the program loses *every* syscall it makes until the dd runs again
(here also its untraced `clock_nanosleep` and `getppid`, which merely count),
where the classic programs lose only the `write` that meets the dd's `write`
program.

**Same rows.** `dd if=/dev/zero of=/dev/null bs=3 count=5` traced with
`-trace-syscalls read,write -comm dd` gives the same 16 rows (name, return
value, file identity; times and pids aside) under the classic handlers and
under `tailcall`, `switch`, `tailcall-probe` and `switch-probe`. The
read/write and restart integration tests (`-test.run
'Readwrite|Restart|Read|Write'`, 31 tests) pass with `IOR_RAW_SYSCALLS`
unset, `tailcall` and `switch`.

Summary, per read/write syscall on 7.2:

| case | classic | raw, tail call | change |
|---|---|---|---|
| traced, filter rejects | 706 insn, 277 cycles, ~86 ns | 460 insn, 196 cycles, ~59 ns | -35 % insn, -29 % cycles |
| traced, record emitted | 1344 insn, 668 cycles, ~214 ns | 1119 insn, 620 cycles, ~198 ns | -17 % insn, -7 % cycles |
| traced, emitted, probe-read registers (el8's path, measured on 7.2) | 1344 insn | 1274 insn, 667 cycles | -5 % insn, 0 % cycles |
| not traced, ior running | 153 insn, 84 cycles, ~26 ns | ~345 insn, ~26-35 ns | +125 % insn |
| skipped runs under RT preemption | ~11k | ~65k | x6 |

### Gate 3: fentry/fexit prototype (task g23)

Measured 2026-10-04 on the same host and kernel (7.2.5-200.fc44.x86_64),
same method as above (6 interleaved rounds; load average moderate; ring
buffer 1 GiB, drops 0 in every run). Modes: classic (env unset),
`IOR_RAW_SYSCALLS=fentry`, `IOR_RAW_SYSCALLS=tailcall`.

**Traced, rejected by the filter** (`-pid 1`):

| config | insn:k, 1e9: med (min-max) | cycles:k, 1e9: med (min-max) | wall s: med (min-max) | insn/syscall med | cycles/syscall min | ns/syscall min |
|---|---|---|---|---|---|---|
| untraced | 4.367 (4.366-4.367) | 2.130 (2.082-2.198) | 0.702 (0.674-0.723) | - | - | - |
| classic | 8.606 (8.605-8.606) | 3.811 (3.771-4.231) | 1.140 (1.083-1.205) | 707 | 281 | 68 |
| fentry | 7.038 (7.038-7.039) | 3.110 (3.074-3.253) | 0.928 (0.925-0.970) | 445 | 165 | 42 |
| tailcall | 7.129 (7.128-7.129) | 3.239 (3.207-3.452) | 0.957 (0.952-1.027) | 460 | 187 | 46 |

**Traced and emitted** (`-comm nomatch`):

| config | insn:k, 1e9: med (min-max) | cycles:k, 1e9: med (min-max) | wall s: med (min-max) | insn/syscall med | cycles/syscall min |
|---|---|---|---|---|---|
| classic | 12.428 (12.427-12.429) | 6.320 (6.218-6.627) | 2.054 (1.751-2.169) | 1344 | 689 |
| fentry | 10.993 (10.993-10.994) | 5.686 (5.497-5.898) | 1.889 (1.795-1.955) | 1104 | 569 |
| tailcall | 11.084 (11.083-11.085) | 6.033 (5.850-6.303) | 1.992 (1.940-2.065) | 1120 | 628 |

(`instructions:k` agreed within 0.1 % across rounds; wall time for the
emitting classic set was the noisiest, so ns/syscall is omitted there.)

**Skipped probe runs** (shutdown total; median of 6 rounds):

| config | emit scope | reject scope |
|---|---|---|
| classic | 81.5 | 3.5 |
| fentry | 76 | 1 |
| tailcall | 198.5 | 2 |

fentry matches classic; the raw dispatcher is about 2.4× worse under the
emitting scope even without a deliberate `SCHED_FIFO` contender (703's
contention case was 6×).

**Attach time** (wall ms from process start to the "Probing for" line;
read+write only, 3 rounds): classic median 997 ms, fentry 1018 ms,
tailcall 1016 ms. For two programs the attach itself is lost in the
object load. **Full-set attach of ~730 fentry/fexit trampolines is not
measured** (the prototype only builds the four read/write programs); that
remains a build-phase residual. Availability on el9 is still gate 1
(*unverified* on this host).

**Same rows.** `dd if=/dev/zero of=/dev/null bs=3 count=5` traced with
`-trace-syscalls read,write -comm dd` under `IOR_RAW_SYSCALLS=fentry`
produces the same 16 rows as classic (name, return value, file identity).

**Argument access.** The BTF signature of `__x64_sys_*` is
`long (*)(struct pt_regs *)`, so `BPF_PROG` gives a typed `regs` and the
prototype reuses `ior_raw_enter_fd` / `ior_raw_exit_ret`, which read
registers through `ior_raw_arg0` (`regs->di` / `BPF_CORE_READ`). No
separate probe-read fentry variant.

**Restart-fold hooks.** fentry does not replace `handle_restart_sigreturn`:
`usesRawDispatchers()` is false, so the classic hand probe stays. The
raw modes still replace it with the enter dispatcher.

Summary vs classic on 7.2 (median instructions):

| case | fentry | raw, tail call |
|---|---|---|
| traced, filter rejects | 445 insn (−37 %) | 460 insn (−35 %) |
| traced, record emitted | 1104 insn (−18 %) | 1120 insn (−17 %) |
| not traced, ior running | ~classic (~153 insn; classic `restart_sigreturn` TP still arms `perf_syscall_enter`) | ~345 insn (+125 %) |
| skipped runs (emit scope, quiet) | ~classic | ~2.4× classic |

#### Gate 3 verdict: prefer fentry for the build-out; do not lead with raw

**Prefer fentry** for the next build step on trampoline kernels: on 7.2
the read/write prototype is at least as cheap as the raw dispatcher on
traced syscalls, keeps per-syscall skip counters (links listed under
classic `sys_enter_*`/`sys_exit_*` names) and never sees compat
syscalls. Untraced cost today matches classic (the classic
`restart_sigreturn` TP remains); unlike raw it does not add a
dispatcher on every syscall. Classic handlers stay the default and the
only backend for el8 (no trampolines) and the fallback everywhere.

**Do not lead with the raw dispatcher.** Its untraced tax (+125 %) and
skip amplification are the deal-breakers the bpftrace floor already
pointed at; fentry matches the traced gain without that dispatcher tax.
Raw may still matter on a kernel that has raw tracepoints but not
trampolines — that is gate 1's call, not a reason to build the full
generator path for it first.

**What this gate did not close** (still required before making fentry
the default or claiming the full cost): attach/load time for the full
~730 trampoline set (only two syscalls were prototyped; the two-program
attach was lost in the object load); el9 trampoline availability
(gate 1, *unverified* here); a contended skip re-check (gate 2);
converting `handle_restart_sigreturn` off a classic `syscalls:*`
tracepoint so untraced cost can fall to the bpftrace-floor zero. The
verdict is a direction for the build-out, not a ship decision.

## Design

### Dispatch by syscall number

Three shapes were considered.

1. **Tail-call program array (preferred among the raw shapes).** Each side
   has one tiny
   dispatcher (enter: 7 instructions xlated; exit: 22, of which the
   `orig_ax` read) that tail-calls `progs[nr]`. Every syscall keeps its own
   handler program, generated from the same bodies as today, verified on its
   own, so program size and verifier complexity per program stay exactly
   what the 4.18/5.14 verifiers accept now. An empty slot is an untraced
   syscall: the tail call falls through and the dispatcher returns. Tail-call
   depth is 1 (limit 33). Program arrays and tail calls exist since 4.2; raw
   tracepoints since 4.17 (RHEL 8's 4.18 has them). Before 5.10 a program
   that tail-calls must not contain BPF-to-BPF calls; the dispatcher has
   none and the generated handlers are fully inlined (keep them so).
   Tail-call targets must have the caller's program type: the handlers
   become `raw_tracepoint` programs too.
2. **Enable bitmap + one program with a switch.** One inlined array lookup
   and a switch. Measured as fast as the tail calls for read/write, but it
   does not scale: all 730 bodies inlined into two programs is ~176k
   instructions, verified path by path in one program. That is over the
   4096-instruction size limit of pre-5.2 verifiers and close to the 1M
   complexity limit of later ones, and one rejected case fails the whole
   object. Rejected for the full set.
3. **Per-family programs.** A few dispatchers by family with switches. Same
   verifier problem per family (FS alone has ~100 syscalls) and no gain over
   the tail call. Rejected.

A middle way worth keeping in mind: many handlers differ only in trace IDs
and argument indices (one body per *kind*). A per-kind switch with the IDs
from the slot's value would shrink 730 programs to a few dozen; it is an
optimisation of load time and memory, not of the per-syscall cost, and not
needed for the first stage.

### Arguments from `struct pt_regs`

`raw_syscalls:sys_enter` is `TP_PROTO(struct pt_regs *regs, long id)`, and
`regs` is the task's user register frame (`task_pt_regs`). The x86_64 syscall
wrappers since 4.17 (`__x64_sys_*(const struct pt_regs *)`) matter only for
kprobes on the wrapper, where the arguments sit in the *inner* regs the
wrapper receives; the tracepoint is called from the entry code with the
frame itself, so no indirection applies here.

| arg | x86_64 | arm64 |
|-----|--------|-------|
| 0..5 | `di si dx r10 r8 r9` | `orig_x0 x1 x2 x3 x4 x5` (x0 is overwritten by the return value) |
| nr at exit | `orig_ax` | `syscallno` |
| ret | tracepoint arg (`ax`) | tracepoint arg (`x0`) |

libbpf's `PT_REGS_PARMn_CORE_SYSCALL` encodes this table (r10 for argument 3
on x86, `orig_x0` on arm64). The build currently passes
`-D__TARGET_ARCH_amd64`, which `bpf_tracing.h` does not recognise (it wants
`__TARGET_ARCH_x86`), so the prototype names the registers itself; the real
implementation should fix the define and use the macros.

A raw tracepoint's argument is an untyped `u64`, so a register is read either
by `bpf_probe_read_kernel` (one helper call, ~90 instructions, every kernel)
or, on 6.2+, by casting `regs` with the `bpf_rdonly_cast` kfunc and loading
directly (task 603 uses the same kfunc). Generated handlers would load only
the arguments they use; on the probe-read path one read of the whole frame
(168 bytes, one helper call) beats several single reads for handlers using
two or more arguments. `tp_btf/sys_enter` (5.5+) gives a typed `regs`
without the kfunc, but `BPF_PROG_TYPE_TRACING` programs cannot be tail-call
targets of a raw tracepoint dispatcher (*unverified* whether a prog array of
tracing programs works at all), so it is not the base design.

No exit handler reads an argument today (checked over the committed file),
which matters on arm64, where `x0` holds the return value at exit.

### The exit side

`raw_syscalls:sys_exit` is `TP_PROTO(struct pt_regs *regs, long ret)`. The
number is `syscall_get_nr` = `regs->orig_ax` (x86_64) / `regs->syscallno`
(arm64). Two differences to the classic exit:

- it also fires for a syscall that cleared the number: `rt_sigreturn` sets
  `orig_ax = -1` (the classic `ftrace_syscall_exit`/`perf_syscall_exit` skip
  `nr < 0`). The bounds check makes that "no slot"; noreturn syscalls keep
  no exit handler.
- a ptrace tracer can rewrite `orig_ax` between enter and exit (seccomp
  `SECCOMP_RET_TRACE`, `PTRACE_SYSCALL` + `PTRACE_SETREGS`). The classic
  path has the same exposure (`syscall_get_nr` at exit), so nothing gets
  worse; the enter-state `enter_trace_id` check already turns such a pair
  into a stateless exit.

### Records and trace IDs

Unchanged. The slot number is the arch's syscall number, but the records keep
carrying the generated trace IDs (tracefs IDs of the generation kernel, used
as labels), so userspace, Parquet and every decoder are untouched. Each
generated raw handler embeds its own `SYS_ENTER_*`/`SYS_EXIT_*` constants
exactly like today. Userspace needs a name -> syscall number table per arch;
generate it (per `GOARCH`) from `golang.org/x/sys/unix`'s `SYS_*` constants
rather than from kernel headers, so that it does not depend on the
generation host. A syscall without a number on the running arch is
"not available", like a missing tracepoint today.

### Probe manager: attach/detach become slot writes

`Attach(syscall)` becomes two map updates (exit slot, then enter slot, so
that an enter is never recorded without its exit being traced) and
`Detach(syscall)` two deletes (enter first). The dispatchers are attached
once, when the first syscall is selected, and detached at `Close`; they
must not stay attached with nothing selected, because they cost every
syscall on the host (see "The cost of an untraced syscall").

The change-hook contract of tasks o03/x13/023 stays as it is, because it is
about *when* records can appear, not about links:

- `Attach` still reports `ChangeBegins` before its first slot write and
  `ChangeEnds` after its last one, both under the probe's `attachMu`;
  `Detach` reports `Changed` after its deletes. The stamps, the clear of
  `restart_pending_map`, the time rule and the `Attached` flag carry over.
- A slot write is visible at once to new dispatcher runs, but, unlike a
  link's `Destroy` (which closes the perf event and waits for the tracepoint
  to drop the program), a prog-array delete does not wait for a handler
  already running on another CPU. The o03 design already allows for that
  ("an exit handler still running on another CPU when `Destroy` returns",
  cleared and refused by the next attach's first report), so the rules do
  not change; the window is only no longer bounded by an RCU grace period.
- The pair is never "half attached" in a way the manager has to undo: a
  failed second write is followed by a delete of the first (map deletes on a
  prog array cannot fail for a valid key), so `IsActive` keeps meaning both
  or none. The z13 "a link's Destroy is final" rules no longer apply to
  syscalls (no links), but stay for the dispatchers and hand probes.
- Toggling a whole family is a loop of map writes (microseconds) instead of
  hundreds of perf-event opens and RCU waits.

### Sampling, filters, enter state, restart folds

All of it lives in the handler bodies and hooks (`filter()`,
`ior_on_syscall_enter*`, `ior_on_syscall_exit*`, `syscall_sampling_rate_map`
indexed by trace ID, `ior_restart_on_enter`/`_on_exit`) and is unchanged. The
restart fold's `handle_restart_sigreturn` hand probe has to move into the
enter dispatcher for the **raw** modes (done in the prototype for
`tailcall`/`switch`); the dispatcher has to run it before the slot
lookup, because it counts handler returns whether or not `rt_sigreturn`
is traced. It must also precede the syscall slots at startup (attach the
dispatchers before filling any slot). **fentry** keeps the classic hand
probe instead (no dispatcher to host it); converting that probe is a
build-out residual so untraced cost can fall below classic.

### File identity (task 603)

Unchanged: `ior_file_ident` uses `bpf_get_current_task_btf()` and
`bpf_rdonly_cast`, both available to raw tracepoint programs; the prototype
reports the same identities as the classic handlers.

### Skipped runs (`recursion_misses`, task 723)

This is the one place where the design changes the *quality* of the
evidence, not just its plumbing.

- The kernel checks recursion on the program the tracepoint calls, i.e. the
  dispatcher; a tail-called handler is not checked again. The attached
  program list therefore holds two programs instead of up to 730, and the
  per-fold sweep of task 723 becomes one read of two counters.
- A skip no longer names a syscall: a dispatcher skipped on a CPU loses
  whatever syscall that run was. Task 723's per-program questions ("did a
  program of *this* fold skip?") collapse to "did the dispatcher skip?".
  That is more conservative (more folds refused), never less sound.
- On kernels where syscall tracepoint programs run preemptibly (7.2:
  `trace_call_bpf_faultable` for classic, and the raw `sys_enter` path has no
  `preempt_disable` either - `__BPF_DECLARE_TRACE_SYSCALL` in
  `include/trace/bpf_probe.h` of 7.2.5), a dispatcher preempted on a CPU
  makes every syscall of every other task on that CPU skip until it resumes,
  where today only the same syscall's program does. Measured: under a
  `SCHED_FIFO` task preempting the traced dd every 50 us the prototype
  counted six times the skipped runs of the classic handlers (~65k against
  ~11k in 4 s), and in the plain benchmark runs on the loaded host more as
  well. This is the main correctness risk. Per-family dispatchers (one
  prog array each, attached on the same raw tracepoint) would narrow it,
  but every further dispatcher pair costs every syscall another ~340
  instructions, which eats the gain after one or two. Kernels that run
  tracepoint programs with preemption off do not have the problem
  (*unverified*: syscall tracepoints became faultable, and their programs
  preemptible, in 6.13).
- On kernels before 6.7 classic tracepoint programs did not count skips at
  all, while raw tracepoint programs did: the evidence becomes *available*
  on 5.x kernels (*unverified* from which version raw tracepoints count
  `recursion_misses`; `bpf_prog_inc_misses_counter` for raw tracepoints is
  5.12+), so `kernelCountsSkippedRuns` must learn the program type.

### Hand probes

Unchanged (sched, task, signal probes are not syscall tracepoints), except
`handle_restart_sigreturn`, see above.

### Compat (32-bit) syscalls

The classic syscall tracepoints never report a 32-bit syscall on x86
(`ARCH_TRACE_IGNORE_COMPAT_SYSCALLS`: `trace_get_syscall_nr` returns -1 for a
compat task), so ior traces none today. The raw tracepoint sees them with the
32-bit number, which is some other 64-bit syscall's slot (compat 3/4 are
read/write, 64-bit 3/4 are close/stat). They must be excluded: on x86_64 by
`current->thread_info.status & TS_COMPAT` (what `in_ia32_syscall` tests; it
also covers `int 0x80` from a 64-bit task), on arm64 by `TIF_32BIT` in
`thread_info.flags`. The prototype reads the BTF-typed task (5.11+); el8
needs `bpf_get_current_task` + a probe read. The check costs a load per
*emitted* record when placed after `filter()`, as in the prototype. x32
numbers carry bit 30 and fall outside the table. Tracing compat syscalls
(separate slot range, own numbers) is possible later and out of scope.

### Kernel support

| kernel | raw_tp | tail calls | direct regs (`bpf_rdonly_cast`) | compat check | skip evidence |
|--------|--------|------------|-------------------------------|--------------|---------------|
| el8 4.18 | yes (4.17) | yes | no: probe reads | probe read | *unverified* |
| el9 5.14 | yes | yes | *unverified* (RHEL backports) | BTF task (5.11) | yes (5.12) |
| 6.2+ / 7.2 | yes | yes | yes | BTF task | yes |

The generated handlers already load on 4.18 and 5.14; as tail-call targets
they keep their bodies, so the verifier risk is limited to the dispatcher
(tiny) and the register reads (CO-RE on `struct pt_regs`, which needs kernel
BTF: RHEL 8.2+). The prototype was only loaded on 7.2.

### The cost of an untraced syscall

The classic path decides "not traced" in C (`perf_syscall_enter` tests its
bitmap and returns: 153 instructions per syscall for both sides); the raw
path decides it in the dispatcher, after the kernel has entered a BPF
program (`bpf_trace_run2`: recursion counter, migration and RCU
bookkeeping, run statistics), twice per syscall: ~345 instructions. A run
that traces a few syscalls therefore charges every *other* syscall on the
host more than today. This is inherent to one program on
`raw_syscalls:sys_enter`; no dispatch shape avoids it. Only per-syscall
attachment does (classic tracepoints, or `fentry`/`fexit`, see the
recommendation).

### Expected gain

Measured on 7.2 (see "Measurements"): the raw path removes
`perf_syscall_enter/exit`'s work, which dominates for a syscall ior's filter
rejects (-35 % instructions, -29 % cycles); for an emitted record the
handler body and the ring buffer dominate and the gain is -17 %
instructions, -7 % cycles. The probe-read register access (el8's path)
gives most of that back in the emitting case (-5 % instructions, cycles
unchanged). Nothing is known yet about 4.18 and 5.14, whose classic path
may cost more or less than 7.2's.

## Recommendation

**Staged go as an opt-in second backend; no-go for replacing the classic
handlers now.** The claim holds in kind but not in size, and the design has
two costs the task did not foresee.

What the measurements say:

- The mechanism is twice as cheap, not 4.5 times (688 -> 340 instructions
  per syscall for an empty pair). For ior that is -35 % instructions (-29 %
  cycles) for a traced syscall the filter rejects, which is the host-wide
  overhead of a `-pid`/`-tid` trace, and -17 % instructions (-7 % cycles,
  about -8 % wall) for an emitted record, where ior's own handler body
  (~640 instructions) and ring buffer dominate. With probe-read register
  access (el8) the emitted gain is within noise.
- An untraced syscall gets *more* expensive (153 -> ~345 instructions): the
  classic path tests a bitmap in C, the raw path runs a BPF program for every
  syscall of every task. Tracing everything (ior's default selection) has
  few untraced syscalls and wins; a narrow `-trace-syscalls` selection on a
  busy host loses.
- Skipped runs under preemption rise sixfold on kernels that run syscall
  tracepoint programs preemptibly, and a skip no longer names a syscall, so
  the restart-fold evidence of task 723 refuses more folds.

Risks, in order: (1) record loss by dispatcher skips on preemptible kernels;
(2) el8/el9 unverified - the prototype ran on 7.2 only, and the el8 path
(probe reads, no BTF task, 4.18 verifier with ~730 raw handlers as tail-call
targets) may give no gain at all; (3) two syscall-number/register tables to
keep right per architecture, and compat syscalls that silently alias other
syscalls if the exclusion is wrong; (4) a large change through the
generator, the probe manager's attach contract and the restart-fold safety
rules (o03/x13/023/723) for a gain of 7-30 %; (5) a slot delete does not
wait for running handlers as a link's `Destroy` does.

Gate 3 answered that alternative: the ior fentry prototype is slightly
cheaper than the raw pair on traced syscalls (−18 % / −37 % insn emit /
reject vs classic), keeps per-syscall skips, and never sees a compat
syscall. Untraced cost is not the bpftrace-floor zero: ior still
attaches classic `handle_restart_sigreturn`, which arms
`perf_syscall_enter` host-wide (~classic's ~153 insn); the raw
dispatcher's extra ~345 insn tax is what fentry avoids today. Reaching
true zero untraced cost needs that hand probe converted too. It needs
BPF trampolines (5.5 on x86_64, 6.0 on arm64; both versions and the
RHEL 9 backports still *unverified*) and ~730 trampoline attachments
(attach cost for the full set unmeasured; two programs were
indistinguishable from classic). It does nothing for el8. **Prefer
fentry over raw for the build-out; see "Gate 3 verdict".**

Follow-up tasks, in order; 1–2 remain cheap gates for any raw residual;
gate 3 answered a build-out direction (residuals still open):

1. **Gate: el9 and el8.** Load the fentry prototype (and, if still
   interesting, the raw one) in the el9 (5.14) and el8 (4.18) VMs:
   trampoline availability on el9, verifier acceptance, and the same dd
   measurement. No-go for a kernel where the emitted gain is under ~10 %.
   el8 keeps classic.
2. **Gate: skip loss (raw only, if raw survives gate 1).** Quantify the
   record loss of the dispatcher against the classic handlers under
   realistic contention. fentry's quiet-host skips already match classic;
   a contended re-check is still worth one run before declaring it equal.
3. ~~**Gate: fentry/fexit prototype**~~ **Answered for direction (task
   g23).** Prefer fentry over raw for the build-out on trampoline
   kernels; classic stays default/fallback. Open residuals of this gate:
   full-set (~730) attach/load time, el9 availability.
4. **Build (fentry-first):** generate `?fentry`/`?fexit` handlers for
   every traced syscall (BTF-typed `struct pt_regs *` args, bodies
   otherwise unchanged); keep `mage generate` idempotent; measure object
   size, load time and attach time for the full set; wire the probe
   manager (or a sibling attacher) so runtime toggles destroy trampoline
   links the same way they destroy classic ones; move
   `handle_restart_sigreturn` off a classic `syscalls:*` tracepoint
   (fentry on `rt_sigreturn` or an equivalent) so untraced cost can drop
   to the bpftrace-floor zero.
5. Raw path only if gate 1 finds a kernel that wants it: `-D__TARGET_ARCH_*`,
   syscall-number table, generator for raw variants, slot-write probe
   manager, restart-fold dispatcher rules, compat exclusion — the previous
   steps 4–8, demoted.
6. A real flag in place of `IOR_RAW_SYSCALLS`, the whole integration suite
   under classic and fentry, then the measurement again and the decision
   about the default; classic stays the fallback.

Until gates 1–2 are answered the prototype stays what it is: off by default,
read and write only, with `fentry` as the third switch value.
