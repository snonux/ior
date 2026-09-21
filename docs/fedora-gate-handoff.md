# Handoff: closing audit gate x4 on a modern Fedora kernel

This is a self-contained handoff for re-running the two checks that could not be
completed on the RHEL 9 development host. Whoever picks this up (a person or an
agent) needs nothing but this file, the repository, and a Fedora machine with
root.

## Why this exists

The syscall-semantics audit (Part 4 of
[`audit/2026-09-06-code-quality-audit.md`](../audit/2026-09-06-code-quality-audit.md))
is finished except for its closure gate, task **x4**. Everything that can be
verified on the development host (`5.14.0-687.42.1.el9_8`) has been verified:
all dependencies are done, the guardrails pass, and every handler that kernel
can generate is byte-identical to the committed artifact.

Two things need a newer kernel:

1. **Generation.** The committed BPF artifact contains handlers for 16 syscalls
   the RHEL 9 kernel does not have: `file_getattr`, `file_setattr`,
   `getxattrat`, `setxattrat`, `listxattrat`, `removexattrat`, `listmount`,
   `listns`, `statmount`, `open_tree_attr`, `lsm_get_self_attr`,
   `lsm_set_self_attr`, `lsm_list_modules`, `mseal`, `uprobe`, `uretprobe`.
   Nobody has shown that the current generator reproduces those 32 handlers.
2. **Live tests.** Eight integration tests could not execute there. They now
   probe the kernel and skip when a feature is missing, so they have never
   actually run and passed against a real kernel since the audit fixes landed.

| Test | Needs |
|---|---|
| `TestXattrGetxattrat` | `getxattrat` (Linux 6.13) |
| `TestXattrSetxattrat` | `setxattrat` (Linux 6.13) |
| `TestXattrListxattrat` | `listxattrat` (Linux 6.13) |
| `TestXattrRemovexattrat` | `removexattrat` (Linux 6.13) |
| `TestMountFsManagementSyscalls` (four expectations) | `statmount`, `listmount` (6.8), `open_tree_attr` (6.15), `listns` (6.19) |
| `TestIouringSetup`, `TestIouringEnter`, `TestIouringRegister` | io_uring permitted (`kernel.io_uring_disabled` not `2`) |

The newest syscall in that list is `listns`. A kernel older than 6.19 will still
be a large improvement, but it leaves that one expectation unverified; say so in
the result.

## How the tests decide to skip

Read [`integrationtests/kernel_support_test.go`](../integrationtests/kernel_support_test.go).
The rules are:

- A test is skipped **only** when the running kernel provably cannot run it. The
  probes ask the kernel, never a version number, because distribution kernels
  backport syscalls.
- Syscall availability is "does `syscalls/sys_enter_<name>` exist in tracefs".
- io_uring availability is a probing `io_uring_setup(0, NULL)`: `EPERM` or
  `ENOSYS` means unavailable, anything else means it works.
- `TestMountFsManagementSyscalls` never skips as a whole. It drops only the
  expectations for syscalls the kernel lacks and logs each omission.
- `TestKernelProbeFindsAnAlwaysPresentSyscall` fails if the probes cannot even
  find `openat`. That protects against a run that looks green because tracefs
  is mounted somewhere unexpected and every probed test skipped.

**On a modern Fedora kernel none of these probes should skip anything.** A skip
coming from this file on Fedora is a finding, not a pass.

## 1. Prepare the Fedora host

The package list below is the Fedora equivalent of
[`build-rocky-linux-9.md`](./build-rocky-linux-9.md). It has not been executed by
the author of this handoff, so treat a missing package name as something to fix
here rather than as a blocker.

```shell
sudo dnf install -y gcc clang llvm bpftool git make golang \
    elfutils-libelf-devel elfutils-libelf-devel-static \
    zlib-devel zlib-static libzstd-devel libzstd-static glibc-static

# ior needs Go 1.26+. If Fedora ships an older Go, let the toolchain fetch it:
export GOTOOLCHAIN=auto
go install github.com/magefile/mage@latest
export PATH="$HOME/go/bin:$PATH"

# libbpfgo must sit next to the repository, pinned and built statically.
git clone https://github.com/aquasecurity/libbpfgo ../libbpfgo   # if missing
git -C ../libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

Check out the branch under test and confirm the starting point:

```shell
git checkout develop && git pull
git log --oneline -1          # record this hash in the result
uname -r                      # record this too
```

## 2. Pre-flight: what does this kernel provide?

Run this first. It tells you up front which of the eight tests can run, so a
later skip is never a surprise.

```shell
for s in getxattrat setxattrat listxattrat removexattrat statmount listmount \
         listns open_tree_attr file_getattr file_setattr mseal \
         lsm_get_self_attr lsm_set_self_attr lsm_list_modules uprobe uretprobe; do
  if sudo test -d /sys/kernel/tracing/events/syscalls/sys_enter_$s; then
    echo "present  $s"
  else
    echo "MISSING  $s"
  fi
done
sysctl kernel.io_uring_disabled     # must be 0 (or 1 when running as root)
```

If `kernel.io_uring_disabled` is `2`, enable io_uring for the duration of the
run and restore it afterwards:

```shell
sudo sysctl -w kernel.io_uring_disabled=0
# ... run the tests ...
sudo sysctl -w kernel.io_uring_disabled=2
```

## 3. Guardrails

```shell
mage fmtCheck && mage vet && mage lint && mage test && mage testRace && mage build
```

All six must pass. `mage test` includes a test that runs `mage lint` on a
planted defect; it fails with "parallel golangci-lint is running" if another
linter is active on the machine. That is environmental: re-run with nothing
else linting.

## 4. Generation check

Do **not** judge this by `git diff` alone. The `#define SYS_ENTER_X <id>` block
holds kernel-assigned tracepoint IDs, which legitimately differ between kernels.
Compare handler bodies by name instead:

```shell
mage generateTracepointsCStdout > /tmp/gen_local.c
scripts/compare-generated-handlers.py /tmp/gen_local.c internal/c/generated_tracepoints.c
echo "exit=$?"
```

Pass criteria:

- `different: 0` and exit status `0`.
- `only in committed` is empty, or lists only syscalls the pre-flight reported
  as `MISSING`. On the RHEL 9 host this list had 16 syscalls; the point of this
  run is to shrink it to zero.
- `only in local` may be non-empty if Fedora's kernel is newer than the one the
  artifact was generated on. That is not a failure. Record the names: they are
  new syscalls that still need a classification in
  `internal/generate/classify.go`.

Then run the real target as a second opinion:

```shell
mage generate
git status --short
```

An ID-only change to `internal/c/generated_tracepoints.c` and the generated Go
files is expected on a different kernel and must **not** be committed. Any
change to `internal/c/generated_tracepoints_result.txt` is a real difference and
needs explaining. Finish with `git checkout -- .` so the tree is clean before
the test run.

## 5. Privileged integration suite

`mage integrationTest` builds everything, but it passes `-test.failfast`, which
hides every test after the first failure. Use it only to build, then run the
binary directly so each test gets its own verdict:

```shell
mage integrationTest > /tmp/integ_build.log 2>&1 || true   # builds ior, ioworkload, integrationtests.test

cd integrationtests
sudo -E IOR_INTEGRATION_PARALLEL=1 ../integrationtests.test \
    -test.timeout=60m -test.count=1 -test.parallel 2 -test.v 2>&1 \
  | grep -aE '^\s*(--- |FAIL|ok|PASS|panic|\s+\w+_test\.go:)' > /tmp/integ_full.log
cd ..

grep -aE '^\s*--- ' /tmp/integ_full.log | awk '{print $2}' | sort | uniq -c
grep -aE '^--- (FAIL|SKIP)' /tmp/integ_full.log
```

The suite has about 220 tests and takes roughly 35 minutes at `-test.parallel 2`.
The unfiltered output is several hundred megabytes of libbpf debug lines, which
is why the command filters it.

Pass criteria:

- Zero `FAIL`.
- No `SKIP` whose reason starts with "kernel does not provide" or mentions
  io_uring, except for syscalls the pre-flight reported as `MISSING`.
- `TestMountFsManagementSyscalls` passes and its `-v` output contains no
  "its expectation is not asserted on this host" line.
- `TestPosixMqBasic` may skip with "mq syscalls unavailable" when the host
  denies `mq_open`; that is unrelated to this gate.

To re-run just the eight tests this handoff is about:

```shell
cd integrationtests
sudo -E ../integrationtests.test -test.count=1 -test.v -test.run \
  '^(TestXattr(Get|Set|List|Remove)xattrat|TestIouring(Setup|Enter|Register)|TestMountFsManagementSyscalls|TestKernelProbeFindsAnAlwaysPresentSyscall)$' \
  2>&1 | grep -aE '^\s*--- |_test\.go:'
cd ..
```

If a test fails only under load, re-run it alone before calling it a
regression. One class of load-dependent failure was already fixed in `f1ba4a1`
(parquet row expectations demanding a `comm` that ior had not resolved yet).

## 6. Things worth checking while you are there

These were recorded during the audit as unverifiable on RHEL 9:

- **`memfd_secret`.** It returns `ENOSYS` on the RHEL 9 host. On Fedora
  `TestFdFromAirEventfdUsers` should now assert `O_RDWR|O_CLOEXEC` for it
  instead of relaxing the expectation. If the syscall is still unavailable, boot
  with `secretmem.enable=1` or note it as unverified.
- **`userfaultfd` access mode.** ior registers it as `O_RDWR`, which is what the
  RHEL 9 kernel reports. Newer mainline is believed to open it `O_RDONLY`.
  Measure it and compare with `eventfdOpenFlagSpecs` in
  `internal/eventloop_exit.go`:

  ```shell
  sudo python3 - <<'EOF'
  import ctypes
  libc = ctypes.CDLL(None, use_errno=True)
  fd = libc.syscall(323, 1)          # userfaultfd(UFFD_USER_MODE_ONLY)
  print(open(f"/proc/self/fdinfo/{fd}").readline().strip() if fd >= 0
        else f"errno={ctypes.get_errno()}")
  EOF
  ```

  `flags: 02` means `O_RDWR`, `flags: 00` means `O_RDONLY`. A mismatch is a new
  finding: file a task, do not patch it as part of the gate.

## 7. Record the result and close the gate

Append a section to the end of
[`audit/2026-09-06-code-quality-audit.md`](../audit/2026-09-06-code-quality-audit.md):

```markdown
#### Fedora gate run for x4 — <date>

- Host: <uname -r>, commit <hash>.
- Pre-flight: <which of the 16 syscalls were present / MISSING>; io_uring <state>.
- Guardrails: <pass/fail per target>.
- Generation: <output summary of compare-generated-handlers.py>; result table <unchanged/changed>.
- Integration suite: <N tests, pass/skip/fail counts>; the eight gate tests: <verdict each>.
- Extra checks: memfd_secret <...>; userfaultfd access mode <...>.
- Verdict: <gate closed / still open because ...>.
```

Close the gate only when sections 3, 4 and 5 meet their pass criteria:

```shell
ask annotate x4 "Fedora gate run <date> on <kernel> at <hash>: <one-line verdict>. See the audit file."
ask done x4
git add audit/2026-09-06-code-quality-audit.md
git commit -m "docs(audit): close Part 4 gate after Fedora run (x4)"
```

If a criterion is not met, leave x4 open, record exactly what is missing, and
file one task per real defect with `ask add +syscalls +bugfix "..."`, adding it
as a dependency with `ask dep add x4 <id>`. A kernel that still lacks `listns`
is not a defect; it is an unverified expectation, and the verdict should say so.
