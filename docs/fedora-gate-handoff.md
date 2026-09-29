# Modern-kernel validation guide

The Rocky 9 development host cannot exercise several syscalls in the committed BPF object.
Run this check on a host with a recent kernel, BTF, tracefs, root access and io_uring
enabled. It was written for the payload split in commit `0e4ebbe` (task `x9`). The
recorded live result in this checkout is from the older Rocky host.

## Why this exists

The [September syscall-semantics audit](../audit/2026-09-06-code-quality-audit.md)
identified coverage that needs a newer kernel. On 2026-09-23 the Rocky 9 host ran the full
privileged suite against `0e4ebbe`: **213 passed, 8 skipped, 0 failed**. The changed fd,
eventfd, two-fd and xattr paths that this kernel supports passed. Three io_uring tests
skipped because `kernel.io_uring_disabled=2`; four xattrat tests skipped because their
tracepoints are absent; Posix MQ skipped after `mq_open` returned permission denied.
`TestMountFsManagementSyscalls` passed but could not assert four newer syscalls. That is a
useful old-kernel result, not a full modern-kernel pass.

Two things need a newer kernel:

1. **Generation.** The committed BPF artifact contains handlers for 16 syscalls
   the RHEL 9 kernel does not have: `file_getattr`, `file_setattr`, `getxattrat`,
   `setxattrat`, `listxattrat`, `removexattrat`, `listmount`, `listns`, `statmount`,
   `open_tree_attr`, `lsm_get_self_attr`, `lsm_set_self_attr`, `lsm_list_modules`,
   `mseal`, `uprobe`, `uretprobe`. The Rocky host reproduced all 699 handlers it
   shares with the committed artifact, but cannot check these 32 handlers.
2. **Live tests.** Four xattrat and three io_uring tests could not execute on
   the Rocky host. Four mount expectations were also omitted.

| Test | Needs |
|---|---|
| `TestXattrGetxattrat` | `getxattrat` (Linux 6.13) |
| `TestXattrSetxattrat` | `setxattrat` (Linux 6.13) |
| `TestXattrListxattrat` | `listxattrat` (Linux 6.13) |
| `TestXattrRemovexattrat` | `removexattrat` (Linux 6.13) |
| `TestMountFsManagementSyscalls` (four expectations) | `statmount`, `listmount` (6.8), `open_tree_attr` (6.15), `listns` (6.19) |
| `TestIouringSetup`, `TestIouringEnter`, `TestIouringRegister` | io_uring permitted (`kernel.io_uring_disabled` not `2`) |

The newest syscall in that list is `listns`. A kernel older than 6.19 will still be a large
improvement, but it leaves that one expectation unverified; say so in the result.

## How the tests decide to skip

Read [`integrationtests/kernel_support_test.go`](../integrationtests/kernel_support_test.go).
The rules are:

- A test is skipped **only** when the running kernel provably cannot run it. The
  probes ask the kernel, never a version number, because distribution kernels backport
  syscalls.
- Syscall availability is "does `syscalls/sys_enter_<name>` exist in tracefs".
- io_uring availability is a probing `io_uring_setup(0, NULL)`: `EPERM` or
  `ENOSYS` means unavailable, anything else means it works.
- `TestMountFsManagementSyscalls` never skips as a whole. It drops only the
  expectations for syscalls the kernel lacks and logs each omission.
- `TestKernelProbeFindsAnAlwaysPresentSyscall` fails if the probes cannot even
  find `openat`. That protects against a run that looks green because tracefs is mounted
  somewhere unexpected and every probed test skipped.

On the intended host, a missing feature is an unverified part of this gate. Record the exact
reason rather than treating a green process exit as full coverage.

## 1. Prepare the Fedora host

The package list below is the Fedora equivalent of
[`build-rocky-linux-9.md`](./build-rocky-linux-9.md). Check package names on the host
before installing; this recipe has not been validated on Fedora.

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

Run this first so later skips have a clear explanation.

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

If `kernel.io_uring_disabled` is `2`, enable io_uring for the duration of the run and
restore it afterwards:

```shell
sudo sysctl -w kernel.io_uring_disabled=0
# ... run the tests ...
sudo sysctl -w kernel.io_uring_disabled=2
```

## 3. Guardrails

```shell
mage fmtCheck && mage vet && mage lint && mage test && mage testRace && mage build
```

All six must pass. `mage test` includes a test that runs `mage lint` on a planted defect; it
fails with "parallel golangci-lint is running" if another linter is active on the machine.
That is environmental: re-run with nothing else linting.

## 4. Generation check

Do **not** judge this by `git diff` alone. The `#define SYS_ENTER_X <id>` block holds
kernel-assigned tracepoint IDs, which legitimately differ between kernels. Compare handler
bodies by name instead:

```shell
mage generateTracepointsCStdout > /tmp/gen_local.c
scripts/compare-generated-handlers.py /tmp/gen_local.c internal/c/generated_tracepoints.c
echo "exit=$?"
```

Pass criteria:

- `different: 0` and exit status `0`.
- `only in committed` is empty, or lists only syscalls the pre-flight reported
  as `MISSING`. On the RHEL 9 host this list had 16 syscalls; the point of this run is to
  shrink it to zero.
- `only in local` may be non-empty if Fedora's kernel is newer than the one the
  artifact was generated on. That is not a failure. Record the names: they are new syscalls
  that still need a classification in `internal/generate/classify.go`.

Then try the normal generation target:

```shell
mage generate
git status --short
```

The diff gate may stop on a different kernel's tracepoint set. That is expected if the
handler comparison above passes, and it leaves the generated files untouched. If generation
succeeds but changes IDs or generated Go files, do not commit those host-specific changes.
Restore only the generated files it changed before testing; leave unrelated worktree edits
alone.

## 5. Privileged integration suite

`mage integrationTest` uses `-test.failfast`, which hides later failures. Build the test
binary, then run it without that flag. Use the same cgo flags as Mage:

```shell
mage build
go build -o ioworkload ./cmd/ioworkload
libbpfgo_dir=$(realpath ../libbpfgo)
CGO_CFLAGS="-I$libbpfgo_dir/output -I$libbpfgo_dir/selftest/common" \
CGO_LDFLAGS="-lelf -lzstd $libbpfgo_dir/output/libbpf/libbpf.a" \
LIBBPFGO="$libbpfgo_dir" go test -c ./integrationtests -o integrationtests.test

cd integrationtests
set -o pipefail
IOR_INTEGRATION_PARALLEL=1 sudo -n -E "$(realpath ../integrationtests.test)" \
    -test.timeout=60m -test.count=1 -test.parallel 2 -test.v 2>&1 \
  | grep --line-buffered -aE '^\s*(--- |FAIL|ok|PASS|panic|\s+\w+_test\.go:)' > /tmp/integ_full.log
test_status=$?
cd ..
test "$test_status" -eq 0

grep -aE '^\s*--- ' /tmp/integ_full.log | awk '{print $2}' | sort | uniq -c
grep -aE '^--- (FAIL|SKIP)' /tmp/integ_full.log
```

The Rocky 9 run took about 28 minutes at `-test.parallel 2`. The unfiltered output
contained several hundred megabytes of libbpf debug lines, so the command keeps only test
verdicts and file:line diagnostics. `pipefail` preserves the test binary's exit status
through `grep`.

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

If a test fails only under load, re-run it alone before calling it a regression. One class
of load-dependent failure was already fixed in `f1ba4a1` (parquet row expectations demanding
a `comm` that ior had not resolved yet).

## 6. Things worth checking while you are there

These were recorded during the audit as unverifiable on RHEL 9:

- **`memfd_secret`.** It returns `ENOSYS` on the RHEL 9 host. On Fedora
  `TestFdFromAirEventfdUsers` should now assert `O_RDWR|O_CLOEXEC` for it instead of relaxing
  the expectation. If the syscall is still unavailable, boot with `secretmem.enable=1` or note
  it as unverified.
- **`userfaultfd` access mode.** ior registers it as `O_RDWR`, which is what the
  RHEL 9 kernel reports. Newer mainline is believed to open it `O_RDONLY`. Measure it and
  compare with `eventfdOpenFlagSpecs` in `internal/eventloop_exit.go`:

  ```shell
  sudo python3 - <<'EOF'
  import ctypes
  libc = ctypes.CDLL(None, use_errno=True)
  fd = libc.syscall(323, 1)  # userfaultfd(UFFD_USER_MODE_ONLY)
  print(open(f"/proc/self/fdinfo/{fd}").readline().strip() if fd >= 0
        else f"errno={ctypes.get_errno()}")
  EOF
  ```

  `flags: 02` means `O_RDWR`, `flags: 00` means `O_RDONLY`. A mismatch is a new finding:
  file a task, do not patch it as part of the gate.

## 7. Record the result

Append a section to the end of
[`audit/2026-09-06-code-quality-audit.md`](../audit/2026-09-06-code-quality-audit.md):

```markdown
#### Modern-kernel validation — <date>

- Host: <uname -r>, commit <hash>.
- Pre-flight: <which of the 16 syscalls were present / MISSING>; io_uring <state>.
- Guardrails: <pass/fail per target>.
- Generation: <output summary of compare-generated-handlers.py>; result table <unchanged/changed>.
- Integration suite: <N tests, pass/skip/fail counts>; the eight gate tests: <verdict each>.
- Extra checks: memfd_secret <...>; userfaultfd access mode <...>.
- Verdict: <gate closed / still open because...>.
```

Record the verdict even if some checks remain unverified. File a task for a confirmed code
defect. A kernel that still lacks `listns` is an environment limit, not a defect.
