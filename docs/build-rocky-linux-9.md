# Building ior on Rocky Linux 9

Verified on a fresh Rocky Linux 9.7 install (kernel `5.14.0-611.5.1.el9_7` or
newer). Runs on the **stock RHEL 9 kernel** — no kernel upgrade needed.

One build-time caveat: Rocky 9 ships neither `libelf.a` nor `libzstd.a` (no
`*-static` packages). Both must be built from source.

> Historical note. Earlier versions of `ior` typed BPF tracepoint context as
> `struct trace_event_raw_sys_enter`/`_exit` (the BTF-emitted alias). RHEL 9
> backports an `rt`-tree patch that adds `preempt_lazy_count` to `struct
> trace_entry`, which widens those aliases by 8 bytes and shifts the `args`/`ret`
> offsets — but the actual context the kernel hands the program is still
> `struct syscall_trace_enter`/`_exit`, where the offsets did not move. The
> verifier saw the program reading past `max_ctx_offset` and rejected the
> attach with `EACCES`. `ior` now uses `syscall_trace_*` directly (matching
> the [bcc fix](https://github.com/iovisor/bcc/pull/4920) and inspektor-gadget),
> so the stock kernel works with no workaround.

## Docker build (no Rocky 9 host required)

The easiest path — builds entirely inside a container from any Docker-capable
Linux host:

```shell
mage buildDocker
# or directly:
./scripts/build-with-docker.sh
# skip image rebuild on subsequent runs:
./scripts/build-with-docker.sh --run
```

`mage buildDocker` builds a `ior-builder:rocky9` image on first run (~15–20 min),
then runs it with the repo root mounted as a volume so the resulting static
binary lands at `./ior`.

## Manual build on a Rocky Linux 9 host

```shell
# 1) Enable repos and install build dependencies (CRB ships static libs).
sudo dnf config-manager --set-enabled crb
sudo dnf install -y epel-release
sudo dnf install -y gcc clang bpftool elfutils-libelf-devel zlib-static \
    glibc-static libzstd-devel git make cmake wget rpmdevtools strace bpftrace
sudo dnf builddep -y elfutils

# 2) Install Go 1.26 from go.dev (Rocky 9 ships only Go 1.25; ior needs 1.26+).
cd /tmp
wget -q https://go.dev/dl/go1.26.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xf go1.26.2.linux-amd64.tar.gz
echo 'export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' | sudo tee /etc/profile.d/go.sh
source /etc/profile.d/go.sh

# 3) Build libelf.a from elfutils source.
mkdir -p ~/src && cd ~
dnf download --source elfutils-libelf
rpm -ivh elfutils-*.src.rpm
tar -C ~/src -xjf rpmbuild/SOURCES/elfutils-*.tar.bz2
cd ~/src/elfutils-*
./configure --enable-deterministic-archives --disable-debuginfod --disable-libdebuginfod
make -C lib -j$(nproc)
make -C libelf -j$(nproc)
sudo cp -v libelf/libelf.a /usr/lib64/

# 4) Build libzstd.a from upstream (libzstd-devel does not ship the static archive).
cd /tmp
wget -q https://github.com/facebook/zstd/releases/download/v1.5.5/zstd-1.5.5.tar.gz
tar xzf zstd-1.5.5.tar.gz
make -C zstd-1.5.5/lib -j$(nproc) libzstd.a
sudo cp -v zstd-1.5.5/lib/libzstd.a /usr/lib64/

# 5) Clone ior + libbpfgo, pin libbpfgo, build the static archive, install mage.
mkdir -p ~/git
git clone https://codeberg.org/snonux/ior ~/git/ior
git clone https://github.com/aquasecurity/libbpfgo ~/git/libbpfgo
git -C ~/git/libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ~/git/libbpfgo submodule update --init --recursive
make -C ~/git/libbpfgo libbpfgo-static
go install github.com/magefile/mage@latest

# 6) Generate against the live kernel and build.
# IOR_FORCE_GENERATE=1 skips the strict diff against the committed audit
# (generated on a different kernel build).
cd ~/git/ior
IOR_FORCE_GENERATE=1 mage generate
mage all

# 7) Smoke test.
sudo ./ior -plain -duration 5
```

If `./ior -plain -duration 5` prints `Probing for 5s` and a stream of CSV rows,
the install is good.

## libbpfgo toolchain

`ior` links against a locally built `libbpfgo` checkout. By default
`Magefile.go` expects that checkout at `../libbpfgo` relative to this repo; set
`LIBBPFGO=/absolute/path/to/libbpfgo` to override.

Pin that checkout to `v0.9.2-libbpf-1.5.1` and rebuild the static artifacts
before running `mage` targets:

```shell
git -C ../libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

Validated commands for this pin:

```shell
mage world
mage integrationTest
```

Troubleshooting and rollback:

- If builds fail with `bpf/bpf.h` missing, re-run the checkout, submodule
  sync, and `make libbpfgo-static` commands above, then retry
  `mage world`.
- Prefer Mage targets over raw `go test` for packages that import `libbpfgo`;
  Mage injects the required `CGO_CFLAGS`, `CGO_LDFLAGS`, and `LIBBPFGO` values.
- To roll back to the previous pin, reset to commit `90dbffffbdab`
  (`v0.6.0-libbpf-1.3.0.20240111220235-90dbffffbdab`) and rebuild:

```shell
git -C ../libbpfgo checkout 90dbffffbdab
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

## Compile once, run everywhere

The full build dance above only has to happen on **one** machine. The resulting
`ior` binary is portable across Linux hosts: `scp ior other-host:/usr/local/bin/`
and run it there.

Two reasons it works:

- The Go binary is compiled with `-extldflags "-static"` and links libbpf,
  libelf, libzstd, and zlib as static archives. There is no runtime dependency
  on the build host's library versions (a couple of glibc resolver functions —
  `getpwnam_r` and friends — fall back to the target's libc, which is fine on
  any reasonable distro).
- The BPF object inside the binary is built with libbpf's CO-RE
  (Compile-Once, Run-Everywhere) machinery. Field offsets are not baked into
  the bytecode; libbpf reads the target kernel's BTF (`/sys/kernel/btf/vmlinux`)
  at load time and patches the program for that kernel. As long as the target
  ships BTF — true on every Debian, Ubuntu, Fedora, Arch, RHEL, and ElRepo
  `kernel-ml` build at the time of writing — the same `ior` binary runs without
  recompilation.

Pick one Rocky 9 / Fedora box, do the build dance once, then distribute the
23 MB binary to wherever you want to trace. The build host needs all the dev
tooling; the trace hosts need only a BTF-enabled kernel and `sudo`.

## Timing semantics

Each reported event pair has two timing counters:

- `durationNs`: syscall runtime on the same thread (`exit(current) - enter(current)`).
- `durationToPrevNs`: inter-syscall gap on the same thread (`enter(current) - exit(previous)`).

Important details:

- `durationToPrevNs` is tracked per `tid` (thread), not globally across all threads.
- The first observed syscall pair for a thread has `durationToPrevNs = 0` because
  there is no prior exit timestamp.
- `durationToPrevNs` is attributed to the current syscall pair (the one whose
  `enter` closes the gap).
- There is no separate "idle" pseudo-event bucket; use the `durationToPrev` count
  field when aggregated flamegraph output should emphasize inter-syscall time.
