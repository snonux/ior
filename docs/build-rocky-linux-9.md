# Building ior on Rocky Linux 9

Verified on a fresh Rocky Linux 9.7 install (kernel `5.14.0-611.5.1.el9_7` or newer). Runs
on the **stock RHEL 9 kernel**, no kernel upgrade needed.

One build-time caveat: Rocky 9 ships neither `libelf.a` nor `libzstd.a` (no `*-static`
packages). Both must be built from source.

> Historical note. Earlier versions of `ior` typed BPF tracepoint context as
> `struct trace_event_raw_sys_enter`/`_exit` (the BTF-emitted alias). RHEL 9
> backports an `rt`-tree patch that adds `preempt_lazy_count` to `struct
> trace_entry`, which widens those aliases by 8 bytes and shifts the `args`/`ret`
> offsets, but the actual context the kernel hands the program is still
> `struct syscall_trace_enter`/`_exit`, where the offsets did not move. The
> verifier saw the program reading past `max_ctx_offset` and rejected the
> attach with `EACCES`. `ior` now uses `syscall_trace_*` directly (matching
> the [bcc fix](https://github.com/iovisor/bcc/pull/4920) and inspektor-gadget),
> so the stock kernel works with no workaround.

## Docker build (no Rocky 9 host required)

The container build avoids installing the C and Go toolchains on the host. It still reads
the host's BTF and tracepoint list:

```shell
mage buildDocker
# or directly:
./scripts/build-with-docker.sh
# skip image rebuild on subsequent runs:
./scripts/build-with-docker.sh --run
```

`mage buildDocker` builds a `ior-builder:rocky9` image on first run (~15–20 min), then runs
it with the repo root mounted as a volume so the resulting static binary lands at `./ior`.

## Manual build on a Rocky Linux 9 host

```shell
# 1) Enable repos and install build dependencies (CRB ships static libs).
sudo dnf config-manager --set-enabled crb
sudo dnf install -y epel-release
sudo dnf install -y gcc clang bpftool golang elfutils-libelf-devel zlib-static \
    glibc-static libzstd-devel git make cmake wget rpmdevtools strace bpftrace
sudo dnf builddep -y elfutils

# 2) Let Go fetch the toolchain required by go.mod when the packaged Go is older.
export GOTOOLCHAIN=auto
export PATH="$HOME/go/bin:$PATH"

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
# IOR_FORCE_GENERATE=1 regenerates for this older kernel. Keep those generated
# outputs local: they omit syscalls present in the committed newer-kernel set.
cd ~/git/ior
IOR_FORCE_GENERATE=1 mage generate
mage all

# 7) Smoke test.
sudo ./ior -plain -duration 5
```

If `sudo ./ior -plain -duration 5` writes status lines such as `Probing for 5s` to stderr
and a stream of CSV rows to stdout, the install is good.

## libbpfgo toolchain

`ior` links against a locally built `libbpfgo` checkout. By default `Magefile.go` expects
that checkout at `../libbpfgo` relative to this repo; set
`LIBBPFGO=/absolute/path/to/libbpfgo` to override.

Pin that checkout to `v0.9.2-libbpf-1.5.1` and rebuild the static artifacts before running
`mage` targets:

```shell
git -C ../libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

Once the pin is built, use these targets on a kernel matching the committed tracepoint set:

```shell
mage world
mage integrationTest
```

On a Rocky 9 kernel, `mage world` stops at its generation diff gate before building: the
committed tracepoint set includes newer syscalls. Use `IOR_FORCE_GENERATE=1 mage generate`
for a local build, then run `mage fmtCheck`, `mage vet`, `mage lint`, `mage test`,
`mage testRace` and `mage build` separately. Do not commit the older-kernel generated
outputs.

Troubleshooting and rollback:

- If builds fail with `bpf/bpf.h` missing, re-run the checkout, submodule
  sync, and `make libbpfgo-static` commands above, then retry the failed Mage target.
- Prefer Mage targets over raw `go test` for packages that import `libbpfgo`;
  Mage injects the required `CGO_CFLAGS`, `CGO_LDFLAGS`, and `LIBBPFGO` values.
- To roll back to the previous pin, reset to commit `90dbffffbdab`
  (`v0.6.0-libbpf-1.3.0.20240111220235-90dbffffbdab`) and rebuild:

```shell
git -C ../libbpfgo checkout 90dbffffbdab
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

## Using the binary on another host

Build once and copy `ior` to compatible Linux/amd64 hosts, for example with
`scp ior other-host:/usr/local/bin/`.

Two reasons it works:

- The Go binary is compiled with `-extldflags "-static"` and links libbpf,
  libelf, libzstd, and zlib as static archives. There is no runtime dependency on the build
  host's library versions (a couple of glibc resolver functions, `getpwnam_r` and friends may
  still need compatible NSS libraries at runtime).
- The BPF object inside the binary is built with libbpf's CO-RE
  (Compile-Once, Run-Everywhere) machinery. Field offsets are not baked into the bytecode;
  libbpf reads the target kernel's BTF (`/sys/kernel/btf/vmlinux`) at load time and patches
  the program for that kernel. The target still needs BTF and the BPF features used by `ior`;
  tracepoints missing on that kernel are skipped with a warning.

The build host needs the development toolchain. Target hosts need compatible kernel support
and permission to attach BPF tracepoints.

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
