# I/O Riot NG (aka ior)

<img src=assets/ior-small.png />

I/O Riot NG is an experiments with BPF. This program traces for synchronous I/O syscalls and then analyses the time taken for each of those syscalls. This is especially useful for drawing FlameGraphs like these:

<img src=assets/ior-flamegraph-example.svg />

Maybe this is a spiritual successor of one of my previous projects, I/O Riot https://codeberg.org/snonux/ioriot, the latter was based on SystemTap and C. The NG is based on Go, C and BPF (via libbpfgo).

This works only on Linux!

## Timing Semantics

Each reported event pair has two timing counters:

- `durationNs`: syscall runtime on the same thread (`exit(current) - enter(current)`).
- `durationToPrevNs`: inter-syscall gap on the same thread (`enter(current) - exit(previous)`).

Important details:

- `durationToPrevNs` is tracked per `tid` (thread), not globally across all threads.
- The first observed syscall pair for a thread has `durationToPrevNs = 0` because there is no prior exit timestamp.
- `durationToPrevNs` is attributed to the current syscall pair (the one whose `enter` closes the gap).
- There is no separate "idle" pseudo-event bucket; use the `durationToPrev` count field when aggregated flamegraph output should emphasize inter-syscall time.

## Fedora

To get this running on Fedora 42, run:

```shell
mkdir ~/git
git clone https://codeberg.org/snonux/ior
git clone https://github.com/aquasecurity/libbpfgo
sudo dnf install -y golang clang bpftool elfutils-libelf-devel zlib-static glibc-static libzstd-static
cd libbpfgo
make
make libbpfgo-static
```

Need libelf static, which isn't in any repos. So we need to compile it ourselves.

```
sudo dnf install rpmdevtools dnf-utils
dnf download --source elfutils-libelf
rpm -ivh elfutils-*.src.rpm
cd ~
sudo dnf builddep rpmbuild/SPECS/*.spec
cd ~/rpmbuild/SPECS
rpmbuild -ba *.spec
mkdir ~/src
tar -C ~/src -xvjpf ~/rpmbuild/SOURCES/elfutils-*.tar.bz2
cd ~/src/elfutils-*
rm -Rf ~/rpmbuild
./configure
make
sudo cp -v ./libelf/libelf.a /usr/lib64/
```

## Native Flamegraph Generation

Flamegraphs are generated natively by `ior` from `.ior.zst` data files; no external flamegraph tool is required.

```sh
./ior -ior=trace.ior.zst -fields=pid,path,tracepoint -count=count
```

This generates an SVG and starts an embedded web server. The terminal prints a URL like:

```text
Flamegraph available at http://HOSTNAME:PORT/abs/path/to.svg
```
