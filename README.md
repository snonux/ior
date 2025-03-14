# I/O Riot NG

<img src=assets/ior-small.png />

I/O Riot NG is an experiments with BPF. This program traces for I/O syscalls and then analyses the time taken for each of those syscalls. This is especially useful for drawing FlameGraphs (using https://github.com/brendangregg/FlameGraph) like these:

<img src=assets/ior-by-count-flamegraph.svg />

Maybe this is a spiritual successor of one of my previous projects, I/O Riot https://codeberg.org/snonux/ioriot, the latter was based on SystemTap and C. The NG is based on Go, C and BPF (via libbpfgo).

## Fedora

To get this running on Fedora 39, run:

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
sudo dnf groupinstall "Development Tools"
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

## Inferno Flamegraphs

We are using Inferno Flamegraphs:  https://github.com/jonhoo/inferno

```sh
cargo install inferno
```

