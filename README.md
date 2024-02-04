# ioriotng

I/O Riot NG is a a experiments with BPF.

Maybe a spiritual successor of one of my previous projects, I/O Riot https://codeberg.org/snonux/ioriot, the latter was based on SystemTap and C. The NG is based on BPF (via libbpfgo).

## Fedora

To get this running on Fedora 39, run:

```shell
mkdir ~/git
git clone https://codeberg.org/snonux/ioriotng
git clone https://github.com/aquasecurity/libbpfgo
sudo dnf install -y zlib-static glibc-static libzstd-static
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
tar -xvjpf ~/rpmbuild/SOURCES/elfutils-*.tar.bz2
cd ~/src/elfutils-*
rm -Rf ~/rpmbuild
./configure
make
sudo cp -v ./libelf/libelf.a /usr/lib64/
```
