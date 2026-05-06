FROM rockylinux:9-minimal

# Update GO_VERSION here to upgrade the Go toolchain baked into the image.
ARG GO_VERSION=1.26.2

# Install full dnf and plugin support (minimal image ships only microdnf)
RUN microdnf install -y dnf dnf-plugins-core && \
    microdnf clean all

# Enable CRB (ships zlib-static / glibc-static), EPEL, and the BaseOS source
# repo (provides the elfutils source RPM needed to build libelf.a).
RUN dnf config-manager --set-enabled crb && \
    dnf config-manager --set-enabled baseos-source && \
    dnf install -y epel-release && \
    dnf clean all

# Build-time toolchain: C compiler, clang/LLVM (for BPF), bpftool, BPF/elf
# headers, static archives for zlib and glibc, and packaging helpers.
RUN dnf install -y \
        gcc clang bpftool \
        elfutils-libelf-devel \
        zlib-static glibc-static libzstd-devel \
        git make cmake wget rpmdevtools && \
    dnf builddep -y elfutils && \
    dnf clean all

# Install Go from go.dev — Rocky 9 ships an older release, ior needs 1.26+.
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz && \
    tar -C /usr/local -xf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Build libelf.a from the Rocky 9 elfutils source RPM.
# Rocky 9 does not ship libelf.a (no *-static packages exist in the distro).
RUN mkdir -p /root/src && cd /root && \
    dnf download --source elfutils-libelf && \
    rpm -ivh elfutils-*.src.rpm && \
    tar -C /root/src -xjf rpmbuild/SOURCES/elfutils-*.tar.bz2 && \
    cd /root/src/elfutils-* && \
    ./configure --enable-deterministic-archives --disable-debuginfod --disable-libdebuginfod && \
    make -C lib -j$(nproc) && \
    make -C libelf -j$(nproc) && \
    cp -v libelf/libelf.a /usr/lib64/ && \
    rm -rf /root/src /root/rpmbuild /root/elfutils-*.src.rpm

# Build libzstd.a from upstream — libzstd-devel does not ship the static archive.
RUN wget -q https://github.com/facebook/zstd/releases/download/v1.5.5/zstd-1.5.5.tar.gz \
        -O /tmp/zstd.tar.gz && \
    tar -C /tmp -xzf /tmp/zstd.tar.gz && \
    make -C /tmp/zstd-1.5.5/lib -j$(nproc) libzstd.a && \
    cp -v /tmp/zstd-1.5.5/lib/libzstd.a /usr/lib64/ && \
    rm -rf /tmp/zstd-1.5.5 /tmp/zstd.tar.gz

# Clone libbpfgo at the required tag and build the static archive.
# Placed at /git/libbpfgo so it is a sibling of the ior mount at /git/ior,
# matching the default LIBBPFGO=../libbpfgo path used by Magefile.go.
RUN mkdir -p /git && \
    git clone https://github.com/aquasecurity/libbpfgo /git/libbpfgo && \
    git -C /git/libbpfgo checkout v0.9.2-libbpf-1.5.1 && \
    git -C /git/libbpfgo submodule update --init --recursive && \
    make -C /git/libbpfgo libbpfgo-static

# Install the mage build tool
RUN go install github.com/magefile/mage@latest

# The ior source tree is mounted at /git/ior at runtime (see build-with-docker.sh).
WORKDIR /git/ior

# Generate kernel-specific tracepoint code then compile the static ior binary.
# IOR_FORCE_GENERATE=1 skips the strict diff against the committed syscall-coverage
# audit, which was generated on a different kernel build than the container host.
# The container runs as root so bpftool and /sys/kernel/tracing are used directly.
CMD ["sh", "-c", "IOR_FORCE_GENERATE=1 mage generate && mage all"]
