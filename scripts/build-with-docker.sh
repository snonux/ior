#!/usr/bin/env bash
# Build the ior binary inside a Rocky Linux 9 container and write it to the
# current directory.  The container image is built once and reused on subsequent
# runs.  The ior source tree is mounted as a volume so the resulting binary
# lands directly in $(pwd)/ior.
#
# Usage:
#   ./build-with-docker.sh          # build image + compile ior
#   ./build-with-docker.sh --build  # force rebuild of the Docker image
#   ./build-with-docker.sh --run    # skip image build, only compile ior
set -euo pipefail

IMAGE="ior-builder:rocky9"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Derive the Go version from go.mod so the Docker image always matches the
# minimum toolchain declared by the project.
GO_VERSION="$(grep '^go ' "${REPO_ROOT}/go.mod" | awk '{print $2}')"

BUILD_IMAGE=true
RUN_BUILD=true

for arg in "$@"; do
    case "$arg" in
        --build) BUILD_IMAGE=true; RUN_BUILD=false ;;
        --run)   BUILD_IMAGE=false; RUN_BUILD=true  ;;
    esac
done

if $BUILD_IMAGE; then
    echo "==> Building Docker image ${IMAGE} (this takes ~15-20 min on first run)..."
    docker build --build-arg "GO_VERSION=${GO_VERSION}" -t "${IMAGE}" "${REPO_ROOT}"
    echo "==> Image build complete."
fi

if $RUN_BUILD; then
    echo "==> Compiling ior inside the container..."
    # --privileged gives full host capabilities.
    # tracefs (/sys/kernel/tracing) and BTF (/sys/kernel/btf) are not auto-mounted
    # by Docker even with --privileged, so they are mounted explicitly:
    #   - /sys/kernel/tracing  : mage generate reads available syscall tracepoints
    #   - /sys/kernel/btf      : mage bpfBuild reads vmlinux BTF for vmlinux.h
    docker run --rm \
        --privileged \
        -v /sys/kernel/tracing:/sys/kernel/tracing \
        -v /sys/kernel/btf:/sys/kernel/btf \
        -v "${REPO_ROOT}:/git/ior" \
        "${IMAGE}"
    echo "==> Done. Binary written to ${REPO_ROOT}/ior"
fi
