export LIBBPFGO = $(CURDIR)/../libbpfgo
export CC = clang
export GOOS = linux
export GOARCH = amd64
export CGO_CFLAGS = -I$(LIBBPFGO)/output -I$(LIBBPFGO)/selftest/common
export CGO_LDFLAGS = -lelf -lzstd $(LIBBPFGO)/output/libbpf.a

all: build run

build: bpfbuild gobuild

.PHONY: bpfbuild
bpfbuild:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./internal/types/vmlinux.h
	$(CC) -g -O2 -Wall -fpie -target bpf -D__TARGET_ARCH_amd64 -I$(LIBBPFGO)/output -c ioriotng.bpf.c -o ioriotng.bpf.o

.PHONY: gobuild
gobuild:
	go build -tags netgo -ldflags '-w -extldflags "-static"' -o ioriotng ./cmd/ioriotng/main.go

.PHONY: clean
clean:
	find . -type f -name ioriotng -delete
	find . -name \*.o -delete
	find . -name vmlinux.h -delete

.PHONY: run
run:
	sudo ./ioriotng -uid $$(id -u)
