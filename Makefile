export LIBBPFGO = $(CURDIR)/../libbpfgo
export CC = clang
export GOOS = linux
export GOARCH = amd64
export CGO_CFLAGS = -I$(LIBBPFGO)/output -I$(LIBBPFGO)/selftest/common
export CGO_LDFLAGS = -lelf -lzstd $(LIBBPFGO)/output/libbpf.a

all: build run

build: bpfbuild gobuild

bpfbuild:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(CC) -g -O2 -Wall -fpie -I$(LIBBPFGO)/selftest/common -target bpf -D__TARGET_ARCH_amd64 -I$(LIBBPFGO)/output -I$(LIBBPFGO)/selftest/common -c ioriotng.bpf.c -o ioriotng.bpf.o

gobuild:
	echo 'package main' > internal/opids.go
	echo >> internal/opids.go
	sed -E 's/#define (.*) ([0-9]+)/const \1 = \2/' opids.h >> internal/opids.go
	go build -race -tags netgo -ldflags '-w -extldflags "-static"' -o ioriotng ./cmd/ioriotng/main.go
clean:
	find . -type f -name ioriotng -delete
	find . -name \*.o -delete
	find . -name vmlinux.h -delete

run:
	sudo ./ioriotng
