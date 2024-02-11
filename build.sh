#!/bin/bash

set -xeuf -o pipefail

declare -r LIBBPFGO="$(pwd)/../libbpfgo"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
echo 'package main' > opids.go
echo >> opids.go
sed -E 's/#define (.*) ([0-9]+)/const \1 = \2/' opids.h >> opids.go

clang -g -O2 -Wall -fpie -I../libbpfgo/selftest/common -target bpf -D__TARGET_ARCH_amd64 -I../libbpfgo/output -I../libbpfgo/selftest/common -c main.bpf.c -o main.bpf.o

export CC=clang
export CGO_CFLAGS="-I$LIBBPFGO/output -I$LIBBPFGO/selftest/common"
export CGO_LDFLAGS="-lelf -lzstd $LIBBPFGO/output/libbpf.a"
export GOOS=linux
export GOARCH=amd64

go build -race -tags netgo -ldflags '-w -extldflags "-static"' -o ioriotng ./cmd/ioriotng/main.go
