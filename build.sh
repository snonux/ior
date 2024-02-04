#!/bin/bash

set -xeuf -o pipefail

clang -g -O2 -Wall -fpie -I../libbpfgo/selftest/common -target bpf -D__TARGET_ARCH_amd64 -I../libbpfgo/output -I../libbpfgo/selftest/common -c main.bpf.c -o main.bpf.o

export CC=clang
export CGO_CFLAGS="-I/home/paul/git/libbpfgo/output -I/home/paul/git/libbpfgo/selftest/common"
export CGO_LDFLAGS="-lelf -lzstd /home/paul/git/libbpfgo/output/libbpf.a"
export GOOS=linux
export GOARCH=amd64

go build -tags netgo -ldflags '-w -extldflags "-static"' -o ioriotng ./main.go
