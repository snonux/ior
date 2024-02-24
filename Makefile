export LIBBPFGO = $(CURDIR)/../libbpfgo
export CC = clang
export GOOS = linux
export GOARCH = amd64
export CGO_CFLAGS = -I$(LIBBPFGO)/output -I$(LIBBPFGO)/selftest/common
export CGO_LDFLAGS = -lelf -lzstd $(LIBBPFGO)/output/libbpf.a

all: bpfbuild gobuild

.PHONY: bpfbuild
bpfbuild:
	make -C ./internal/c redo
	cp -v ./internal/c/ioriotng.bpf.o .

gen: generated
generate: generated

.PHONY: generated
generated:
	#make -C ./internal/c/generated
	make -C ./internal/generated

.PHONY: gobuild
gobuild:
	go build -tags netgo -ldflags '-w -extldflags "-static"' -o ioriotng ./cmd/ioriotng/main.go

.PHONY: clean
clean:
	find . -type f -name ioriotng -delete
	if [ -e ioriotng.bpf.o ]; then rm ioriotng.bpf.o; fi
	make -C ./internal/c clean

.PHONY: world
world: clean generate all
