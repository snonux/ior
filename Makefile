export LIBBPFGO = $(CURDIR)/../libbpfgo
export CC = clang
export GOOS = linux
export GOARCH = amd64
export CGO_CFLAGS = -I$(LIBBPFGO)/output -I$(LIBBPFGO)/selftest/common
export CGO_LDFLAGS = -lelf -lzstd $(LIBBPFGO)/output/libbpf/libbpf.a

all: bpfbuild gobuild

.PHONY: bpfbuild
bpfbuild:
	make -C ./internal/c redo
	cp -v ./internal/c/ior.bpf.o .

gen: generated
generate: generated

.PHONY: generated
generated:
	make -C ./internal/c/generated
	make -C ./internal/generated

.PHONY: gobuild
gobuild:
	go build -tags netgo -ldflags '-w -extldflags "-static"' -o ior ./cmd/ior/main.go

.PHONY: clean
clean:
	find . -type f -name ior -delete
	if [ -e ior.bpf.o ]; then rm ior.bpf.o; fi
	make -C ./internal/c clean

.PHONY: world
world: clean generate all

.PHONY: flames
flames:
	perl ~/git/FlameGraph/flamegraph.pl ior-by-count-flamegraph.collapsed \
		--title "I/O Syscall Count" --nametype Path --hash \
		> ior-by-count-flamegraph.svg
	perl ~/git/FlameGraph/flamegraph.pl ior-by-duration-flamegraph.collapsed \
		--title "I/O Syscall Durations" --nametype Path --hash --countname Nanoseconds \
		> ior-by-duration-flamegraph.svg
