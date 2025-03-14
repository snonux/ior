export LIBBPFGO = $(CURDIR)/../libbpfgo
export CC = clang
export GOOS = linux
export GOARCH = amd64
export CGO_CFLAGS = -I$(LIBBPFGO)/output -I$(LIBBPFGO)/selftest/common
export CGO_LDFLAGS = -lelf -lzstd $(LIBBPFGO)/output/libbpf/libbpf.a
export GO ?= go

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
	$(GO) build -tags netgo -ldflags '-w -extldflags "-static"' -o ior ./cmd/ior/main.go

.PHONY: clean
clean:
	find . -type f -name ior -delete
	if [ -e ior.bpf.o ]; then rm ior.bpf.o; fi
	make -C ./internal/c clean

.PHONY: world
world: clean generate all

.PHONY: flames
flames:
	perl ~/git/FlameGraph/flamegraph.pl ior-by-path-count-flamegraph.collapsed \
		--title "I/O Syscall Count" --nametype Path --hash --inverted \
		> ior-by-path-count-flamegraph.svg; \
	perl ~/git/FlameGraph/flamegraph.pl ior-by-path-duration-flamegraph.collapsed \
		--title "I/O Syscall Durations" --nametype Path --hash --countname Nanoseconds --inverted \
		> ior-by-path-duration-flamegraph.svg; \
	perl ~/git/FlameGraph/flamegraph.pl ior-by-syscall-count-flamegraph.collapsed \
		--title "I/O Syscall Count" --nametype Path --hash \
		> ior-by-syscall-count-flamegraph.svg; \
	perl ~/git/FlameGraph/flamegraph.pl ior-by-syscall-duration-flamegraph.collapsed \
		--title "I/O Syscall Durations" --nametype Path --hash --countname Nanoseconds \
		> ior-by-syscall-duration-flamegraph.svg; \

.PHONY: inferno
inferno:
	inferno-flamegraph < ior-by-path-count-flamegraph.collapsed \
		--title "I/O Syscall Count" --nametype Path --hash --inverted \
		> ior-by-path-count-flamegraph.svg; \
	inferno-flamegraph < ior-by-path-duration-flamegraph.collapsed \
		--title "I/O Syscall Durations" --nametype Path --hash --countname Nanoseconds --inverted \
		> ior-by-path-duration-flamegraph.svg; \
	inferno-flamegraph < ior-by-syscall-count-flamegraph.collapsed \
		--title "I/O Syscall Count" --nametype Path --hash \
		> ior-by-syscall-count-flamegraph.svg; \
	inferno-flamegraph < ior-by-syscall-duration-flamegraph.collapsed \
		--title "I/O Syscall Durations" --nametype Path --hash --countname Nanoseconds \
		> ior-by-syscall-duration-flamegraph.svg; \

.PHONY: prof
prof:
	$(GO) tool pprof -pdf ./ior ior.cpuprofile > cpuprofile.pdf && evince cpuprofile.pdf &
	$(GO) tool pprof -pdf ./ior ior.memprofile > memprofile.pdf && evince memprofile.pdf &
