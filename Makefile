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
	make -C ./internal/c redo
	if [ ! -e ioriotng.bpf.o ]; then cp -v ./internal/c/ioriotng.bpf.o .; fi

.PHONY: tracepoint_list.go
tracepoint_list.go:
	# Fetch tracepoint probes from C code and generate list for Go userland code to auto-attach to.
	echo "// Auto-generated from C, don't change manually!" > ./internal/tracepoints/tracepoint_list.go
	echo 'package tracepoints' >> ./internal/tracepoints/tracepoint_list.go
	echo >> ./internal/tracepoints/tracepoint_list.go
	echo 'var tracepointList = []string{' >> ./internal/tracepoints/tracepoint_list.go
	sed -n -E '/^SEC.*sys_(enter|exit)_/ { s/[")]//g; s/.*sys_(.*)/\t"\1",/; p; }' \
		./internal/c/tracepoints/*.c >> ./internal/tracepoints/tracepoint_list.go
	echo '}' >> ./internal/tracepoints/tracepoint_list.go

.PHONY: gobuild
gobuild: tracepoint_list.go
	go build -tags netgo -ldflags '-w -extldflags "-static"' -o ioriotng ./cmd/ioriotng/main.go

.PHONY: clean
clean:
	find . -type f -name ioriotng -delete
	if [ -e ioriotng.bpf.o ]; then rm ioriotng.bpf.o; fi
	make -C ./internal/c clean

.PHONY: run
run:
	sudo ./ioriotng -uid $$(id -u)
