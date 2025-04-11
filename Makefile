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

gen: generate
generate: generate

.PHONY: generate
generate:
	make -C ./internal/c generate
	make -C ./internal/tracepoints generate
	make -C ./internal/types generate

.PHONY: gobuild
gobuild:
	$(GO) build -tags netgo -ldflags '-w -extldflags "-static"' -o ior ./cmd/ior/main.go
gobuild_race:
	$(GO) build -tags netgo -ldflags '-w -extldflags "-static"' -race -o ior ./cmd/ior/main.go

.PHONY: clean
clean:
	find . -type f -name ior -delete
	if [ -e ior.bpf.o ]; then rm ior.bpf.o; fi
	make -C ./internal/c clean

.PHONY: mrproper
mrproper: clean
	find . -type f -name \*.zst -delete		
	find . -type f -name \*.collapsed -delete		
	find . -type f -name \*.svg -delete		
	find . -type f -name \*profile -delete		
	find . -type f -name \*.pdf -delete		
	find . -type f -name \*.tmp -delete		
	find . -type f -name palete.map -delete		

.PHONY: world
world: clean generate test all

.PHONY: prof
prof:
	$(GO) tool pprof -pdf ./ior ior.cpuprofile > cpuprofile.pdf && evince cpuprofile.pdf &
	$(GO) tool pprof -pdf ./ior ior.memprofile > memprofile.pdf && evince memprofile.pdf &

.PHONY: test
test:
	$(GO) clean -testcache
	$(GO) test ./... -v

.PHONY: bench
bench:
	$(GO) test ./... -v -bench=. -run xxx
