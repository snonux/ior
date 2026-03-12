# libbpfgo Upgrade Plan

## Goal

Upgrade `ior` from `github.com/aquasecurity/libbpfgo v0.6.0-libbpf-1.3.0...`
to the latest tagged upstream release `v0.9.2-libbpf-1.5.1`, and align the
repo's Go module, local static-link toolchain checkout, build instructions, and
runtime validation on that same tag.

## Current State

- `go.mod` / `go.sum` are expected to pin
  `github.com/aquasecurity/libbpfgo v0.9.2-libbpf-1.5.1`
- `Magefile.go` defaults to the sibling checkout at `../libbpfgo` (local path:
  `/home/paul/git/libbpfgo`) and should emit rebuild guidance if static
  artifacts are missing
- The local checkout is currently ahead of the latest tag:
  `v0.9.2-libbpf-1.5.1-23-g9a319d2`
- `README.md` / `AGENTS.md` should pin the tag, sync the `libbpf` submodule,
  and document the static rebuild workflow explicitly

## Upgrade Target

- Upstream tag: `v0.9.2-libbpf-1.5.1`
- Local checkout to use for static headers/archive:
  `/home/paul/git/libbpfgo`
- Repo-relative default checkout path used by `Magefile.go`: `../libbpfgo`
- Override path for local experiments: `LIBBPFGO=/absolute/path/to/libbpfgo`
- Do not target `libbpfgo` `main` as part of this upgrade unless a tagged
  release blocker is found

## Pinned Source of Truth

- `go.mod` / `go.sum` should pin `github.com/aquasecurity/libbpfgo
  v0.9.2-libbpf-1.5.1`
- `README.md` and `AGENTS.md` should document the same checkout, tag, submodule,
  and `make libbpfgo-static` workflow
- `Magefile.go` should fail with explicit rebuild guidance when the local
  `libbpfgo` checkout is missing the static artifacts that `ior` expects

## Breaking-Change Watchpoints

- `v0.8.0-libbpf-1.5` includes a `BPFProg` API alignment change
- `v0.9.1-libbpf-1.5.1` changes `AttachUprobe` /
  `AttachURetprobe` signatures
- `libbpf` minimum version moves from `1.3.x` to `1.5.1`
- Static builds require `git submodule update --init --recursive` in the local
  `libbpfgo` checkout before `make libbpfgo-static`

`ior` appears to use a narrow subset of APIs:

- module loading (`NewModuleFromFile`, `NewModuleFromBuffer`, `BPFLoadObject`)
- maps (`GetMap`, `SetMaxEntries`, `InitGlobalVariable`)
- ringbuf (`InitRingBuf`)
- program lookup and tracepoint attach (`GetProgram`, `AttachTracepoint`)

The direct API-break risk is therefore expected to be low, but compile/runtime
validation is still required.

## Implementation Workstreams

1. Align the version source of truth
   - Pin `go.mod` / `go.sum` to `v0.9.2-libbpf-1.5.1`
   - Align the local checkout instructions in `README.md`
   - Align `AGENTS.md` and `Magefile.go` guidance with the same tag and rebuild flow
   - Ensure the local checkout is reset to the exact tag and rebuilt

2. Rebuild the local static toolchain
   - In `/home/paul/git/libbpfgo`:
     - `git checkout v0.9.2-libbpf-1.5.1`
     - `git submodule update --init --recursive`
     - `make libbpfgo-static`

3. Compile and fix `ior`
   - Rebuild `ior` against the upgraded wrapper and static `libbpf`
   - Fix any compile/API regressions in:
     - `internal/ior.go`
     - `internal/bpfsetup.go`
     - `internal/bpfembed.go`
     - any `probemanager` adapter code if signatures changed

4. Validate behavior
   - Run `mage world`
   - Run root-required integration coverage
   - Specifically verify:
     - embedded `ior.bpf.o` loading still works
     - tracepoint attach/detach still works
     - ring buffer event ingestion still works
     - static build/link flags still work with the rebuilt local checkout

5. Finalize docs and rollback guidance
   - Document the exact `libbpfgo` tag and rebuild commands
   - Mention the local checkout path used by `Magefile.go`
   - Add troubleshooting notes for submodule sync / static rebuild failures

## Validation Commands

- `GOTOOLCHAIN=auto mage test`
- `GOTOOLCHAIN=auto mage world`
- `GOTOOLCHAIN=auto mage integrationTest`

## References

- Repo files:
  - `go.mod`
  - `README.md`
  - `AGENTS.md`
  - `Magefile.go`
  - `internal/ior.go`
  - `internal/bpfsetup.go`
  - `internal/bpfembed.go`
- Local toolchain checkout:
  - `/home/paul/git/libbpfgo`
