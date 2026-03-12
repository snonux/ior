# libbpfgo Upgrade Plan

## Goal

Upgrade `ior` from `github.com/aquasecurity/libbpfgo v0.6.0-libbpf-1.3.0...`
to the latest tagged upstream release `v0.9.2-libbpf-1.5.1`, and align the
repo's Go module, local static-link toolchain checkout, build instructions, and
runtime validation on that same tag.

## Current State

- `go.mod` / `go.sum` now pin
  `github.com/aquasecurity/libbpfgo v0.9.2-libbpf-1.5.1`
- `Magefile.go` defaults to the sibling checkout at `../libbpfgo` (local path:
  `/home/paul/git/libbpfgo`) and emits rebuild guidance if static
  artifacts are missing
- The local checkout is currently ahead of the latest tag:
  `v0.9.2-libbpf-1.5.1-23-g9a319d2`
- `README.md`, `AGENTS.md`, and `integrationtests/README.md` now pin the tag,
  sync the `libbpf` submodule, and document the rebuild or validation workflow
- Integration coverage now passes again after restoring the legacy
  `-flamegraph` / `-name` compatibility path used by the harness to collect
  `.ior.zst` artifacts

## Upgrade Target

- Upstream tag: `v0.9.2-libbpf-1.5.1`
- Local checkout to use for static headers/archive:
  `/home/paul/git/libbpfgo`
- Repo-relative default checkout path used by `Magefile.go`: `../libbpfgo`
- Override path for local experiments: `LIBBPFGO=/absolute/path/to/libbpfgo`
- Do not target `libbpfgo` `main` as part of this upgrade unless a tagged
  release blocker is found

## Pinned Source of Truth

- `go.mod` / `go.sum` pin `github.com/aquasecurity/libbpfgo
  v0.9.2-libbpf-1.5.1`
- `README.md`, `AGENTS.md`, and `integrationtests/README.md` document the same
  checkout, tag, validation commands, and `make libbpfgo-static` workflow
- `Magefile.go` fails with explicit rebuild guidance when the local
  `libbpfgo` checkout is missing the static artifacts that `ior` expects
- `internal/ior.go` preserves the legacy `-flamegraph` / `-name` trace-output
  path required by the integration harness while leaving TUI and `-plain`
  behavior unchanged

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
   - Run `env GOTOOLCHAIN=auto mage world`
   - Run root-required `env GOTOOLCHAIN=auto mage integrationTest`
   - Specifically verify:
     - embedded `ior.bpf.o` loading still works
     - tracepoint attach/detach still works
     - ring buffer event ingestion still works
     - static build/link flags still work with the rebuilt local checkout

5. Finalize docs and rollback guidance
   - Document the exact `libbpfgo` tag and rebuild commands
   - Mention the local checkout path used by `Magefile.go`
   - Add troubleshooting notes for submodule sync / static rebuild failures
   - Record the rollback target: `go.mod` pseudo-version
     `v0.6.0-libbpf-1.3.0.20240111220235-90dbffffbdab` plus local checkout
     commit `90dbffffbdab`

## Validation Result

- `env GOTOOLCHAIN=auto mage world` passed after the pinning commit
  `f28dab3`
- `env GOTOOLCHAIN=auto mage integrationTest` passed after compatibility fix
  commit `28338f4`
- The embedded-object path is covered by
  `env GOTOOLCHAIN=auto TEST_NAME=TestLoadBPFModuleUsesEmbeddedObjectByDefault mage testWithName`

## Troubleshooting

- Missing `bpf/bpf.h` or `libbpf` symbols usually means the sibling checkout is
  not at `v0.9.2-libbpf-1.5.1` or was not rebuilt after a `git checkout`.
- Raw `go test` can still fail for packages that import `libbpfgo` because it
  does not inherit the `CGO_CFLAGS`, `CGO_LDFLAGS`, and `LIBBPFGO` values that
  `Magefile.go` sets up. Use Mage targets for validated flows.
- If integration tests fail immediately with unknown `-flamegraph` /
  `-name` flags, rebuild `ior` from a checkout that includes commit `28338f4`.

## Rollback

If the tagged release proves insufficient, revert the `ior` side to
`github.com/aquasecurity/libbpfgo
v0.6.0-libbpf-1.3.0.20240111220235-90dbffffbdab`, reset the sibling checkout,
and rebuild:

```bash
git -C /home/paul/git/libbpfgo checkout 90dbffffbdab
git -C /home/paul/git/libbpfgo submodule update --init --recursive
make -C /home/paul/git/libbpfgo libbpfgo-static
```

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
