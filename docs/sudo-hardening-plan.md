# Sudo Hardening Plan for I/O Riot NG (ior)

## Problem Statement

The current build system (`Magefile.go`) silently wraps entire `go test` invocations—and several generation subcommands—with `sudo` when the invoking user is not root.  This means:

1. **You must trust `mage`** (an arbitrary-code build tool) with root privileges.
2. **An attacker who can modify `Magefile.go`** (or any helper it imports) gets immediate privilege escalation.
3. **It is impossible to audit what actually ran as root**, because the `sudo` command is assembled dynamically inside Go code.

## Goal

Run `mage` **entirely as an unprivileged user**.  Only the **minimal set of specific sub-processes** that genuinely require elevated privileges (`CAP_BPF` / root) should ever run under `sudo`, and they should be invoked with `sudo -n` so no interactive password prompt can be exploited by a malicious build script.

Granular `/etc/sudoers.d/` rules can then grant **password-less, command-locked** access to exactly those subprocesses.

## Threat Model

| Asset | Risk | Mitigation |
|---|---|---|
| `Magefile.go` | Malicious code injection → arbitrary root | `mage` never runs as root; `sudo` is only used for bounded, hard-coded subcommands |
| `go test` | `init()`, `_testmain.go`, or imported packages run arbitrary code at startup | Integration tests are compiled to a static binary first; only the final binary runs under `sudo` |
| `/sys/kernel/tracing` | Leak of kernel tracepoint data | Read-only access to public tracepoint format files (already world-readable on many systems, but the path traversal needs root on locked-down kernels) |
| `bpftool` | Arbitrary BPF object loading | Restricted to the single read-only invocation: `bpftool btf dump file /sys/kernel/btf/vmlinux format c` |
| `ior` binary | Full `CAP_BPF` access | Acceptable because it is the product being tested; access is via a compiled test binary with a deterministic path |

## What Needs Root (and Why)

| Operation | Needs root? | Reason |
|---|---|---|
| Compiling Go / BPF object | **No** | Pure toolchain work |
| `mage test` (unit tests) | **No** | Mocks / stubs; no real BPF attachment |
| `mage generate` / `mage world` | **Partially** | `bpftool btf dump ...` and reading `/sys/kernel/tracing/events/syscalls/*/format` |
| `mage integrationTest` | **Yes** | Spawns `./ior`, which attaches BPF tracepoints |
| `mage integrationTestSerial` | **Yes** | Same |
| `mage demo` / `mage demoOne` | **Yes** | Tapes launch `./ior` (BPF) and `pkill` |
| `mage installDemoTools` | **Yes** | `dnf install` system-wide package |

## Design Principles

1. **Compile as user, run binary as root.**
   - Build the integration-test binary (`go test -c`) while fully unprivileged.
   - Only the resulting `integrationtests.test` binary runs under `sudo`.
2. **Explicit `sudo -n` for every elevated command.**
   - No silent wrapping.
   - If `sudo -n` fails, the build fails with a clear error telling the admin which sudo rule is missing.
3. **Hard-code elevated commands; no dynamic construction.**
   - The exact command line passed to `sudo` must be easily auditable in `Magefile.go`.
4. **Sudoers rules are command-granular.**
   - Each rule locks the user to a single command with exact arguments (or wildcards only where strictly necessary).

## Changes to `Magefile.go`

### 1. Remove automatic `sudo` wrapping from `buildGoTestCmd`

Current behavior: when `os.Geteuid() != 0`, the function manufactures a `sudo env … go test …` command.  **Delete this logic.**  Going forward `buildGoTestCmd` returns a plain `go` command with no privilege elevation.

### 2. Add compiled-binary helper for integration tests

Two new helpers are introduced:

- `compileIntegrationTestBinary(env)` – runs `go test -c ./integrationtests/...` with the required `CGO_*` environment.
- `runIntegrationTestBinary(env, args…)` – elevates **only** the compiled binary via `sudo -n -E ./integrationtests.test …`, running it from the `integrationtests/` directory so that relative path resolution (`../ior`, `../ioworkload`) matches `go test` behaviour.

`IntegrationTest`, `IntegrationTestSerial`, and `testWithName` (when the target is an integration test) are updated to:

1. build `ior`, `ioworkload`, and compile the test binary as an unprivileged user;
2. invoke `runIntegrationTestBinary` to execute the tests under `sudo`.

### 3. Harden existing `sudo*` helpers

- `sudoOutput` is updated to prefix every elevated call with `sudo -n`.
- `sudoRunWithEnv` is updated to prefix every elevated call with `sudo -n env …`.
- `ensureSudoTimestamp` and `startSudoKeepalive` are **retained but restricted** to the `Demo` targets (they are harmless there, and the demo still needs a warm sudo timestamp).

### 4. What stays the same

- `mage build`, `mage test`, `mage testRace`, `mage generateTracepointsGo`, `mage generateTypesGo` – no root required.
- `ensureVMLINUX` and `readSyscallFormats` already call `sudoOutput` for discrete commands; they remain elevated, but now via `sudo -n`.

## Impact on Existing Workflows

| Before | After |
|---|---|
| `mage integrationTest` as non-root → auto `sudo env … go test …` | `mage integrationTest` as non-root → compiles as user, then `sudo -n -E ./integrationtests.test …` |
| Password prompt may appear mid-build | `sudo -n` fails fast if rule missing; no surprise prompts |
| JSON progress ticker from `go test -json` | Dropped for integration-test path; plain `-test.v` style output is printed directly.  (The compiled test binary does not support the `go test` JSON protocol.) |
| `mage testWithName TEST_NAME=TestAioSetup` | Same compiled-binary dance when target is an integration test |
| `mage generate` | Unchanged UX; `sudo -n bpftool …` and `sudo -n sh -c 'cat /sys/kernel/tracing/…'` run automatically if sudoers rules exist |

## Files Modified

- `Magefile.go` – removes implicit sudo wrapping for `go test`; adds compiled-binary helpers.
- `docs/sudo-rules-for-ior.txt` – copy-paste rules for `/etc/sudoers.d/`.

## Deployment Steps for the Admin

1. As **root**, copy `docs/sudo-rules-for-ior.txt` into `/etc/sudoers.d/ior`.
2. Replace `%developers` with the actual Unix group or usernames that need to run tests.
3. Validate syntax: `visudo -c -f /etc/sudoers.d/ior`.
4. As **unprivileged user**, verify: `sudo -n bpftool btf dump file /sys/kernel/btf/vmlinux format c | head -3`.
5. Run `mage integrationTest` as the unprivileged user.

## Known Limitations

- **`mage demo`** is **not covered** by the granular rules.  The demo tapes run a helper script (`run-tape.sh`) that performs multiple privileged actions (`pkill`, launching `./ior`).  Running the demo still requires a broad `NOPASSWD` rule for that script, or running `mage demo` as root.
- **`mage installDemoTools`** requires `dnf` access and remains outside the scope of automated test rules.
- The compiled integration-test binary is invoked from the **repository root**.  Sudoers rules using a wildcard path (`…/ior/integrationtests.test`) assume the repository is checked out somewhere predictable (e.g., `/home/<user>/git/ior/`).  If the checkout lives in arbitrary locations, use a wrapper script at a fixed path.
