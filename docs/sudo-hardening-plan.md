# Sudo use in the build and test targets

This page records the implemented sudo boundary. Run Mage as an ordinary user. Build and
test targets compile as that user. When needed, Mage uses `sudo -n` to read protected kernel
data or run the compiled integration test binary.

| Target | Elevated part |
|---|---|
| `mage build`, `mage test`, `mage testRace`, `mage vet`, `mage lint` | None on a prepared host |
| `mage generate`, `mage world` | BTF dump and tracepoint-format reads when the host restricts them |
| `mage integrationTest`, `mage integrationTestSerial`, integration `testWithName` | Compiled `integrationtests.test` binary, after any build prerequisites |
| `mage demo`, `mage demoOne` | Demo subprocesses; warm a sudo timestamp with `sudo -v` |
| `mage installDemoTools` | `dnf` package installation |

`Magefile.go` compiles `integrationtests.test` as the caller, then runs its absolute path
from `integrationtests/` through `sudo -n -E`. The working directory lets the harness find
`../ior` and `../ioworkload`. `-n` prevents a password prompt in the middle of a target.
[The example sudoers file](./sudo-rules-for-ior.txt) shows command-specific rules for BTF,
tracefs and the test binary.

A command-specific sudo rule is still a trust grant: whoever can replace
`integrationtests.test` or `ior` at an allowed path can run that binary as root. Keep the
checkout and build artifacts under trusted control. The rule also depends on the checkout
path; adjust it when the repo lives elsewhere. `sudo -n true` may fail even when a rule for
the specific test binary works, so check the exact command you intend to run.

The demo has its own sudo timestamp and helper-script flow. The example granular rules do
not cover every demo subprocess. `mage installDemoTools` requires an administrator to
install `ttyd` with `dnf`.

This file was originally a change plan. The code described above is present in `Magefile.go`;
for a new machine, use the [Rocky build guide](./build-rocky-linux-9.md) and validate any
sudoers edits with `visudo -c -f /etc/sudoers.d/ior`.
