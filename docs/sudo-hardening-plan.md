# Sudo use in the build and test targets

This page records the implemented sudo boundary. Run Mage as an ordinary user. Build and
test targets compile as that user. When needed, Mage uses `sudo -n` to read protected kernel
data or run a compiled test binary.

| Target | Elevated part |
|---|---|
| `mage build`, `mage test`, `mage testRace`, `mage vet`, `mage lint` | None on a prepared host |
| `mage generate`, `mage world` | BTF dump and tracepoint-format reads when the host restricts them |
| `mage integrationTest`, `mage integrationTestSerial` | The test binary at `integrationtests.test`, twice, after any build prerequisites: first the test binary of `./internal` restricted to the root link tests, then the integration test binary |
| Integration `testWithName` | Compiled `integrationtests.test` binary (the integration tests only), after any build prerequisites |
| `mage demo`, `mage demoOne` | Demo subprocesses; warm a sudo timestamp with `sudo -v` |
| `mage installDemoTools` | `dnf` package installation |

`Magefile.go` compiles `integrationtests.test` as the caller, then runs its absolute path
from `integrationtests/` through `sudo -n -E`. The working directory lets the harness find
`../ior` and `../ioworkload`. `-n` prevents a password prompt in the middle of a target.
[The example sudoers file](./sudo-rules-for-ior.txt) shows command-specific rules for BTF,
tracefs and the test binary.

`integrationtests.test` is a path, not one program. `mage integrationTest` and
`mage integrationTestSerial` put two different binaries there, one after the other, and run
each as root (`runRootLinkTests` and `runIntegrationTests` in `Magefile.go`):

1. The test binary of `./internal` (`go test -c ./internal/ -o integrationtests.test`), run
   from `internal/` with `-test.run '^(…)$' -test.timeout=5m -test.count=1 -test.v`. The
   pattern names the root link tests of `internal/ior_bpflink_root_test.go`
   (`gatecmd.RootLinkTests`), which load the real BPF object and make libbpf's destroy of
   real links fail. Each of them re-executes the same path as its helper process; that
   child inherits root and needs no second sudo call. The step fails unless every listed
   test is reported as passed, and removes the binary again before the next step, also when
   it failed.
2. The integration test binary (`go test -c ./integrationtests/...`), run from
   `integrationtests/` as described above.

What that means for a host with the example rule: nothing has to change. The rule names the
path and no arguments, and a sudoers command without arguments matches any arguments. It
says nothing about the working directory either: sudo leaves the command in the directory
Mage started it in, `internal/` for the first step and `integrationtests/` for the second.
So the rule that permits the integration run permits the root link step as well. The other
side of that: the rule never restricted which tests run as root. The `-test.run` pattern is
Mage's choice, not something sudo enforces, and the binary at the path is whatever the
caller compiled there.

A host whose administrator tightened the rule beyond the example does need an edit:

- A rule with a fixed argument list written for the integration run does not match the
  root link step, and `mage integrationTest` stops there with `sudo: a password is
  required`. Add a second line for the step, with the arguments as Mage passes them (`=`
  is escaped in a sudoers argument list):

  ```
  %developers ALL=(root) NOPASSWD:SETENV: /home/paul/git/ior/integrationtests.test -test.run ^(TestModuleCloseSurvivesAFailedDestroyOfIorsLinks|TestModuleCloseAfterACleanDestroyOfIorsLinks|TestBareLibbpfgoLinkKeepsItsPointerAfterAFailedDestroy)$ -test.timeout\=5m -test.count\=1 -test.v
  ```

  `visudo -c` accepts that line (sudo 1.9.17); it was not installed and matched against a
  real run, so check it with `sudo -n -l` and one `mage integrationTest`. It has to be kept
  in step with `gatecmd.RootLinkTests` and `gatecmd.RootLinkTestArgs`; the example rule
  without arguments does not.
- A rule with a `CWD=` option (sudo 1.9.3 and later) does not restrict the directory, it
  sets it: `CWD=/home/paul/git/ior/integrationtests` would run both binaries there, and the
  root link step would no longer run in its package directory. Leave `CWD=` off these
  rules, or give the step a line of its own with `CWD=/home/paul/git/ior/internal` and the
  argument list above, which is what tells the two runs apart.

A command-specific sudo rule is still a trust grant: whoever can replace
`integrationtests.test` or `ior` at an allowed path can run that binary as root. Mage
itself does so twice per integration run, as described above. Keep the
checkout and build artifacts under trusted control. The rule also depends on the checkout
path; adjust it when the repo lives elsewhere. `sudo -n true` may fail even when a rule for
the specific test binary works, so check the exact command you intend to run.

The demo has its own sudo timestamp and helper-script flow. The example granular rules do
not cover every demo subprocess. `mage installDemoTools` requires an administrator to
install `ttyd` with `dnf`.

This file was originally a change plan. The code described above is present in `Magefile.go`;
for a new machine, use the [Rocky build guide](./build-rocky-linux-9.md) and validate any
sudoers edits with `visudo -c -f /etc/sudoers.d/ior`.
