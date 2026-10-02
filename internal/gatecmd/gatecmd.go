// Package gatecmd holds the command lines of the repository's static-analysis
// gates as data.
//
// Magefile.go is behind `//go:build mage`, so nothing can import it and any
// test of what `mage lint` or `mage vet` actually runs has to work from the
// source text. That was tried for several rounds and lost repeatedly: a target
// whose body merely mentions the right strings, a flag routed through a
// constant, a helper wrapping the invocation, a guard clause returning early -
// each read correctly and ran something else, or nothing.
//
// Keeping the argv here instead makes it ordinary Go that internal/buildgate
// imports, asserts on, and executes against a package with a planted defect.
// The Mage targets become the thin wrappers that supply the environment and
// check the error.
//
// The root link step of `mage integrationTest` is here for the same reason,
// although it is no static-analysis gate: which tests it runs, with which
// arguments, and how it tells that they ran at all (RootLinkTests,
// RootLinkTestArgs, RootLinkTestsNotPassed).
package gatecmd

import "strings"

// GolangciLintBin is the linter binary the lint gate runs, and GolangciLintPkg
// is the module path `mage lint` names when it is missing from PATH.
const (
	GolangciLintBin = "golangci-lint"
	GolangciLintPkg = "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"
)

// VetUnsafeptrExempt is the one package vetted with the unsafeptr analyzer
// disabled. cmd/ioworkload converts the address returned by SYS_SHMAT into a
// []byte so the workload can fault the shared page in, and vet cannot tell a
// kernel-supplied mapping address from a raw integer. Every other package is
// vetted with the full analyzer set.
const VetUnsafeptrExempt = "ior/cmd/ioworkload"

// LintConfigVerify is the pre-flight that rejects a configuration `run` would
// otherwise half-ignore: golangci-lint silently drops keys it does not
// recognize, so a typo reports "0 issues" from a config nobody reviewed.
func LintConfigVerify() []string {
	return []string{GolangciLintBin, "config", "verify"}
}

// LintRun is the lint gate itself.
//
// The mage build tag is passed so Magefile.go is linted too: the default build
// ignores `//go:build mage`, which would leave the one file that defines the
// gate as the one file outside it. A single pass suffices only while no file
// is excluded *by* that tag, which internal/buildgate asserts against the
// toolchain's own package lists.
func LintRun() []string {
	return []string{GolangciLintBin, "run", "--build-tags", "mage", "./..."}
}

// VetAll vets the given packages with the full analyzer set. The caller passes
// every package in the module except VetUnsafeptrExempt.
func VetAll(packages []string) []string {
	return append([]string{"go", "vet"}, packages...)
}

// VetUnsafeptrExempted vets the one exempt package with unsafeptr disabled.
func VetUnsafeptrExempted() []string {
	return []string{"go", "vet", "-unsafeptr=false", VetUnsafeptrExempt}
}

// CleanTestCache drops cached test results so Test always really runs.
func CleanTestCache() []string {
	return []string{"go", "clean", "-testcache"}
}

// TestAll runs the whole suite. The timeout is generous because the
// integration tests drive real workloads.
func TestAll() []string {
	return []string{"go", "test", "./...", "-failfast", "-timeout=90m"}
}

// RootLinkTests are the tests of internal/ior_bpflink_root_test.go: they load
// the real BPF object, make libbpf's destroy of real links fail and close the
// module (task 123), and read the skipped runs of really attached programs
// (task 723). They skip for anybody but root, so `mage test` passes
// them by, and the root link step of `mage integrationTest` is the one place
// that runs them. The names are listed rather than matched by a pattern so
// that a renamed test fails a gate (internal/buildgate) instead of silently
// no longer running.
func RootLinkTests() []string {
	return []string{
		"TestModuleCloseSurvivesAFailedDestroyOfIorsLinks",
		"TestModuleCloseAfterACleanDestroyOfIorsLinks",
		"TestBareLibbpfgoLinkKeepsItsPointerAfterAFailedDestroy",
		"TestSkippedRunsAreReadFromReallyAttachedPrograms",
	}
}

// RootLinkTestArgs are the arguments the test binary of ./internal gets to
// run RootLinkTests, and nothing else, as root. -test.v is not for the reader
// alone: RootLinkTestsNotPassed reads the verdicts it prints.
func RootLinkTestArgs() []string {
	return []string{
		"-test.run", "^(" + strings.Join(RootLinkTests(), "|") + ")$",
		"-test.timeout=5m",
		"-test.count=1",
		"-test.v",
	}
}

// RootLinkTestsNotPassed returns the tests of RootLinkTests that output, the
// -test.v output of the test binary, does not report as passed.
//
// The exit status of the binary cannot say so. A test binary whose -test.run
// matches nothing prints "testing: warning: no tests to run" and exits 0, and
// so does one whose tests all skipped - which is what these do for anybody
// but root. Either would make the step a green no-op. A verdict counts only
// at the start of a line, where the testing package prints that of a
// top-level test; a subtest's is indented.
func RootLinkTestsNotPassed(output string) []string {
	passed := map[string]bool{}
	for line := range strings.SplitSeq(output, "\n") {
		if rest, ok := strings.CutPrefix(line, "--- PASS: "); ok {
			name, _, _ := strings.Cut(rest, " ")
			passed[name] = true
		}
	}
	var missing []string
	for _, name := range RootLinkTests() {
		if !passed[name] {
			missing = append(missing, name)
		}
	}
	return missing
}
