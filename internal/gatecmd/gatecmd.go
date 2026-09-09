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
package gatecmd

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
