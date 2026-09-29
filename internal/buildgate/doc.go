// Package buildgate holds fitness tests for the repository's static-analysis
// gates: that `mage world` still runs them, and that the lint configuration's
// exclusions stay scoped to the package they were written for.
//
// It has no production code. The gates it guards are configuration
// (Magefile.go, .golangci.yml) rather than Go APIs, so nothing else in the
// tree fails when they are quietly weakened - which is exactly how the
// errcheck findings this package exists to prevent accumulated in the first
// place: `mage vet` and an ad-hoc `errcheck ./...` both existed, and neither
// ran unless somebody remembered to run it.
package buildgate
