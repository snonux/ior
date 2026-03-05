package integrationtests

import (
	"fmt"

	"ior/internal/flamegraph"
)

// TestResult holds all captured I/O records from a single ior run.
type TestResult struct {
	Records []flamegraph.IterRecord
}

// LoadTestResult parses an .ior.zst file into a TestResult.
func LoadTestResult(iorZstFile string) (TestResult, error) {
	iter, err := flamegraph.LoadFromFile(iorZstFile)
	if err != nil {
		return TestResult{}, fmt.Errorf("load test result: %w", err)
	}

	var result TestResult
	for record := range iter {
		result.Records = append(result.Records, record)
	}
	return result, nil
}
