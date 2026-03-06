package file

import (
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestFlagsBuildStringConcurrent(t *testing.T) {
	flagsToHumanCache = sync.Map{}

	const workers = 32
	const iterations = 500
	const want = "O_WRONLY|O_APPEND"
	flag := Flags(syscall.O_WRONLY | syscall.O_APPEND)

	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				var sb strings.Builder
				flag.BuildString(&sb)
				if got := sb.String(); got != want {
					errs <- got
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)

	for got := range errs {
		t.Fatalf("unexpected BuildString output %q, want %q", got, want)
	}
}
