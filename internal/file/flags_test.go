package file

import (
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFlagsStringRendersPathDescriptorsWithoutReadAccess(t *testing.T) {
	tests := []struct {
		name  string
		flags Flags
		want  string
	}{
		{name: "path only", flags: Flags(unix.O_PATH), want: "O_PATH"},
		{name: "path with cloexec", flags: Flags(unix.O_PATH | syscall.O_CLOEXEC), want: "O_CLOEXEC|O_PATH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flags.String(); got != tt.want {
				t.Fatalf("Flags(%#x).String() = %q, want %q", int(tt.flags), got, tt.want)
			}
		})
	}
}

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
