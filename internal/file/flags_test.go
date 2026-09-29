package file

import (
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFlagsString(t *testing.T) {
	tests := []struct {
		name  string
		flags Flags
		want  string
	}{
		{name: "unknown", flags: unknownFlag, want: "O_NONE"},
		{name: "read only", flags: Flags(syscall.O_RDONLY), want: "O_RDONLY"},
		{name: "write only", flags: Flags(syscall.O_WRONLY), want: "O_WRONLY"},
		{name: "read write with append", flags: Flags(syscall.O_RDWR | syscall.O_APPEND), want: "O_RDWR|O_APPEND"},
		{name: "invalid access mode", flags: Flags(syscall.O_ACCMODE), want: "O_ACCMODE"},
		{name: "read only with cloexec", flags: Flags(syscall.O_RDONLY | syscall.O_CLOEXEC), want: "O_RDONLY|O_CLOEXEC"},
		{name: "read only with nonblock and cloexec", flags: Flags(syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_CLOEXEC), want: "O_RDONLY|O_CLOEXEC|O_NONBLOCK"},
		{name: "temporary file", flags: Flags(0x410002), want: "O_RDWR|O_TMPFILE"},
		{name: "temporary file with excl", flags: Flags(unix.O_TMPFILE | syscall.O_RDWR | syscall.O_EXCL), want: "O_RDWR|O_TMPFILE|O_EXCL"},
		{name: "read-only directory without temporary file", flags: Flags(syscall.O_RDONLY | syscall.O_DIRECTORY), want: "O_RDONLY|O_DIRECTORY"},
		// O_SYNC includes O_DSYNC, but neither supplies an access mode.
		{name: "read only sync without duplicate dsync", flags: Flags(0x101000), want: "O_RDONLY|O_SYNC"},
		{name: "read only with dsync", flags: Flags(syscall.O_RDONLY | syscall.O_DSYNC), want: "O_RDONLY|O_DSYNC"},
		{name: "path only", flags: Flags(unix.O_PATH), want: "O_PATH"},
		{name: "path with cloexec", flags: Flags(unix.O_PATH | syscall.O_CLOEXEC), want: "O_CLOEXEC|O_PATH"},
		{name: "read only with kernel large-file bit", flags: Flags(syscall.O_RDONLY | linuxOLargefile), want: "O_RDONLY|O_LARGEFILE"},
		{name: "large read-write file", flags: Flags(linuxOLargefile | syscall.O_RDWR), want: "O_RDWR|O_LARGEFILE"},
		{name: "read only with ndelay alias uses canonical name", flags: Flags(syscall.O_RDONLY | syscall.O_NDELAY), want: "O_RDONLY|O_NONBLOCK"},
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
	const want = "O_RDWR|O_TMPFILE"
	flag := Flags(0x410002)

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
