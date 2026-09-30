package internal

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/textsafe"
	"ior/internal/types"
)

// osc8Payload is a traced name that plants a spoofed OSC 8 hyperlink in a
// terminal printing it raw; osc8Escaped is its textsafe.Escape rendering.
const (
	osc8Payload = "\x1b]8;;http://evil\aclick\x1b]8;;\a"
	osc8Escaped = `\x1b]8;;http://evil\x07click\x1b]8;;\x07`
)

// ttyBuffer records writes like a bytes.Buffer but reports the file
// descriptor of a real pseudo-terminal, so textsafe.IsTerminal's ioctl sees
// a terminal while the test can still read back what was written.
type ttyBuffer struct {
	bytes.Buffer
	pty *os.File
}

func (b *ttyBuffer) Fd() uintptr { return b.pty.Fd() }

// newTTYBuffer opens a pseudo-terminal master for the ttyBuffer, skipping
// the test on hosts without /dev/ptmx.
func newTTYBuffer(t *testing.T) *ttyBuffer {
	t.Helper()
	pty, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { _ = pty.Close() })
	return &ttyBuffer{pty: pty}
}

// hostilePlainPair is a pair whose comm and file carry the OSC 8 payload.
func hostilePlainPair() *event.Pair {
	pair := event.NewPair(&types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Pid: 1, Tid: 2})
	pair.ExitEv = &types.RetEvent{TraceId: types.SYS_EXIT_OPENAT, Pid: 1, Tid: 2, Ret: 3}
	pair.Comm = osc8Payload
	pair.File = file.NewFd(3, "/tmp/"+osc8Payload, 0)
	return pair
}

// parsePlainRow parses one -plain output line as CSV.
func parsePlainRow(t *testing.T, out string) []string {
	t.Helper()
	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil || len(records) != 1 || len(records[0]) != 7 {
		t.Fatalf("output %q is not one 7-column CSV row (records %v, err %v)", out, records, err)
	}
	return records[0]
}

// printPlain emits the hostile pair through a plainSink on w and flushes, so
// buffered (non-terminal) writers show the row too.
func printPlain(t *testing.T, w io.Writer, mode textsafe.EscapeMode) {
	t.Helper()
	sink := newPlainSink(w, mode)
	sink.Print(hostilePlainPair())
	if err := sink.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

// TestPlainPrintCallbackEscapesOnTerminal is the task 7p2 regression test:
// when stdout is a terminal, -plain must not write the traced ESC/BEL bytes.
func TestPlainPrintCallbackEscapesOnTerminal(t *testing.T) {
	out := newTTYBuffer(t)
	printPlain(t, out, textsafe.EscapeAuto)

	got := out.String()
	if strings.ContainsAny(got, "\x1b\a") {
		t.Fatalf("terminal output %q still carries ESC/BEL", got)
	}
	fields := parsePlainRow(t, got)
	if fields[2] != osc8Escaped {
		t.Errorf("comm = %q, want %q", fields[2], osc8Escaped)
	}
	if want := "/tmp/" + osc8Escaped + "%(3,O_RDONLY)"; fields[6] != want {
		t.Errorf("file = %q, want %q", fields[6], want)
	}
}

// TestPlainPrintCallbackRawWhenPiped checks the documented machine-consumer
// behaviour: a non-terminal writer receives the exact traced bytes.
func TestPlainPrintCallbackRawWhenPiped(t *testing.T) {
	var out bytes.Buffer
	printPlain(t, &out, textsafe.EscapeAuto)

	fields := parsePlainRow(t, out.String())
	if fields[2] != osc8Payload {
		t.Errorf("comm = %q, want raw %q", fields[2], osc8Payload)
	}
	if want := "/tmp/" + osc8Payload + "%(3,O_RDONLY)"; fields[6] != want {
		t.Errorf("file = %q, want raw %q", fields[6], want)
	}
}

// TestPlainPrintCallbackEscapeOverrides checks the -escape overrides:
// always escapes into a pipe (| less -R, | tee still end in a terminal),
// never keeps the raw bytes even on a terminal.
func TestPlainPrintCallbackEscapeOverrides(t *testing.T) {
	var piped bytes.Buffer
	printPlain(t, &piped, textsafe.EscapeAlways)
	if got := parsePlainRow(t, piped.String())[2]; got != osc8Escaped {
		t.Errorf("-escape=always into a pipe: comm = %q, want %q", got, osc8Escaped)
	}

	tty := newTTYBuffer(t)
	printPlain(t, tty, textsafe.EscapeNever)
	if got := parsePlainRow(t, tty.String())[2]; got != osc8Payload {
		t.Errorf("-escape=never on a terminal: comm = %q, want raw %q", got, osc8Payload)
	}
}

// openPTYPair opens a pseudo-terminal and returns its master and slave. The
// slave is a real terminal file suitable for os.Stdout; what is written to
// it can be read back from the master.
func openPTYPair(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("unlock pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skipf("pty number: %v", err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open pty slave: %v", err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

// readLine reads from r until a line feed arrives or the timeout expires.
func readLine(t *testing.T, r *os.File) string {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		var got []byte
		buf := make([]byte, 4096)
		for !bytes.ContainsRune(got, '\n') {
			n, err := r.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				break
			}
		}
		done <- string(got)
	}()
	select {
	case got := <-done:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading the pty")
		return ""
	}
}

// emitViaDefaultStdout builds an event loop with the production default
// printCb (plainStdoutSink), swaps os.Stdout for out only afterwards,
// as a test or a late redirect would, and emits the hostile pair.
func emitViaDefaultStdout(t *testing.T, mode textsafe.EscapeMode, out *os.File) {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{plainMode: true, escapeMode: mode, commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	old := os.Stdout
	os.Stdout = out
	defer func() { os.Stdout = old }()
	el.emit(hostilePlainPair())
	// Rows to a pipe are buffered; flushing is the loop's job in production.
	el.flushOutput()
}

// TestPlainStdoutCallbackFollowsStdout covers the production -plain path:
// the default callback binds os.Stdout (and its terminal check) at the first
// pair, so a terminal stdout gets escaped rows, a pipe gets raw rows, and
// -escape overrides the check in both directions.
func TestPlainStdoutCallbackFollowsStdout(t *testing.T) {
	ttyCases := []struct {
		mode textsafe.EscapeMode
		want string
	}{{textsafe.EscapeAuto, osc8Escaped}, {textsafe.EscapeNever, osc8Payload}}
	for _, tc := range ttyCases {
		t.Run("tty/"+tc.mode.String(), func(t *testing.T) {
			master, slave := openPTYPair(t)
			emitViaDefaultStdout(t, tc.mode, slave)
			// The pty line discipline turns LF into CRLF; drop the CR.
			row := strings.ReplaceAll(readLine(t, master), "\r", "")
			if got := parsePlainRow(t, row)[2]; got != tc.want {
				t.Errorf("comm = %q, want %q", got, tc.want)
			}
		})
	}

	pipeCases := []struct {
		mode textsafe.EscapeMode
		want string
	}{{textsafe.EscapeAuto, osc8Payload}, {textsafe.EscapeAlways, osc8Escaped}}
	for _, tc := range pipeCases {
		t.Run("pipe/"+tc.mode.String(), func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("os.Pipe: %v", err)
			}
			defer func() { _ = r.Close() }()
			emitViaDefaultStdout(t, tc.mode, w)
			_ = w.Close()
			if got := parsePlainRow(t, readLine(t, r))[2]; got != tc.want {
				t.Errorf("comm = %q, want %q", got, tc.want)
			}
		})
	}
}
