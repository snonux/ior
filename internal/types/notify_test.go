package types

import (
	"encoding/binary"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestFdPathCodecsAcceptOnlyReviewedLayouts(t *testing.T) {
	want := &FdPathEvent{EventType: ENTER_FD_PATH_EVENT, TraceId: SYS_ENTER_FANOTIFY_MARK,
		Time: 0x123456789abcdef, Pid: 420, Tid: 421, Fd: 27, Dirfd: -100,
		PathnameStatus: PATH_READ_NULL, Flags: 0x10203040, SchemaVersion: FD_PATH_EVENT_SCHEMA_VERSION}
	copy(want.Pathname[:], "/watch/target")
	if unsafe.Sizeof(*want) != 304 || unsafe.Offsetof(want.Pathname) != 32 || unsafe.Offsetof(want.SchemaVersion) != 296 {
		t.Fatalf("Go fd_path_event layout changed: size=%d pathname=%d schema=%d", unsafe.Sizeof(*want), unsafe.Offsetof(want.Pathname), unsafe.Offsetof(want.SchemaVersion))
	}
	compact, err := want.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(compact) != 300 {
		t.Fatalf("compact size=%d, want 300", len(compact))
	}
	for _, decode := range []func([]byte) *FdPathEvent{NewFdPathEvent, NewFdPathEventFast} {
		for _, size := range []int{300, 304} {
			raw := make([]byte, size)
			copy(raw, compact)
			got := decode(raw)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("decode %d bytes: got %+v, want %+v", size, got, want)
			}
			got.Recycle()
			// Reused pool objects must not retain the prior event's fields.
			clear(raw)
			binary.LittleEndian.PutUint32(raw[296:300], FD_PATH_EVENT_SCHEMA_VERSION)
			got = decode(raw)
			if !reflect.DeepEqual(got, &FdPathEvent{SchemaVersion: FD_PATH_EVENT_SCHEMA_VERSION}) {
				t.Fatalf("pooled decode retained fields: %+v", got)
			}
			got.Recycle()
			binary.LittleEndian.PutUint32(raw[296:300], FD_PATH_EVENT_SCHEMA_VERSION+1)
			if decode(raw) != nil {
				t.Fatal("unknown schema accepted")
			}
		}
		for size := 0; size <= 312; size++ {
			if size == 300 || size == 304 {
				continue
			}
			raw := make([]byte, size)
			copy(raw, compact)
			if decode(raw) != nil {
				t.Fatalf("unexpected size %d accepted", size)
			}
		}
	}
}

// Compile the actual C header to exercise the producer's alignment and bytes,
// independently of the generated Go encoder or its matching field offsets.
func TestFdPathDecodesCProducer(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("C compiler required for the notification ABI test: ", err)
	}
	binaryPath := filepath.Join(t.TempDir(), "notify-producer")
	cmd := exec.Command(compiler, "-x", "c", "-I../c", "-o", binaryPath, "-")
	cmd.Stdin = strings.NewReader(`#include <linux/types.h>
#include <stdio.h>
#include <string.h>
#include "types.h"
int main(void) {
    struct fd_path_event ev;
    memset(&ev, 0xa5, sizeof(ev));
    ev.event_type = ENTER_FD_PATH_EVENT;
    ev.trace_id = 713;
    ev.time = 0x123456789abcdefULL;
    ev.pid = 420;
    ev.tid = 421;
    ev.fd = 27;
    ev.dirfd = -100;
    memset(ev.pathname, 0, sizeof(ev.pathname));
    strcpy(ev.pathname, "/c/producer");
    ev.pathname_status = PATH_READ_FAILED;
    ev.flags = 0x10203040;
    ev.schema_version = FD_PATH_EVENT_SCHEMA_VERSION;
    return fwrite(&ev, sizeof(ev), 1, stdout) != 1;
}
`)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile producer: %v\n%s", err, output)
	}
	raw, err := exec.Command(binaryPath).Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 304 {
		t.Fatalf("C producer size=%d, want 304", len(raw))
	}
	want := &FdPathEvent{EventType: ENTER_FD_PATH_EVENT, TraceId: 713, Time: 0x123456789abcdef,
		Pid: 420, Tid: 421, Fd: 27, Dirfd: -100, PathnameStatus: PATH_READ_FAILED,
		Flags: 0x10203040, SchemaVersion: FD_PATH_EVENT_SCHEMA_VERSION}
	copy(want.Pathname[:], "/c/producer")
	for _, decode := range []func([]byte) *FdPathEvent{NewFdPathEvent, NewFdPathEventFast} {
		got := decode(raw)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("decode producer: got %+v, want %+v", got, want)
		}
		got.Recycle()
	}
}
