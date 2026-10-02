package internal

import (
	"syscall"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/types"
)

// creat and open_by_handle_at return a new descriptor like the open family,
// and their exit records say which file it is. The entry must carry that, or
// its first row would give it whatever identity that row has - in a run that
// captures identities, and only there.
func TestCreatAndOpenByHandleAtRecordTheFileTheyOpened(t *testing.T) {
	_, creat := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid, "/data/created.txt", types.SYS_ENTER_CREAT)
	_, byHandle := makeEnterOpenByHandleEvent(t, defaulTime+1000, execCommPid, execCommTid, syscall.O_RDONLY, defaultTestHandle)
	calls := []struct {
		name  string
		enter []byte
		exit  types.TraceId
		fd    int32
	}{
		{name: "creat", enter: creat, exit: types.SYS_EXIT_CREAT, fd: 47},
		{name: "open_by_handle_at", enter: byHandle, exit: types.SYS_EXIT_OPEN_BY_HANDLE_AT, fd: 48},
	}
	for _, captured := range []bool{true, false} {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		el.trustFileIdents(captured)
		for i, call := range calls {
			exitRaw := identExit(t, call.exit, defaulTime+uint64(i)*1000+openPairLatency, execCommPid, call.fd, 4711)
			mustEmit(t, feedRawPair(t, el, call.enter, exitRaw), call.name)
			tracked, ok := el.fdState().get(call.fd, execCommPid)
			if want := map[bool]uint32{true: 4711, false: 0}[captured]; !ok || identOf(tracked) != want {
				t.Fatalf("%s (captured=%v): entry = %v (ok=%v) with identity %d, want %d",
					call.name, captured, tracked, ok, identOf(tracked), want)
			}
		}
	}
}
