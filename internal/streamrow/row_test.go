package streamrow

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

func TestSequencerStartsAfterSeed(t *testing.T) {
	seq := NewSequencer(41)
	if got, want := seq.Next(), uint64(42); got != want {
		t.Fatalf("first Next() = %d, want %d", got, want)
	}
	if got, want := seq.Next(), uint64(43); got != want {
		t.Fatalf("second Next() = %d, want %d", got, want)
	}
}

func TestSequencerIsMonotonicUnderConcurrency(t *testing.T) {
	seq := NewSequencer(0)

	const workers = 8
	const perWorker = 64

	got := make(chan uint64, workers*perWorker)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				got <- seq.Next()
			}
		}()
	}
	wg.Wait()
	close(got)

	seen := make(map[uint64]struct{}, workers*perWorker)
	for n := range got {
		if _, ok := seen[n]; ok {
			t.Fatalf("duplicate sequence number %d", n)
		}
		seen[n] = struct{}{}
	}
	if got, want := len(seen), workers*perWorker; got != want {
		t.Fatalf("unique sequence count = %d, want %d", got, want)
	}
}

func TestNewPopulatesFieldsFromPair(t *testing.T) {
	enter := &types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Time: 1234, Pid: 42, Tid: 84}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_OPENAT, Time: 1300, Ret: -2, Pid: 42, Tid: 84}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(7, "/tmp/test.txt", 0)
	pair.Comm = "cat"
	pair.Duration = 66
	pair.DurationToPrev = 19
	pair.Bytes = 512
	pair.AddressSpaceBytes = 2048
	pair.RequestedSleepNs = 987_654

	got := New(9, pair)
	if got.Seq != 9 || got.TimeNs != 1234 {
		t.Fatalf("Seq/TimeNs = %d/%d, want 9/1234", got.Seq, got.TimeNs)
	}
	if got.Syscall != "openat" || got.Family != "FS" || got.Comm != "cat" {
		t.Fatalf("Syscall/Family/Comm = %q/%q/%q, want openat/FS/cat", got.Syscall, got.Family, got.Comm)
	}
	if got.PID != 42 || got.TID != 84 {
		t.Fatalf("PID/TID = %d/%d, want 42/84", got.PID, got.TID)
	}
	if got.FileName != "/tmp/test.txt" || got.FD != 7 {
		t.Fatalf("FileName/FD = %q/%d, want /tmp/test.txt/7", got.FileName, got.FD)
	}
	if got.DurationNs != 66 || got.GapNs != 19 || got.Bytes != 512 {
		t.Fatalf("DurationNs/GapNs/Bytes = %d/%d/%d, want 66/19/512", got.DurationNs, got.GapNs, got.Bytes)
	}
	if got.AddressSpaceBytes != 2048 {
		t.Fatalf("AddressSpaceBytes = %d, want 2048", got.AddressSpaceBytes)
	}
	if got.RequestedSleepNs != 987_654 {
		t.Fatalf("RequestedSleepNs = %d, want 987654", got.RequestedSleepNs)
	}
	if got.RetVal != -2 || !got.IsError {
		t.Fatalf("RetVal/IsError = %d/%v, want -2/true", got.RetVal, got.IsError)
	}
}

func TestNewWarningPopulatesSyntheticWarningFields(t *testing.T) {
	got := NewWarning(7, "Dropped malformed event")
	if got.Seq != 7 || got.TimeNs == 0 {
		t.Fatalf("Seq/TimeNs = %d/%d, want 7/non-zero", got.Seq, got.TimeNs)
	}
	if got.Syscall != "warning" || got.Family != "Misc" || got.Comm != "ior" {
		t.Fatalf("Syscall/Family/Comm = %q/%q/%q, want warning/Misc/ior", got.Syscall, got.Family, got.Comm)
	}
	if got.FileName != "Dropped malformed event" || got.FD != UnknownFD {
		t.Fatalf("FileName/FD = %q/%d, want warning text/%d", got.FileName, got.FD, UnknownFD)
	}
	if got.RetVal != -1 || !got.IsError {
		t.Fatalf("RetVal/IsError = %d/%v, want -1/true", got.RetVal, got.IsError)
	}
}

func TestNewCarriesReadyCountForEpollWait(t *testing.T) {
	enter := &types.FdEvent{TraceId: types.SYS_ENTER_EPOLL_WAIT, Time: 2000, Pid: 15, Tid: 16, Fd: 9}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_EPOLL_WAIT, Time: 2100, Ret: 3, Pid: 15, Tid: 16}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(9, "anon_inode:[eventpoll]", -1)

	got := New(17, pair)
	if got.Syscall != "epoll_wait" || got.FD != 9 {
		t.Fatalf("Syscall/FD = %q/%d, want epoll_wait/9", got.Syscall, got.FD)
	}
	if got.RetVal != 3 || got.IsError {
		t.Fatalf("RetVal/IsError = %d/%v, want 3/false", got.RetVal, got.IsError)
	}
	if got.Bytes != 0 {
		t.Fatalf("Bytes = %d, want 0 for epoll ready-count events", got.Bytes)
	}
}

func TestNewCarriesReadyCountForPoll(t *testing.T) {
	enter := &types.PollEvent{TraceId: types.SYS_ENTER_POLL, Time: 3000, Pid: 22, Tid: 23, Nfds: 1, TimeoutNs: 100_000_000}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_POLL, Time: 3100, Ret: 1, Pid: 22, Tid: 23}
	pair := event.NewPair(enter)
	pair.ExitEv = exit

	got := New(24, pair)
	if got.Syscall != "poll" || got.FD != UnknownFD {
		t.Fatalf("Syscall/FD = %q/%d, want poll/%d", got.Syscall, got.FD, UnknownFD)
	}
	if got.RetVal != 1 || got.IsError {
		t.Fatalf("RetVal/IsError = %d/%v, want 1/false", got.RetVal, got.IsError)
	}
	if got.Bytes != 0 {
		t.Fatalf("Bytes = %d, want 0 for poll ready-count events", got.Bytes)
	}
}

func TestNewCarriesRequestedSleepNs(t *testing.T) {
	enter := &types.SleepEvent{TraceId: types.SYS_ENTER_NANOSLEEP, Time: 3200, Pid: 31, Tid: 32, RequestedNs: 5_000_000}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_NANOSLEEP, Time: 3300, Ret: 0, Pid: 31, Tid: 32}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.RequestedSleepNs = enter.RequestedNs

	got := New(25, pair)
	if got.Syscall != "nanosleep" || got.FD != UnknownFD {
		t.Fatalf("Syscall/FD = %q/%d, want nanosleep/%d", got.Syscall, got.FD, UnknownFD)
	}
	if got.RequestedSleepNs != 5_000_000 {
		t.Fatalf("RequestedSleepNs = %d, want 5000000", got.RequestedSleepNs)
	}
	if got.Bytes != 0 {
		t.Fatalf("Bytes = %d, want 0 for sleep events", got.Bytes)
	}
}

// TestRowValueAccessors verifies that all typed accessor methods return the
// underlying field values set on a Row.
func TestRowValueAccessors(t *testing.T) {
	r := Row{
		Syscall:    "read",
		Comm:       "cat",
		FileName:   "/etc/hosts",
		PID:        10,
		TID:        11,
		FD:         3,
		DurationNs: 500,
		GapNs:      200,
		Bytes:      1024,
		RetVal:     -1,
		IsError:    true,
	}

	if r.SyscallValue() != "read" {
		t.Fatalf("SyscallValue = %q, want read", r.SyscallValue())
	}
	if r.CommValue() != "cat" {
		t.Fatalf("CommValue = %q, want cat", r.CommValue())
	}
	if r.FileValue() != "/etc/hosts" {
		t.Fatalf("FileValue = %q, want /etc/hosts", r.FileValue())
	}
	if r.PIDValue() != 10 {
		t.Fatalf("PIDValue = %d, want 10", r.PIDValue())
	}
	if r.TIDValue() != 11 {
		t.Fatalf("TIDValue = %d, want 11", r.TIDValue())
	}
	if r.FDValue() != 3 {
		t.Fatalf("FDValue = %d, want 3", r.FDValue())
	}
	if r.LatencyValue() != 500 {
		t.Fatalf("LatencyValue = %d, want 500", r.LatencyValue())
	}
	if r.GapValue() != 200 {
		t.Fatalf("GapValue = %d, want 200", r.GapValue())
	}
	if r.BytesValue() != 1024 {
		t.Fatalf("BytesValue = %d, want 1024", r.BytesValue())
	}
	if r.ReturnValue() != -1 {
		t.Fatalf("ReturnValue = %d, want -1", r.ReturnValue())
	}
	if !r.ErrorValue() {
		t.Fatal("ErrorValue = false, want true")
	}
}

// TestSequencerNilSafeNext verifies that calling Next on a nil Sequencer returns
// 0 without panicking.
func TestSequencerNilSafeNext(t *testing.T) {
	var s *Sequencer
	if got := s.Next(); got != 0 {
		t.Fatalf("nil Sequencer.Next() = %d, want 0", got)
	}
}

// TestNewCarriesRetForSeccompAndModuleExits locks in audit finding M1/F2 at the
// row level. seccomp/init_module/delete_module used to emit a payload-less
// null_event on the exit side, so New() found no *types.RetEvent and every row
// reported ret=0, is_error=false even for a failing call. The generator now
// classifies those exits as KindRet (ret_event), so a negative return has to
// surface here as RetVal < 0 and IsError.
func TestNewCarriesRetForSeccompAndModuleExits(t *testing.T) {
	tests := []struct {
		name        string
		enterID     types.TraceId
		exitID      types.TraceId
		wantSyscall string
		ret         int64
		wantIsError bool
	}{
		{"seccomp", types.SYS_ENTER_SECCOMP, types.SYS_EXIT_SECCOMP, "seccomp", -1, true},
		{"init_module", types.SYS_ENTER_INIT_MODULE, types.SYS_EXIT_INIT_MODULE, "init_module", -13, true},
		{"delete_module", types.SYS_ENTER_DELETE_MODULE, types.SYS_EXIT_DELETE_MODULE, "delete_module", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enter := &types.NullEvent{TraceId: tt.enterID, Time: 10, Pid: 5, Tid: 6}
			pair := event.NewPair(enter)
			pair.ExitEv = &types.RetEvent{TraceId: tt.exitID, Time: 20, Ret: tt.ret, Pid: 5, Tid: 6}

			got := New(1, pair)
			if got.Syscall != tt.wantSyscall {
				t.Fatalf("Syscall = %q, want %q", got.Syscall, tt.wantSyscall)
			}
			if got.RetVal != tt.ret || got.IsError != tt.wantIsError {
				t.Fatalf("RetVal/IsError = %d/%v, want %d/%v", got.RetVal, got.IsError, tt.ret, tt.wantIsError)
			}
			if got.ReturnValue() != tt.ret || got.ErrorValue() != tt.wantIsError {
				t.Fatalf("ReturnValue/ErrorValue = %d/%v, want %d/%v",
					got.ReturnValue(), got.ErrorValue(), tt.ret, tt.wantIsError)
			}
		})
	}
}

// TestNewCarriesRetForKindSpecificExits covers the kind-specific exit events.
// New() used to type-assert *types.RetEvent only, so accept/accept4,
// pipe/pipe2, socketpair and the eventfd/pidfd family — whose BPF structs do
// carry a ret alongside their extra payload — rendered ret=0, is_error=false
// even for a failing call. New() now reads the value through
// event.RetCarrier, so a negative return has to surface as RetVal < 0 and
// IsError on every one of them.
func TestNewCarriesRetForKindSpecificExits(t *testing.T) {
	tests := []struct {
		name        string
		enter       event.Event
		exit        event.Event
		wantSyscall string
		wantRet     int64
		wantIsError bool
	}{
		{
			name:        "accept failing",
			enter:       &types.AcceptEvent{TraceId: types.SYS_ENTER_ACCEPT, Time: 10, Pid: 5, Tid: 6, Fd: 3, Ret: -1},
			exit:        &types.AcceptEvent{TraceId: types.SYS_EXIT_ACCEPT, Time: 20, Pid: 5, Tid: 6, Fd: -1, Ret: -11},
			wantSyscall: "accept",
			wantRet:     -11,
			wantIsError: true,
		},
		{
			name:        "accept4 succeeding",
			enter:       &types.AcceptEvent{TraceId: types.SYS_ENTER_ACCEPT4, Time: 10, Pid: 5, Tid: 6, Fd: 3, Ret: -1},
			exit:        &types.AcceptEvent{TraceId: types.SYS_EXIT_ACCEPT4, Time: 20, Pid: 5, Tid: 6, Fd: -1, Ret: 9},
			wantSyscall: "accept4",
			wantRet:     9,
			wantIsError: false,
		},
		{
			name:        "pipe failing",
			enter:       &types.PipeEvent{TraceId: types.SYS_ENTER_PIPE, Time: 10, Pid: 5, Tid: 6, Fd0: -1, Fd1: -1, Ret: -1},
			exit:        &types.PipeEvent{TraceId: types.SYS_EXIT_PIPE, Time: 20, Pid: 5, Tid: 6, Fd0: -1, Fd1: -1, Ret: -24},
			wantSyscall: "pipe",
			wantRet:     -24,
			wantIsError: true,
		},
		{
			name:        "pipe2 succeeding",
			enter:       &types.PipeEvent{TraceId: types.SYS_ENTER_PIPE2, Time: 10, Pid: 5, Tid: 6, Fd0: -1, Fd1: -1, Ret: -1},
			exit:        &types.PipeEvent{TraceId: types.SYS_EXIT_PIPE2, Time: 20, Pid: 5, Tid: 6, Fd0: 7, Fd1: 8, Ret: 0},
			wantSyscall: "pipe2",
			wantRet:     0,
			wantIsError: false,
		},
		{
			name:        "socketpair failing",
			enter:       &types.SocketpairEvent{TraceId: types.SYS_ENTER_SOCKETPAIR, Time: 10, Pid: 5, Tid: 6, Sv0: -1, Sv1: -1, Ret: -1},
			exit:        &types.SocketpairEvent{TraceId: types.SYS_EXIT_SOCKETPAIR, Time: 20, Pid: 5, Tid: 6, Sv0: -1, Sv1: -1, Ret: -93},
			wantSyscall: "socketpair",
			wantRet:     -93,
			wantIsError: true,
		},
		{
			name:        "eventfd2 failing",
			enter:       &types.EventfdEvent{TraceId: types.SYS_ENTER_EVENTFD2, Time: 10, Pid: 5, Tid: 6, Ret: -1},
			exit:        &types.EventfdEvent{TraceId: types.SYS_EXIT_EVENTFD2, Time: 20, Pid: 5, Tid: 6, Ret: -24},
			wantSyscall: "eventfd2",
			wantRet:     -24,
			wantIsError: true,
		},
		{
			name:        "pidfd_open failing",
			enter:       &types.EventfdEvent{TraceId: types.SYS_ENTER_PIDFD_OPEN, Time: 10, Pid: 5, Tid: 6, Ret: -1},
			exit:        &types.EventfdEvent{TraceId: types.SYS_EXIT_PIDFD_OPEN, Time: 20, Pid: 5, Tid: 6, Ret: -3},
			wantSyscall: "pidfd_open",
			wantRet:     -3,
			wantIsError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair := event.NewPair(tt.enter)
			pair.ExitEv = tt.exit

			got := New(1, pair)
			if got.Syscall != tt.wantSyscall {
				t.Fatalf("Syscall = %q, want %q", got.Syscall, tt.wantSyscall)
			}
			if got.RetVal != tt.wantRet || got.IsError != tt.wantIsError {
				t.Fatalf("RetVal/IsError = %d/%v, want %d/%v",
					got.RetVal, got.IsError, tt.wantRet, tt.wantIsError)
			}
			if got.ReturnValue() != tt.wantRet || got.ErrorValue() != tt.wantIsError {
				t.Fatalf("ReturnValue/ErrorValue = %d/%v, want %d/%v",
					got.ReturnValue(), got.ErrorValue(), tt.wantRet, tt.wantIsError)
			}
		})
	}
}

// retCarrierFixtures builds one exit event per generated event type that
// carries a `ret` field, keyed by the Go type name as it appears in
// internal/types/generated_types.go. TestNewCoversEveryRetCarryingEventType
// cross-checks this map against the committed artifact, so adding a new
// ret-carrying kind fails the build here until it is proven to reach Row.
var retCarrierFixtures = map[string]func(ret int64) event.Event{
	"RetEvent": func(ret int64) event.Event {
		return &types.RetEvent{TraceId: types.SYS_EXIT_OPENAT, Time: 20, Pid: 5, Tid: 6, Ret: ret}
	},
	"SocketpairEvent": func(ret int64) event.Event {
		return &types.SocketpairEvent{TraceId: types.SYS_EXIT_SOCKETPAIR, Time: 20, Pid: 5, Tid: 6, Ret: ret}
	},
	"AcceptEvent": func(ret int64) event.Event {
		return &types.AcceptEvent{TraceId: types.SYS_EXIT_ACCEPT, Time: 20, Pid: 5, Tid: 6, Ret: ret}
	},
	"PipeEvent": func(ret int64) event.Event {
		return &types.PipeEvent{TraceId: types.SYS_EXIT_PIPE, Time: 20, Pid: 5, Tid: 6, Ret: ret}
	},
	"EventfdEvent": func(ret int64) event.Event {
		return &types.EventfdEvent{TraceId: types.SYS_EXIT_EVENTFD2, Time: 20, Pid: 5, Tid: 6, Ret: ret}
	},
}

// TestNewCoversEveryRetCarryingEventType is the anti-rot invariant for the
// RetCarrier fix: it parses the committed internal/types/generated_types.go,
// collects every generated struct with a Ret field, and asserts each one both
// satisfies event.RetCarrier and actually propagates its return value through
// New(). A newly generated ret-carrying kind therefore cannot silently render
// ret=0, is_error=false — this test fails until it is wired up and proven.
func TestNewCoversEveryRetCarryingEventType(t *testing.T) {
	names, err := retCarryingGeneratedTypes()
	if err != nil {
		t.Fatalf("scan generated types: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("no ret-carrying generated event types found; scan is broken")
	}

	for _, name := range names {
		newExit, ok := retCarrierFixtures[name]
		if !ok {
			t.Errorf("generated type %s carries a Ret field but has no fixture; add it to "+
				"retCarrierFixtures so streamrow.New coverage is proven for it", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			exit := newExit(-13)
			if _, ok := exit.(event.RetCarrier); !ok {
				t.Fatalf("%s does not satisfy event.RetCarrier; the types generator "+
					"must emit GetRet for every struct with a ret member", name)
			}

			pair := event.NewPair(&types.NullEvent{TraceId: types.SYS_ENTER_OPENAT, Time: 10, Pid: 5, Tid: 6})
			pair.ExitEv = exit
			if got := New(1, pair); got.RetVal != -13 || !got.IsError {
				t.Fatalf("New() with %s exit ret=-13 gave RetVal/IsError = %d/%v, want -13/true",
					name, got.RetVal, got.IsError)
			}

			pair = event.NewPair(&types.NullEvent{TraceId: types.SYS_ENTER_OPENAT, Time: 10, Pid: 5, Tid: 6})
			pair.ExitEv = newExit(4)
			if got := New(1, pair); got.RetVal != 4 || got.IsError {
				t.Fatalf("New() with %s exit ret=4 gave RetVal/IsError = %d/%v, want 4/false",
					name, got.RetVal, got.IsError)
			}
		})
	}

	known := make(map[string]struct{}, len(names))
	for _, name := range names {
		known[name] = struct{}{}
	}
	for name := range retCarrierFixtures {
		if _, ok := known[name]; !ok {
			t.Errorf("retCarrierFixtures has a stale entry %s: no such ret-carrying generated type", name)
		}
	}
}

// retCarryingGeneratedTypes returns the names of every struct in the committed
// internal/types/generated_types.go that has a Ret field.
func retCarryingGeneratedTypes() ([]string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	path := filepath.Join(repoRoot, "internal", "types", "generated_types.go")

	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}

	var names []string
	ast.Inspect(parsed, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		for _, f := range st.Fields.List {
			for _, fieldName := range f.Names {
				if fieldName.Name == "Ret" {
					names = append(names, ts.Name.Name)
					return true
				}
			}
		}
		return true
	})
	sort.Strings(names)
	return names, nil
}
