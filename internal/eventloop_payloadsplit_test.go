package internal

import (
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/streamrow"
	"ior/internal/types"
)

// Task 89 split the rare payloads out of three hot ring-buffer records:
//
//   - fd_event lost the requested-size tail that only fgetxattr/flistxattr
//     fill (now fd_size_event);
//   - two_fd_event lost the two 256-byte names that only move_mount fills
//     (now two_fd_names_event);
//   - eventfd_event lost the 256-byte name that only memfd_create and fsopen
//     fill (now eventfd_name_event).
//
// The change must not be visible in any row. The scenario below drives every
// moved syscall - and the hot syscalls that share their state (open, read,
// dup, close) - through the real raw-event path, and compares the rows with
// goldens captured by running the very same scenario, encoded in the old wire
// layout, through the code before the split (commit 5313780). Every record is
// built from explicit byte offsets rather than from the generated Go types, so
// the builders compile and mean the same thing on both sides of the change.
//
// The golden rows list the streamrow.Row fields through rowNonZeroFields, which
// leaves out zero-valued fields. A %+v dump of the whole struct made every
// additive Row field (NoFile in task zp2, IsWarning in task rq2) rewrite every
// golden line, and the test failed at HEAD after rq2 for that reason alone.
// With zero fields omitted, a new field that stays zero in this scenario needs
// no golden change, while one that becomes non-zero (a real change of a row)
// still fails the comparison. The pre-split capture's values are unchanged: the
// golden is the original %+v capture with its zero-valued fields dropped, and
// with its pid/tid (4242, the fixture's then value) rewritten to execCommPid,
// absentPidBase + 4242 (task zs2): the scenario leaves descriptors untraced on
// purpose ("E:name" rows), which only holds while procfs finds no such pid.
//
// Both wire generations are checked against the one golden: payloadWireSplit
// is what the current BPF object emits, payloadWireWide is what an older
// object (an IOR_BPF_OBJECT override) still emits and must keep decoding to
// the same rows.

type payloadWire int

const (
	// payloadWireWide is the pre-split layout: fd_event 48 B with the size
	// tail, two_fd_event 568 B and eventfd_event 312 B with their names.
	payloadWireWide payloadWire = iota
	// payloadWireSplit is the current layout: lean hot records and dedicated
	// records for the rare payloads.
	payloadWireSplit
)

func (w payloadWire) String() string {
	if w == payloadWireWide {
		return "wide"
	}
	return "split"
}

// Event type numbers from internal/c/types.h. They are literals so that this
// file also compiles against the pre-split tree the goldens were taken from.
const (
	psEnterOpen         = 1
	psExitRet           = 8
	psEnterFd           = 5
	psEnterEventfd      = 27
	psExitEventfd       = 28
	psEnterTwoFd        = 37
	psOpenNameFixup     = 48
	psEnterFdSize       = 56
	psEnterTwoFdNames   = 58
	psEnterEventfdName  = 60
	psPathReadOK        = 0
	psPathReadNull      = 1
	psPathReadFailed    = 2
	psReadClassified    = 1
	psWriteClassified   = 2
	psUnclassified      = 0
	psFdSizeSchema      = 1
	psTwoFdSchema       = 3
	psEventfdNameSchema = 2
	psOpenSchema        = 3
)

// payloadScenario accumulates the raw records of one run in ring-buffer order.
type payloadScenario struct {
	wire payloadWire
	now  uint64
	raws [][]byte
}

const (
	psPid     = execCommPid
	psTid     = execCommTid
	psLatency = 100
	psStep    = 1000
)

func psHeader(size int, eventType uint32, traceID types.TraceId, time uint64) []byte {
	raw := make([]byte, size)
	binary.LittleEndian.PutUint32(raw[0:4], eventType)
	binary.LittleEndian.PutUint32(raw[4:8], uint32(traceID))
	binary.LittleEndian.PutUint64(raw[8:16], time)
	binary.LittleEndian.PutUint32(raw[16:20], psPid)
	binary.LittleEndian.PutUint32(raw[20:24], psTid)
	return raw
}

func psPut32(raw []byte, off int, v int64)  { binary.LittleEndian.PutUint32(raw[off:off+4], uint32(v)) }
func psPut64(raw []byte, off int, v uint64) { binary.LittleEndian.PutUint64(raw[off:off+8], v) }

// psString writes s NUL-terminated into raw[off:off+256].
func psString(raw []byte, off int, s string) {
	n := copy(raw[off:off+256], s)
	raw[off+n] = 0
}

func (s *payloadScenario) enterTime() uint64 {
	s.now += psStep
	return s.now
}

func (s *payloadScenario) add(raw []byte) { s.raws = append(s.raws, raw) }

// ret appends the ret_event exit (kernel size 40) of the syscall entered last.
func (s *payloadScenario) ret(exitID types.TraceId, ret int64, retType uint32) {
	raw := psHeader(40, psExitRet, exitID, s.now+psLatency)
	psPut64(raw, 16, uint64(ret))
	psPut32(raw, 24, psPid)
	psPut32(raw, 28, psTid)
	psPut32(raw, 32, int64(retType))
	s.add(raw)
}

func (s *payloadScenario) openat(name string, ret int64) {
	raw := psHeader(320, psEnterOpen, types.SYS_ENTER_OPENAT, s.enterTime())
	psPut32(raw, 24, 0) // O_RDONLY
	psString(raw, 28, name)
	copy(raw[284:300], "ioworkload")
	psPut32(raw, 300, -100)
	psPut32(raw, 304, psOpenSchema)
	psPut32(raw, 308, psPathReadOK)
	s.add(raw)
	s.ret(types.SYS_EXIT_OPENAT, ret, psUnclassified)
}

// fd appends a plain single-descriptor syscall (read, write, dup, close).
func (s *payloadScenario) fd(enterID, exitID types.TraceId, fd int32, ret int64, retType uint32) {
	size := 32
	if s.wire == payloadWireWide {
		size = 48
	}
	raw := psHeader(size, psEnterFd, enterID, s.enterTime())
	psPut32(raw, 24, int64(fd))
	if s.wire == payloadWireWide {
		psPut32(raw, 44, psFdSizeSchema) // size 0, size_valid 0
	}
	s.add(raw)
	s.ret(exitID, ret, retType)
}

// fdSize appends an xattr read carrying its requested buffer size.
func (s *payloadScenario) fdSize(enterID, exitID types.TraceId, fd int32, size uint64, ret int64) {
	eventType := uint32(psEnterFdSize)
	if s.wire == payloadWireWide {
		eventType = psEnterFd
	}
	raw := psHeader(48, eventType, enterID, s.enterTime())
	psPut32(raw, 24, int64(fd))
	psPut64(raw, 32, size)
	psPut32(raw, 40, 1)
	psPut32(raw, 44, psFdSizeSchema)
	s.add(raw)
	s.ret(exitID, ret, psReadClassified)
}

// eventfd appends an eventfd-family pair. name is captured only when status
// is not PATH_READ_NULL (memfd_create, fsopen); fixup, when non-nil, is the
// name re-read at sys_exit after a failed enter-side read.
func (s *payloadScenario) eventfd(enterID, exitID types.TraceId, flags, fd int32, name string, status uint32, fixup *string, ret int64) {
	named := enterID == types.SYS_ENTER_MEMFD_CREATE || enterID == types.SYS_ENTER_FSOPEN
	var raw []byte
	switch {
	case s.wire == payloadWireWide:
		raw = psHeader(312, psEnterEventfd, enterID, s.enterTime())
	case named:
		raw = psHeader(312, psEnterEventfdName, enterID, s.enterTime())
	default:
		raw = psHeader(48, psEnterEventfd, enterID, s.enterTime())
	}
	psPut32(raw, 24, int64(flags))
	psPut64(raw, 32, uint64(^uint64(0))) // ret = -1 at enter
	psPut32(raw, 40, int64(fd))
	if len(raw) == 312 {
		psString(raw, 44, name)
		psPut32(raw, 300, int64(status))
		psPut32(raw, 304, psEventfdNameSchema)
	}
	s.add(raw)
	if fixup != nil {
		rec := make([]byte, 268)
		binary.LittleEndian.PutUint32(rec[0:4], psOpenNameFixup)
		binary.LittleEndian.PutUint32(rec[4:8], uint32(enterID))
		binary.LittleEndian.PutUint32(rec[8:12], psTid)
		psString(rec, 12, *fixup)
		s.add(rec)
	}
	exitSize := 48
	if s.wire == payloadWireWide {
		exitSize = 312
	}
	exit := psHeader(exitSize, psExitEventfd, exitID, s.now+psLatency)
	psPut32(exit, 24, int64(flags))
	psPut64(exit, 32, uint64(ret))
	psPut32(exit, 40, -1)
	if exitSize == 312 {
		psPut32(exit, 300, psPathReadNull)
		psPut32(exit, 304, psEventfdNameSchema)
	}
	s.add(exit)
}

// twoFd appends close_range or kcmp.
func (s *payloadScenario) twoFd(enterID, exitID types.TraceId, fdA, fdB int32, extra uint64, ret int64) {
	size := 48
	if s.wire == payloadWireWide {
		size = 568
	}
	raw := psHeader(size, psEnterTwoFd, enterID, s.enterTime())
	psPut32(raw, 24, int64(fdA))
	psPut32(raw, 28, int64(fdB))
	psPut64(raw, 32, extra)
	if s.wire == payloadWireWide {
		psPut32(raw, 552, psPathReadNull)
		psPut32(raw, 556, psPathReadNull)
		psPut32(raw, 560, psTwoFdSchema)
	} else {
		psPut32(raw, 40, psTwoFdSchema)
	}
	s.add(raw)
	s.ret(exitID, ret, psUnclassified)
}

// moveMount appends move_mount with both captured names.
func (s *payloadScenario) moveMount(fromFd, toFd int32, from, to string, fromStatus, toStatus uint32, flags uint64, ret int64) {
	eventType := uint32(psEnterTwoFdNames)
	if s.wire == payloadWireWide {
		eventType = psEnterTwoFd
	}
	raw := psHeader(568, eventType, types.SYS_ENTER_MOVE_MOUNT, s.enterTime())
	psPut32(raw, 24, int64(fromFd))
	psPut32(raw, 28, int64(toFd))
	psPut64(raw, 32, flags)
	psString(raw, 40, from)
	psString(raw, 296, to)
	psPut32(raw, 552, int64(fromStatus))
	psPut32(raw, 556, int64(toStatus))
	psPut32(raw, 560, psTwoFdSchema)
	s.add(raw)
	s.ret(types.SYS_EXIT_MOVE_MOUNT, ret, psUnclassified)
}

const (
	psEBADF  = 9
	psEPERM  = 1
	psERANGE = 34
	psENOENT = 2
)

// buildPayloadScenario is the fixed syscall sequence. File-descriptor state
// carries over between rows (open registers 5, close_range evicts it, ...),
// so a difference in any moved kind would also show up in later rows.
func buildPayloadScenario(wire payloadWire) [][]byte {
	s := &payloadScenario{wire: wire, now: defaulTime}
	recovered := "ior-recovered-memfd"

	s.openat("/tmp/ior-golden.txt", 5)
	s.fd(types.SYS_ENTER_READ, types.SYS_EXIT_READ, 5, 100, psReadClassified)
	s.fd(types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE, 5, 50, psWriteClassified)
	s.fdSize(types.SYS_ENTER_FGETXATTR, types.SYS_EXIT_FGETXATTR, 5, 0, 42)
	s.fdSize(types.SYS_ENTER_FGETXATTR, types.SYS_EXIT_FGETXATTR, 5, 64, 42)
	s.fdSize(types.SYS_ENTER_FLISTXATTR, types.SYS_EXIT_FLISTXATTR, 5, 0, 17)
	s.fdSize(types.SYS_ENTER_FLISTXATTR, types.SYS_EXIT_FLISTXATTR, 5, 128, -psERANGE)
	s.fdSize(types.SYS_ENTER_FGETXATTR, types.SYS_EXIT_FGETXATTR, 77, 16, 4)

	s.eventfd(types.SYS_ENTER_EVENTFD2, types.SYS_EXIT_EVENTFD2, 0x80800, -1, "", psPathReadNull, nil, 6)
	s.eventfd(types.SYS_ENTER_MEMFD_CREATE, types.SYS_EXIT_MEMFD_CREATE, 1, -1, "ior-memfd", psPathReadOK, nil, 7)
	s.eventfd(types.SYS_ENTER_MEMFD_CREATE, types.SYS_EXIT_MEMFD_CREATE, 0, -1, "", psPathReadFailed, &recovered, 8)
	s.eventfd(types.SYS_ENTER_MEMFD_CREATE, types.SYS_EXIT_MEMFD_CREATE, 0, -1, "", psPathReadFailed, nil, 9)
	s.eventfd(types.SYS_ENTER_MEMFD_CREATE, types.SYS_EXIT_MEMFD_CREATE, 0, -1, "ior-memfd-denied", psPathReadOK, nil, -psEPERM)
	s.eventfd(types.SYS_ENTER_FSOPEN, types.SYS_EXIT_FSOPEN, 1, -1, "ext4", psPathReadOK, nil, 10)
	s.eventfd(types.SYS_ENTER_FSOPEN, types.SYS_EXIT_FSOPEN, 0, -1, "", psPathReadNull, nil, -psEPERM)
	s.eventfd(types.SYS_ENTER_PIDFD_OPEN, types.SYS_EXIT_PIDFD_OPEN, 0, -1, "", psPathReadNull, nil, 11)
	s.eventfd(types.SYS_ENTER_SIGNALFD4, types.SYS_EXIT_SIGNALFD4, 0x800, 6, "", psPathReadNull, nil, 6)
	s.eventfd(types.SYS_ENTER_EPOLL_CREATE1, types.SYS_EXIT_EPOLL_CREATE1, 0x80000, -1, "", psPathReadNull, nil, 12)
	s.eventfd(types.SYS_ENTER_FSMOUNT, types.SYS_EXIT_FSMOUNT, 0, 10, "", psPathReadNull, nil, 13)

	s.twoFd(types.SYS_ENTER_KCMP, types.SYS_EXIT_KCMP, 5, 7, uint64(psPid)<<32, 0)
	s.twoFd(types.SYS_ENTER_KCMP, types.SYS_EXIT_KCMP, -1, -1, 1, 1)
	s.moveMount(-100, -100, "/mnt/ior-src", "/mnt/ior-dst", psPathReadOK, psPathReadOK, 0, 0)
	s.moveMount(13, -100, "", "/mnt/ior-dst", psPathReadOK, psPathReadOK, 0x4, 0)
	s.moveMount(-100, -100, "", "", psPathReadFailed, psPathReadNull, 0, -psENOENT)

	s.fd(types.SYS_ENTER_DUP, types.SYS_EXIT_DUP, 11, 20, psUnclassified)
	s.fd(types.SYS_ENTER_READ, types.SYS_EXIT_READ, 20, 8, psReadClassified)
	s.twoFd(types.SYS_ENTER_CLOSE_RANGE, types.SYS_EXIT_CLOSE_RANGE, 5, 7, 4, 0)
	s.fd(types.SYS_ENTER_READ, types.SYS_EXIT_READ, 5, 1, psReadClassified)
	s.twoFd(types.SYS_ENTER_CLOSE_RANGE, types.SYS_EXIT_CLOSE_RANGE, 5, 9, 0, 0)
	s.fd(types.SYS_ENTER_READ, types.SYS_EXIT_READ, 5, -psEBADF, psReadClassified)
	s.fd(types.SYS_ENTER_READ, types.SYS_EXIT_READ, 7, -psEBADF, psReadClassified)
	s.fd(types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE, 12, 3, psWriteClassified)
	s.fd(types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, 6, 0, psUnclassified)
	s.fd(types.SYS_ENTER_READ, types.SYS_EXIT_READ, 6, -psEBADF, psReadClassified)
	s.twoFd(types.SYS_ENTER_CLOSE_RANGE, types.SYS_EXIT_CLOSE_RANGE, 10, ^int32(0), 0, 0)
	s.fd(types.SYS_ENTER_READ, types.SYS_EXIT_READ, 13, -psEBADF, psReadClassified)
	return s.raws
}

// payloadSplitFilters are the filters every scenario runs under; each keeps a
// different subset, so the filter semantics of the moved kinds are compared
// too, not only their unfiltered rows.
func payloadSplitFilters() map[string]globalfilter.Filter {
	return map[string]globalfilter.Filter{
		"none":         {},
		"file golden":  {File: &globalfilter.StringFilter{Pattern: "ior-golden"}},
		"file memfd":   {File: &globalfilter.StringFilter{Pattern: "memfd"}},
		"file mnt":     {File: &globalfilter.StringFilter{Pattern: "/mnt/"}},
		"bytes >= 1":   {Bytes: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 1}},
		"fd == 5":      {FD: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 5}},
		"syscall xatt": {Syscall: &globalfilter.StringFilter{Pattern: "xattr"}},
		"errors only":  {ErrorsOnly: true},
		"comm":         {Comm: &globalfilter.StringFilter{Pattern: "ioworkload"}},
	}
}

// rowNonZeroFields renders a row like %+v does ({Name:value Name:value}, in
// declaration order) but skips zero-valued fields, so the golden does not
// depend on the set of Row fields that happen to be zero in this scenario.
func rowNonZeroFields(row streamrow.Row) string {
	v := reflect.ValueOf(row)
	parts := make([]string, 0, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%v", v.Type().Field(i).Name, v.Field(i).Interface()))
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// payloadSplitRows runs one scenario through a fresh event loop and renders
// every emitted row (CSV row, the full stream row, file flags), every
// warning, and the loop's counters.
func payloadSplitRows(t *testing.T, filter globalfilter.Filter, raws [][]byte) []string {
	t.Helper()
	el := newFilteredEventLoop(t, filter)
	var lines []string
	el.SetWarningCallback(func(message string) { lines = append(lines, "warning: "+message) })
	out := make(chan *event.Pair, 1)
	for _, raw := range raws {
		el.processRawEvent(raw, out)
		select {
		case ep := <-out:
			lines = append(lines, fmt.Sprintf("%s | flags=%v | %+v", ep.String(), ep.Flags(), rowNonZeroFields(streamrow.New(0, ep))))
			ep.Recycle()
		default:
		}
	}
	return append(lines, fmt.Sprintf("counters: tracepoints=%d mismatches=%d syscalls=%d afterFilter=%d",
		el.numTracepoints, el.numTracepointMismatches, el.numSyscalls, el.numSyscallsAfterFilter))
}

// payloadSplitGoldenText renders all filters' rows in a stable order.
func payloadSplitGoldenText(t *testing.T, wire payloadWire) string {
	t.Helper()
	filters := payloadSplitFilters()
	names := make([]string, 0, len(filters))
	for name := range filters {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "== %s\n", name)
		for _, line := range payloadSplitRows(t, filters[name], buildPayloadScenario(wire)) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func TestPayloadSplitPreservesRowsAndFilters(t *testing.T) {
	golden, err := os.ReadFile("testdata/payloadsplit.golden")
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []payloadWire{payloadWireWide, payloadWireSplit} {
		t.Run(wire.String(), func(t *testing.T) {
			got := payloadSplitGoldenText(t, wire)
			if got == string(golden) {
				return
			}
			wantLines, gotLines := strings.Split(string(golden), "\n"), strings.Split(got, "\n")
			for i := 0; i < len(wantLines) && i < len(gotLines); i++ {
				if wantLines[i] != gotLines[i] {
					t.Fatalf("first row mismatch at line %d\nwant: %s\n got: %s", i+1, wantLines[i], gotLines[i])
				}
			}
			t.Fatalf("row count differs: want %d lines, got %d", len(wantLines), len(gotLines))
		})
	}
}
