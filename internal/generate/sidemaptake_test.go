package generate

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// sideMapOpRE matches every lookup or delete of the per-tid side maps that
// carry enter-side state (user pointers, flags) across to the exit handler.
var sideMapOpRE = regexp.MustCompile(`bpf_map_(lookup|delete)_elem\(&(pipe_ctx_map|socketpair_ctx_map|eventfd_flags_map), &tid\)`)

// sideMapKindMaps lists, per kind with an exit side-map take, the map that
// take must consume. It is written out by hand rather than derived from
// exitSideMapTakers so a kind silently dropped from that table fails here.
var sideMapKindMaps = map[TracepointKind]string{
	KindSocketpair:   "socketpair_ctx_map",
	KindPipe:         "pipe_ctx_map",
	KindEventfd:      "eventfd_flags_map",
	KindNamedEventfd: "eventfd_flags_map",
	KindPidfd:        "eventfd_flags_map",
}

// exitTracepoint builds the minimal exit tracepoint of the given kind; a
// sys_exit_* format only ever carries the syscall number and ret.
func exitTracepoint(name string, kind TracepointKind) GeneratedTracepoint {
	return GeneratedTracepoint{
		Format: &Format{
			Name:           name,
			ExternalFields: []Field{{Name: "__syscall_nr"}, {Name: "ret"}},
		},
		Classification: ClassificationResult{Kind: kind},
	}
}

// checkSideMapTakeBeforeReserve returns an error unless every side-map lookup
// and delete in handler runs after the exit hook and before the ring-buffer
// reserve, so a full ring buffer can no longer strand the entry (task lo2).
func checkSideMapTakeBeforeReserve(name, handler string) error {
	reserveAt := strings.Index(handler, "bpf_ringbuf_reserve(")
	hookLoc := exitHookCall.FindStringIndex(handler)
	if reserveAt < 0 || hookLoc == nil {
		return fmt.Errorf("%s: missing exit hook or ring-buffer reserve", name)
	}
	hookAt := hookLoc[0]
	for _, loc := range sideMapOpRE.FindAllStringIndex(handler, -1) {
		if loc[0] < hookAt || loc[0] > reserveAt {
			return fmt.Errorf("%s: %s is not between ior_on_syscall_exit and bpf_ringbuf_reserve",
				name, handler[loc[0]:loc[1]])
		}
	}
	return nil
}

// TestSideMapTakePrecedesReserve renders the exit handler of every side-map
// kind and pins that exactly one lookup and one delete of the kind's map run
// before the reserve, while the event fields are still assigned after it.
func TestSideMapTakePrecedesReserve(t *testing.T) {
	for kind, mapName := range sideMapKindMaps {
		t.Run(kind.MetadataName(), func(t *testing.T) {
			handler := generateBPFHandler(exitTracepoint("sys_exit_probe", kind))
			if err := checkSideMapTakeBeforeReserve("sys_exit_probe", handler); err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"lookup", "delete"} {
				call := fmt.Sprintf("bpf_map_%s_elem(&%s, &tid)", op, mapName)
				if got := strings.Count(handler, call); got != 1 {
					t.Fatalf("%d copies of %s, want 1:\n%s", got, call, handler)
				}
			}
			if strings.Index(handler, "ev->ret = ctx->ret;") < strings.Index(handler, "bpf_ringbuf_reserve(") {
				t.Fatalf("event fields must still be written after the reserve:\n%s", handler)
			}
		})
	}
}

// TestSideMapTakeOnlyOnSideMapExits is the negative side: enter handlers and
// exits of kinds without a side map render no take at all.
func TestSideMapTakeOnlyOnSideMapExits(t *testing.T) {
	for kind := range sideMapKindMaps {
		enter := exitTracepoint("sys_enter_probe", kind)
		if got := generateSideMapTake(enter, true); got != "" {
			t.Fatalf("%s enter renders a side-map take %q, want none", kind.MetadataName(), got)
		}
	}
	for _, kind := range []TracepointKind{KindNull, KindRet, KindFd, KindAccept, KindSocket} {
		if got := generateSideMapTake(exitTracepoint("sys_exit_probe", kind), false); got != "" {
			t.Fatalf("%s exit renders a side-map take %q, want none", kind.MetadataName(), got)
		}
	}
}

// TestCommittedSideMapTakesPrecedeReserve applies the same ordering rule to
// every handler of the committed internal/c/generated_tracepoints.c, so a
// stale artifact (generated before the fix) fails even though the diff gate
// only compares the tracepoint set.
func TestCommittedSideMapTakesPrecedeReserve(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	takes := 0
	for name, handler := range splitGeneratedHandlers(t, source) {
		ops := sideMapOpRE.FindAllString(handler, -1)
		if strings.HasPrefix(name, "sys_enter_") {
			if len(ops) != 0 {
				t.Errorf("%s: enter handler reads or deletes a side map: %v", name, ops)
			}
			continue
		}
		if len(ops) == 0 {
			continue
		}
		takes++
		if err := checkSideMapTakeBeforeReserve(name, handler); err != nil {
			t.Error(err)
		}
	}
	if takes == 0 {
		t.Fatal("no exit handler takes a side-map entry; the scan matched nothing")
	}
}
