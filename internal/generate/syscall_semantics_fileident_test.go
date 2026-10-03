package generate

import (
	"fmt"
	"regexp"
	"testing"
)

// The file identity words of fd_event, dup3_event (task d23) and ret_event
// (task 603; internal/c/fileident.c) are part of what a committed handler
// means, so the semantics oracle checks them with every other capture:
//
//   - an enter handler that reserves a record of identEnterRecords writes
//     ev->file_ident exactly once, from the record's own descriptor field and
//     after that field is set, so the identity is that of the descriptor the
//     row reports (dup3's oldfd);
//   - an exit handler that reserves a ret_event writes it exactly once: the
//     identity of the returned descriptor for the syscalls of
//     returnedFileSyscalls, and 0 for every other one (the word used to be
//     padding and the reservation is not zeroed);
//   - no other handler writes the word.

// returnedFileSyscalls is reviewed data, not derived from the generator's kind
// table: the syscalls whose successful return value is a new descriptor of
// the file the call itself opened, and whose exit is a ret_event.
var returnedFileSyscalls = map[string]struct{}{
	"creat":             {},
	"mq_open":           {},
	"open":              {},
	"open_by_handle_at": {},
	"open_tree":         {},
	"open_tree_attr":    {},
	"openat":            {},
	"openat2":           {},
}

// identEnterRecords is reviewed data: the enter records that carry the
// identity of their descriptor. dup3_event grew the word in task d23 because
// dup3 copies the old descriptor's fd table entry (dup and dup2 are
// fd_events).
var identEnterRecords = map[string]struct{}{
	"fd_event":   {},
	"dup3_event": {},
}

const (
	fileIdentEnterLine = "    ev->file_ident = ior_file_ident(ev->fd);\n"
	fileIdentRetLine   = "    ev->file_ident = ior_file_ident_of_ret(ctx->ret);\n"
	fileIdentZeroLine  = "    ev->file_ident = 0;\n"
)

var (
	fileIdentEnterRE = regexp.MustCompile(`(?m)^    ev->file_ident = ior_file_ident\(ev->fd\);$`)
	fileIdentRetRE   = regexp.MustCompile(`(?m)^    ev->file_ident = ior_file_ident_of_ret\(ctx->ret\);$`)
	fileIdentZeroRE  = regexp.MustCompile(`(?m)^    ev->file_ident = 0;$`)
	fdAssignmentRE   = regexp.MustCompile(`(?m)^    ev->fd = [^;\n]*;$`)
)

// validateFileIdentCapture checks both handlers of one syscall against the
// rules above. exitBody is empty for a noreturn syscall.
func validateFileIdentCapture(name, enterBody, exitBody string) error {
	if err := validateEnterFileIdent(name, stripCComments(enterBody)); err != nil {
		return err
	}
	if exitBody == "" {
		return nil
	}
	return validateExitFileIdent(name, stripCComments(exitBody))
}

// validateEnterFileIdent is the enter half: the capture is there exactly when
// the record is one of identEnterRecords, and follows the descriptor it
// identifies.
func validateEnterFileIdent(name, body string) error {
	handler := "sys_enter_" + name
	writes := cLValueWriteLocations(body, "ev->file_ident")
	eventStruct := eventStructRE.FindStringSubmatch(body)
	if _, carries := identEnterRecords[structOf(eventStruct)]; !carries {
		if len(writes) != 0 {
			return fmt.Errorf("%s writes ev->file_ident %d times but reserves no record with the word", handler, len(writes))
		}
		return nil
	}
	captures := fileIdentEnterRE.FindAllStringIndex(body, -1)
	if len(writes) != 1 || len(captures) != 1 {
		return fmt.Errorf("%s has %d writes/%d captures of ev->file_ident, want 1/1", handler, len(writes), len(captures))
	}
	fds := fdAssignmentRE.FindAllStringIndex(body, -1)
	if len(fds) != 1 || fds[0][1] > captures[0][0] {
		return fmt.Errorf("%s reads the file identity before its one ev->fd assignment", handler)
	}
	return validateBeforeSubmit(handler, body, captures[0][1])
}

// structOf returns the struct name an eventStructRE match captured, or ""
// for no match.
func structOf(match []string) string {
	if match == nil {
		return ""
	}
	return match[1]
}

// validateExitFileIdent is the exit half: a ret_event says which file the
// call returned, or explicitly that it returned none.
func validateExitFileIdent(name, body string) error {
	handler := "sys_exit_" + name
	writes := cLValueWriteLocations(body, "ev->file_ident")
	if eventStruct := eventStructRE.FindStringSubmatch(body); eventStruct == nil || eventStruct[1] != "ret_event" {
		if len(writes) != 0 {
			return fmt.Errorf("%s writes ev->file_ident %d times but reserves no ret_event", handler, len(writes))
		}
		return nil
	}
	want, what := fileIdentZeroRE, "0"
	if _, returnsFile := returnedFileSyscalls[name]; returnsFile {
		want, what = fileIdentRetRE, "the returned descriptor's identity"
	}
	captures := want.FindAllStringIndex(body, -1)
	if len(writes) != 1 || len(captures) != 1 {
		return fmt.Errorf("%s has %d writes of ev->file_ident, %d of them %s; want 1/1", handler, len(writes), len(captures), what)
	}
	return validateBeforeSubmit(handler, body, captures[0][1])
}

// fileIdentEnterMutations break the identity capture of an fd_event enter.
func fileIdentEnterMutations() []semanticMutation {
	enter := func(name, old, replacement string) func(*testing.T, string) string {
		return func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "enter", name, old, replacement)
		}
	}
	fdLine := "    ev->fd = (__s32)ctx->args[0];\n"
	return []semanticMutation{
		{"file identity not captured", enter("read", fileIdentEnterLine, "")},
		{"file identity of another argument", enter("read", fileIdentEnterLine,
			"    ev->file_ident = ior_file_ident((__s32)ctx->args[1]);\n")},
		{"file identity constant", enter("close", fileIdentEnterLine, fileIdentZeroLine)},
		{"file identity read before the descriptor is set", enter("write", fdLine+fileIdentEnterLine,
			fileIdentEnterLine+fdLine)},
		{"file identity overwritten", enter("read", fileIdentEnterLine, fileIdentEnterLine+fileIdentZeroLine)},
		{"file identity written after submission", enter("read", fileIdentEnterLine+"\n    bpf_ringbuf_submit(ev, 0);\n",
			"\n    bpf_ringbuf_submit(ev, 0);\n"+fileIdentEnterLine)},
		{"dup3's file identity not captured", enter("dup3", fileIdentEnterLine, "")},
		{"dup3's file identity of the new descriptor", enter("dup3", fileIdentEnterLine,
			"    ev->file_ident = ior_file_ident((__s32)ctx->args[1]);\n")},
		{"file identity written into a record without the word", enter("recvfrom",
			"    ev->schema_version = FD_SIZE_EVENT_SCHEMA_VERSION;\n",
			"    ev->schema_version = FD_SIZE_EVENT_SCHEMA_VERSION;\n"+fileIdentEnterLine)},
	}
}

// fileIdentExitMutations break the identity word of a ret_event exit.
func fileIdentExitMutations() []semanticMutation {
	exit := func(name, old, replacement string) func(*testing.T, string) string {
		return func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "exit", name, old, replacement)
		}
	}
	return []semanticMutation{
		{"opened file not identified", exit("openat", fileIdentRetLine, fileIdentZeroLine)},
		{"opened file identity dropped", exit("open_by_handle_at", fileIdentRetLine, "")},
		{"identity word left stale", exit("read", fileIdentZeroLine, "")},
		{"identity of a return value that is no descriptor", exit("read", fileIdentZeroLine, fileIdentRetLine)},
		{"identity of a duplicated descriptor's return", exit("dup", fileIdentZeroLine, fileIdentRetLine)},
		{"opened file identity written twice", exit("openat2", fileIdentRetLine, fileIdentRetLine+fileIdentRetLine)},
		{"creat's file not identified", exit("creat", fileIdentRetLine, fileIdentZeroLine)},
		{"opened file identity written after submission", exit("mq_open", fileIdentRetLine+"\n    bpf_ringbuf_submit(ev, 0);\n",
			"\n    bpf_ringbuf_submit(ev, 0);\n"+fileIdentRetLine)},
	}
}

// TestSyscallSemanticsOracleRejectsFileIdentMutations keeps the oracle honest
// about the file identity words (task 603): each mutation of the committed
// handlers must fail parsing or the comparison with the reviewed rows.
func TestSyscallSemanticsOracleRejectsFileIdentMutations(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	for _, mutation := range append(fileIdentEnterMutations(), fileIdentExitMutations()...) {
		t.Run(mutation.name, func(t *testing.T) {
			actual, err := parseGeneratedSyscallSemantics(mutation.mutate(t, source))
			if err == nil && len(compareSyscallSemantics(syscallSemanticExpectations, actual)) == 0 {
				t.Fatalf("%s mutation did not fail parsing or comparison", mutation.name)
			}
		})
	}
}

// TestReturnedFileSyscallsAreCommittedOpenHandlers pins the reviewed list
// against the artifact from the other side: every listed syscall has a
// committed exit handler (a stale name would silently check nothing).
func TestReturnedFileSyscallsAreCommittedOpenHandlers(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	for name := range returnedFileSyscalls {
		re := regexp.MustCompile(`(?m)^int handle_sys_exit_` + regexp.QuoteMeta(name) + `\(`)
		if !re.MatchString(source) {
			t.Errorf("returnedFileSyscalls lists %q, which has no committed exit handler", name)
		}
	}
}
