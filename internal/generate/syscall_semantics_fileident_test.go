package generate

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
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
//   - no other handler writes the word;
//   - the enter handlers of namedFdSyscalls (close; task xz2) first try to
//     send the enter as an fd_name_event: one call of ior_emit_fd_name_enter
//     for the syscall's own trace ID and the very argument ev->fd is set
//     from, ahead of the reserve, whose "sent" answer ends the handler. The
//     call also walks to the identity, so these handlers store its result
//     (the local file_ident) instead of walking again. No other handler
//     makes that call.

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

// namedFdSyscalls is reviewed data: the fd_event syscalls whose enter
// reports the last path component of the file behind the descriptor. Only a
// close qualifies: userspace cannot ask procfs about a descriptor that is
// gone when its row is processed.
var namedFdSyscalls = map[string]struct{}{
	"close": {},
}

const (
	fileIdentLocalLine = "    ev->file_ident = file_ident;\n"
	fileIdentEnterLine = "    ev->file_ident = ior_file_ident(ev->fd);\n"
	fileIdentRetLine   = "    ev->file_ident = ior_file_ident_of_ret(ctx->ret);\n"
	fileIdentZeroLine  = "    ev->file_ident = 0;\n"
)

var (
	fileIdentEnterRE = regexp.MustCompile(`(?m)^    ev->file_ident = ior_file_ident\(ev->fd\);$`)
	fileIdentRetRE   = regexp.MustCompile(`(?m)^    ev->file_ident = ior_file_ident_of_ret\(ctx->ret\);$`)
	fileIdentZeroRE  = regexp.MustCompile(`(?m)^    ev->file_ident = 0;$`)
	fileIdentLocalRE = regexp.MustCompile(`(?m)^    ev->file_ident = file_ident;$`)
	fdAssignmentRE   = regexp.MustCompile(`(?m)^    ev->fd = ([^;\n]*);$`)
	// fdNameEnterRE matches the whole attempt, declaration and early return
	// included: trace ID in group 1, descriptor expression in group 2.
	fdNameEnterRE = regexp.MustCompile(`(?m)^    __u32 file_ident;\n` +
		`    if \(ior_emit_fd_name_enter\(pid, tid, (SYS_ENTER_[A-Z0-9_]+), now, ([^;\n]*), &file_ident\)\)\n` +
		`        return 0;$`)
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
	_, named := namedFdSyscalls[name]
	if !named && strings.Contains(body, "ior_emit_fd_name_enter") {
		return fmt.Errorf("%s reports a file name, which only %v may", handler, namedFdSyscalls)
	}
	if _, carries := identEnterRecords[structOf(eventStruct)]; !carries {
		if len(writes) != 0 || named {
			return fmt.Errorf("%s writes ev->file_ident %d times but reserves no record with the word", handler, len(writes))
		}
		return nil
	}
	capture := fileIdentEnterRE
	if named {
		capture = fileIdentLocalRE
	}
	captures := capture.FindAllStringIndex(body, -1)
	if len(writes) != 1 || len(captures) != 1 {
		return fmt.Errorf("%s has %d writes/%d captures of ev->file_ident, want 1/1", handler, len(writes), len(captures))
	}
	fds := fdAssignmentRE.FindAllStringSubmatchIndex(body, -1)
	if len(fds) != 1 || fds[0][1] > captures[0][0] {
		return fmt.Errorf("%s reads the file identity before its one ev->fd assignment", handler)
	}
	if named {
		if err := validateFdNameEnter(name, body, body[fds[0][2]:fds[0][3]]); err != nil {
			return err
		}
	}
	return validateBeforeSubmit(handler, body, captures[0][1])
}

// validateFdNameEnter checks the fd_name_event attempt of a namedFdSyscalls
// enter handler: exactly one call, with its declaration and early return, for
// this syscall's trace ID and the argument fdExpr the plain record reports,
// after the enter hook and ahead of the handler's own reserve.
func validateFdNameEnter(name, body, fdExpr string) error {
	handler := "sys_enter_" + name
	attempts := fdNameEnterRE.FindAllStringSubmatchIndex(body, -1)
	if len(attempts) != 1 || strings.Count(body, "ior_emit_fd_name_enter") != 1 {
		return fmt.Errorf("%s has %d complete fd-name attempts, want 1", handler, len(attempts))
	}
	at := attempts[0]
	if traceID := body[at[2]:at[3]]; traceID != "SYS_ENTER_"+strings.ToUpper(name) {
		return fmt.Errorf("%s reports its file name under trace ID %s", handler, traceID)
	}
	if got := body[at[4]:at[5]]; got != fdExpr {
		return fmt.Errorf("%s names the file of %q but reports descriptor %q", handler, got, fdExpr)
	}
	hook := strings.Index(body, "ior_on_syscall_enter")
	reserve := strings.Index(body, "bpf_ringbuf_reserve")
	if hook < 0 || hook > at[0] || reserve < at[1] {
		return fmt.Errorf("%s does not try the fd-name record between its enter hook and its reserve", handler)
	}
	return nil
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
		{"file identity constant", enter("fsync", fileIdentEnterLine, fileIdentZeroLine)},
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

// fdNameEnterMutations break the fd_name_event attempt of close's enter
// (task xz2), or add one where it does not belong.
func fdNameEnterMutations() []semanticMutation {
	enter := func(name, old, replacement string) func(*testing.T, string) string {
		return func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "enter", name, old, replacement)
		}
	}
	const (
		decl    = "    __u32 file_ident;\n"
		attempt = "    if (ior_emit_fd_name_enter(pid, tid, SYS_ENTER_CLOSE, now, (__s32)ctx->args[0], &file_ident))\n"
		leave   = "        return 0;\n\n"
		reserve = "    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);\n"
	)
	return []semanticMutation{
		{"closed file's name not reported", enter("close", decl+attempt+leave, decl)},
		{"closed file's name of another argument", enter("close", "now, (__s32)ctx->args[0], &file_ident", "now, (__s32)ctx->args[1], &file_ident")},
		{"closed file's name under another trace ID", enter("close", "(pid, tid, SYS_ENTER_CLOSE, now, ", "(pid, tid, SYS_ENTER_READ, now, ")},
		{"plain record sent behind the named one", enter("close", attempt+leave, "    ior_emit_fd_name_enter(pid, tid, SYS_ENTER_CLOSE, now, (__s32)ctx->args[0], &file_ident);\n\n")},
		{"close's identity walked a second time", enter("close", fileIdentLocalLine, fileIdentEnterLine)},
		{"close's identity dropped", enter("close", fileIdentLocalLine, fileIdentZeroLine)},
		{"closed file's name reported twice", enter("close", attempt+leave, attempt+leave+attempt+leave)},
		{"file name reported by a hot call", enter("read", "    struct fd_event *ev = bpf_ringbuf_reserve(",
			"    __u32 file_ident;\n    if (ior_emit_fd_name_enter(pid, tid, SYS_ENTER_READ, now, (__s32)ctx->args[0], &file_ident))\n"+
				"        return 0;\n\n    struct fd_event *ev = bpf_ringbuf_reserve(")},
		{"closed file's name tried after the reserve", enter("close", decl+attempt+leave+reserve, reserve+decl+attempt+leave)},
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
// about the file identity words (task 603) and the name close reports with
// its identity (task xz2): each mutation of the committed handlers must fail
// parsing or the comparison with the reviewed rows.
func TestSyscallSemanticsOracleRejectsFileIdentMutations(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	mutations := slices.Concat(fileIdentEnterMutations(), fileIdentExitMutations(), fdNameEnterMutations())
	for _, mutation := range mutations {
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
