package generate

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Task 79: the generated handlers no longer memset a string field before
// reading into it. Ring-buffer memory is handed out unzeroed, and userspace
// reads a string only up to its first NUL, so every string field must end up
// terminated on every path to bpf_ringbuf_submit - and nothing more:
//
//   - a successful bpf_probe_read_user_str terminates the string itself;
//   - a NULL-pointer branch and a failed read write ev->FIELD[0] = 0;
//   - a string the syscall does not capture is terminated unconditionally;
//   - comm is written in full by bpf_get_current_comm.
//
// The checker below pins that contract for one handler body; the tests run
// it over fresh generator output and over every committed handler.

// stringFieldsByStruct lists the string fields of every event struct that a
// generated handler emits (internal/c/types.h), except comm, which is checked
// through structsWithComm. TestStringFieldListsMatchTypesH derives the same
// sets from types.h and fails when the two disagree.
var stringFieldsByStruct = map[string][]string{
	"open_event":         {"filename"},
	"exec_event":         {"filename"},
	"path_event":         {"pathname"},
	"fd_path_event":      {"pathname"},
	"name_event":         {"oldname", "newname"},
	"two_fd_names_event": {"oldname", "newname"},
	"eventfd_name_event": {"filename"},
}

// structsWithComm are the event structs that carry the task's comm.
var structsWithComm = map[string]bool{"open_event": true, "exec_event": true}

// handWrittenStringStructs are the structs with a string field that only
// hand-written BPF code fills; TestHandWrittenBPFStringCapturesNeedNoMemset
// covers them, and fdname_harness_test.go the name of fd_name_event.
var handWrittenStringStructs = map[string]bool{"open_name_fixup_event": true, "process_exec_event": true, "task_newtask_event": true, "task_rename_event": true, "fd_name_event": true}

var handlerStructRE = regexp.MustCompile(`(?m)^/// \S+ is a struct (\w+)`)

const commCaptureLine = "    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));\n"

// commCaptureRE matches commCaptureLine at handler level (four-space indent,
// i.e. not inside any branch).
var commCaptureRE = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(commCaptureLine))

// checkHandlerStringFields verifies the string contract of one generated
// handler body (as returned by splitGeneratedHandlers) and returns the first
// violation, or nil.
func checkHandlerStringFields(name, body string) error {
	if strings.Contains(body, "__builtin_memset") {
		return fmt.Errorf("%s: memsets a buffer; string fields are terminated instead", name)
	}
	m := handlerStructRE.FindStringSubmatch(body)
	if m == nil {
		return fmt.Errorf("%s: no struct comment", name)
	}
	submitAt := strings.Index(body, "bpf_ringbuf_submit(ev, 0);")
	for _, field := range stringFieldsByStruct[m[1]] {
		if err := checkStringFieldTerminated(name, body, field, submitAt); err != nil {
			return err
		}
	}
	if structsWithComm[m[1]] {
		captures := commCaptureRE.FindAllStringIndex(body, -1)
		if len(captures) != 1 {
			return fmt.Errorf("%s: %d unconditional comm captures, want 1", name, len(captures))
		}
		if got := strings.Count(body, "ev->comm"); got != 2 {
			return fmt.Errorf("%s: comm is touched outside bpf_get_current_comm", name)
		}
		if submitAt < 0 || captures[0][0] > submitAt {
			return fmt.Errorf("%s: comm is captured after the submit", name)
		}
	}
	return nil
}

func checkStringFieldTerminated(name, body, field string, submitAt int) error {
	quoted := regexp.QuoteMeta(field)
	terminators := regexp.MustCompile(`(?m)^[ ]+ev->`+quoted+`\[0\] = 0;\n`).FindAllStringIndex(body, -1)
	if writes := regexp.MustCompile(`ev->`+quoted+`\[`).FindAllStringIndex(body, -1); len(writes) != len(terminators) {
		return fmt.Errorf("%s: %s is written %d times other than by its terminator", name, field, len(writes)-len(terminators))
	}
	for _, loc := range terminators {
		if submitAt < 0 || loc[0] > submitAt {
			return fmt.Errorf("%s: %s is terminated after the submit", name, field)
		}
	}
	probeCalls := strings.Count(body, "bpf_probe_read_user_str(ev->"+field+",")
	probes := regexp.MustCompile(`(?m)^ +if \(bpf_probe_read_user_str\(ev->`+quoted+`, sizeof\(ev->`+quoted+
		`\), \(void ?\*\)ctx->args\[(\d+)\]\) < 0\)( \{)?\n`).FindAllStringSubmatchIndex(body, -1)
	if probeCalls != len(probes) {
		return fmt.Errorf("%s: %s is read without checking the result", name, field)
	}
	switch len(probes) {
	case 0:
		// Not captured: one unconditional terminator at handler level.
		if len(terminators) != 1 || !strings.HasPrefix(body[terminators[0][0]:], "    ev->"+field) ||
			strings.HasPrefix(body[terminators[0][0]:], "     ") {
			return fmt.Errorf("%s: uncaptured %s needs exactly one unconditional terminator, has %d", name, field, len(terminators))
		}
		return nil
	case 1:
	default:
		return fmt.Errorf("%s: %s is read %d times", name, field, len(probes))
	}
	probe := probes[0]
	want := 0
	// The failed read must write the terminator.
	if probe[4] >= 0 {
		end, ok := matchingBrace(body, probe[5]-1)
		if !ok || countWithin(terminators, probe[1], end) != 1 {
			return fmt.Errorf("%s: the failed read of %s does not terminate it", name, field)
		}
	} else if !strings.HasPrefix(strings.TrimLeft(body[probe[1]:], " "), "ev->"+field+"[0] = 0;\n") {
		return fmt.Errorf("%s: the failed read of %s does not terminate it", name, field)
	}
	want++
	// A NULL-pointer branch, where there is one, must write it too.
	arg := body[probe[2]:probe[3]]
	if guard := strings.Index(body, "    if (ctx->args["+arg+"] == 0) {\n"); guard >= 0 && guard < probe[0] {
		open := guard + strings.Index(body[guard:], "{")
		end, ok := matchingBrace(body, open)
		if !ok || countWithin(terminators, open, end) != 1 {
			return fmt.Errorf("%s: the NULL branch of %s does not terminate it", name, field)
		}
		want++
	}
	// Nothing else: in particular no terminator on the success path.
	if len(terminators) != want {
		return fmt.Errorf("%s: %s has %d terminators, want %d", name, field, len(terminators), want)
	}
	return nil
}

// stringKindFixtures covers every event struct with a string field, including
// both shapes of the eventfd and two-fd kinds (with and without a captured
// name), exec with and without a dirfd, and the recovering open kinds.
func stringKindFixtures(t *testing.T) string {
	t.Helper()
	exitUnlink := strings.Replace(strings.Replace(FormatExitRead, "sys_exit_read", "sys_exit_unlink", 1), "ID: 843", "ID: 883", 1)
	input := strings.Join([]string{
		FormatOpenat, FormatExitOpenat,
		FormatOpen, FormatExitOpen,
		FormatExecve, FormatExitExecve,
		FormatExecveat, FormatExitExecveat,
		FormatRename, FormatExitRename,
		FormatUnlink, exitUnlink,
		FormatEventfd2, FormatExitEventfd2,
		FormatMoveMount, FormatExitMoveMount,
		syntheticEnter("close_range", 9322), syntheticExit("close_range", 9321),
		FormatRead, FormatExitRead,
	}, "\n") + "\n"
	formats := mustParseAll(t, input)
	formats = append(formats, mqFormats("mq_open", 9300)...)
	formats = append(formats, namedEventfdFormats("memfd_create", "uname", 9400)...)
	formats = append(formats, notificationFormats()...)
	return GenerateTracepointsC(formats)
}

func TestGeneratedStringFieldsAreTerminatedNotMemset(t *testing.T) {
	handlers := splitGeneratedHandlers(t, stringKindFixtures(t))
	covered := map[string]int{}
	for name, body := range handlers {
		if err := checkHandlerStringFields(name, body); err != nil {
			t.Errorf("%v\n%s", err, body)
		}
		if m := handlerStructRE.FindStringSubmatch(body); m != nil {
			covered[m[1]]++
		}
	}
	for structName := range stringFieldsByStruct {
		if covered[structName] == 0 {
			t.Errorf("fixture has no handler emitting %s", structName)
		}
	}
}

func TestGeneratedArtifactTerminatesStringFields(t *testing.T) {
	artifact, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	handlers := splitGeneratedHandlers(t, artifact)
	withStrings := 0
	for name, body := range handlers {
		if err := checkHandlerStringFields(name, body); err != nil {
			t.Error(err)
		}
		if m := handlerStructRE.FindStringSubmatch(body); m != nil && len(stringFieldsByStruct[m[1]]) > 0 {
			withStrings++
		}
	}
	// Only the named variants still reserve a string field.
	if withStrings != 76 {
		t.Errorf("%d committed handlers emit a struct with a string field, want 76", withStrings)
	}
	if got := strings.Count(artifact, "__builtin_memset"); got != 0 {
		t.Errorf("generated_tracepoints.c has %d memsets, want 0", got)
	}
}

// TestStringFieldListsMatchTypesH keeps the hand-maintained field lists above
// in step with internal/c/types.h: every char[] field of every struct must be
// covered by exactly one of them, and nothing may be listed that types.h does
// not have.
func TestStringFieldListsMatchTypesH(t *testing.T) {
	typesH, err := readCSource("types.h")
	if err != nil {
		t.Fatalf("read types.h: %v", err)
	}
	structs, _, err := ParseCTypesInput(strings.NewReader(typesH))
	if err != nil {
		t.Fatalf("parse types.h: %v", err)
	}
	fields := map[string][]string{} // generated-handler string fields, comm excluded
	withComm := map[string]bool{}
	handWritten := map[string]bool{}
	for _, s := range structs {
		for _, m := range s.Members {
			if m.TypeName != "char" || m.ArraySize == "" {
				continue
			}
			switch {
			case handWrittenStringStructs[s.Name]:
				handWritten[s.Name] = true
			case m.FieldName == "comm":
				withComm[s.Name] = true
			default:
				fields[s.Name] = append(fields[s.Name], m.FieldName)
			}
		}
	}
	if len(fields) == 0 {
		t.Fatal("types.h has no string fields; the parser or the path is broken")
	}
	if !reflect.DeepEqual(fields, stringFieldsByStruct) {
		t.Errorf("stringFieldsByStruct = %v, types.h has %v", stringFieldsByStruct, fields)
	}
	if !reflect.DeepEqual(withComm, structsWithComm) {
		t.Errorf("structsWithComm = %v, types.h has %v", structsWithComm, withComm)
	}
	if !reflect.DeepEqual(handWritten, handWrittenStringStructs) {
		t.Errorf("handWrittenStringStructs = %v, types.h has %v", handWrittenStringStructs, handWritten)
	}
}

// TestHandWrittenBPFStringCapturesNeedNoMemset pins the same rule for the
// hand-written string captures: the open-name fixup record is submitted only
// after a successful (hence terminated) read, sched_process_exec's comm is
// written in full by bpf_get_current_comm, and so is task_newtask's (the creator's
// context holds the name the child inherits). task_newtask deliberately does not
// copy the tracepoint's own comm field: it is not guaranteed to be zero-padded
// on older kernels (strlcpy leaves stale bytes after the NUL), and copying it out
// of the context needs pointer arithmetic old verifiers reject. Userspace cuts
// at the first NUL (types.StringValue), so either would be safe to read, but only
// the helper needs no assumption at all. task_rename cannot use that helper (the
// tracepoint fires before the kernel stores the new name, and the renamed task
// need not be the current one), so it reads the name from the raw tracepoint's
// comm argument with bpf_probe_read_kernel_str and discards the record when that
// read fails.
func TestHandWrittenBPFStringCapturesNeedNoMemset(t *testing.T) {
	filterC, err := readCSource("filter.c")
	if err != nil {
		t.Fatalf("read filter.c: %v", err)
	}
	fixup := regexp.MustCompile(`(?s)static __always_inline void ior_emit_name_fixup\(.*?\n\}\n`).FindString(filterC)
	if fixup == "" {
		t.Fatal("ior_emit_name_fixup not found in filter.c")
	}
	if strings.Contains(fixup, "__builtin_memset") {
		t.Error("ior_emit_name_fixup memsets its filename")
	}
	failedReadDiscards := "    if (bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)filename_ptr) < 0) {\n" +
		"        bpf_ringbuf_discard(ev, 0);\n        return;\n    }\n"
	if !strings.Contains(fixup, failedReadDiscards) {
		t.Error("ior_emit_name_fixup must discard a record whose read failed; only a successful read is terminated")
	}
	if !strings.Contains(filterC, "// String fields in ring-buffer records.") {
		t.Error("filter.c lost the documented decision about stale bytes after the terminator")
	}

	execC, err := readCSource("exec.c")
	if err != nil {
		t.Fatalf("read exec.c: %v", err)
	}
	handler := regexp.MustCompile(`(?s)int handle_sched_process_exec\(.*?\n\}\n`).FindString(execC)
	if handler == "" {
		t.Fatal("handle_sched_process_exec not found in exec.c")
	}
	if strings.Contains(handler, "__builtin_memset") {
		t.Error("handle_sched_process_exec memsets comm")
	}
	if !strings.Contains(handler, commCaptureLine) {
		t.Error("handle_sched_process_exec must capture comm unconditionally")
	}

	newtask := regexp.MustCompile(`(?s)int handle_task_newtask\(.*?\n\}\n`).FindString(execC)
	if newtask == "" {
		t.Fatal("handle_task_newtask not found in exec.c")
	}
	if strings.Contains(newtask, "__builtin_memset") {
		t.Error("handle_task_newtask memsets comm")
	}
	if !strings.Contains(newtask, commCaptureLine) {
		t.Error("handle_task_newtask must capture comm with bpf_get_current_comm unconditionally")
	}
	// Copying ctx->comm compiles to ctx pointer arithmetic that RHEL/Rocky 8/9
	// verifiers reject (see the comment in exec.c); the buildgate objdump test
	// checks the compiled object, this one catches the source pattern early.
	if strings.Contains(newtask, "ctx->comm") {
		t.Error("handle_task_newtask must not read the tracepoint's comm array out of the context")
	}

	// task_rename's name is copied out of the kernel buffer the raw tracepoint
	// hands over. The helper terminates it on success and the record is
	// discarded on failure, so an unterminated string never reaches userspace.
	rename := regexp.MustCompile(`(?s)int handle_task_rename\(.*?\n\}\n`).FindString(execC)
	if rename == "" {
		t.Fatal("handle_task_rename not found in exec.c")
	}
	if strings.Contains(rename, "__builtin_memset") {
		t.Error("handle_task_rename memsets comm")
	}
	const renameCommRead = "    if (bpf_probe_read_kernel_str(ev->comm, sizeof(ev->comm), args->comm) < 0) {\n" +
		"        bpf_ringbuf_discard(ev, 0);\n        ior_count_ringbuf_drop();\n        return 0;\n    }\n"
	if !strings.Contains(rename, renameCommRead) {
		t.Error("handle_task_rename must discard a record whose comm read failed and count it as a drop (task mz2); only a successful read is terminated")
	}
	if strings.Contains(rename, "ctx->newcomm") {
		t.Error("handle_task_rename must not read the classic tracepoint's newcomm array out of the context")
	}
}

// TestCheckHandlerStringFieldsRejectsViolations keeps the checker honest. The
// first case is the pre-task-79 shape; the others are the ways a string could
// reach userspace unterminated, or a capture could be erased.
func TestCheckHandlerStringFieldsRejectsViolations(t *testing.T) {
	handlers := splitGeneratedHandlers(t, stringKindFixtures(t))
	for name, body := range handlers {
		if err := checkHandlerStringFields(name, body); err != nil {
			t.Fatalf("fixture is not valid to begin with: %v", err)
		}
	}
	mutate := func(handler, old, replacement string) string {
		body := handlers[handler]
		if body == "" {
			t.Fatalf("fixture has no %s", handler)
		}
		return strings.Replace(body, old, replacement, 1)
	}
	const (
		unlinkNull   = "        ev->pathname[0] = 0;\n        ev->pathname_status = PATH_READ_NULL;\n"
		unlinkFailed = "            ev->pathname_status = PATH_READ_FAILED;\n            ev->pathname[0] = 0;\n"
		execFailed   = "            ev->filename_status = PATH_READ_FAILED;\n            ev->filename[0] = 0;\n"
		// The failed branch of a recovering kind ends with the pointer stash.
		unlinkStash = "            ior_stash_pending_filename(tid, ctx->args[0]);\n"
	)
	cases := []struct {
		name, handler, old, replacement string
	}{
		{"pre-task-79 full-buffer memset", "sys_enter_unlink",
			"    if (ctx->args[0] == 0) {\n",
			"    __builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));\n    if (ctx->args[0] == 0) {\n"},
		{"NULL branch unterminated", "sys_enter_unlink", unlinkNull, "        ev->pathname_status = PATH_READ_NULL;\n"},
		{"failed read unterminated", "sys_enter_unlink", unlinkFailed, "            ev->pathname_status = PATH_READ_FAILED;\n"},
		{"terminator on the success path", "sys_enter_unlink",
			unlinkFailed + unlinkStash + "        }\n",
			"            ev->pathname_status = PATH_READ_FAILED;\n" + unlinkStash + "        }\n        ev->pathname[0] = 0;\n"},
		{"terminator at the wrong index", "sys_enter_unlink", unlinkNull,
			"        ev->pathname[1] = 0;\n        ev->pathname_status = PATH_READ_NULL;\n"},
		{"probe result unchecked", "sys_enter_unlink", "        if (bpf_probe_read_user_str(", "        (void)(bpf_probe_read_user_str("},
		{"name side unterminated", "sys_enter_rename",
			"            ev->newname_status = PATH_READ_FAILED;\n            ev->newname[0] = 0;\n",
			"            ev->newname_status = PATH_READ_FAILED;\n"},
		{"open failed read unterminated", "sys_enter_openat",
			"            ev->filename_status = PATH_READ_FAILED;\n            ev->filename[0] = 0;\n",
			"            ev->filename_status = PATH_READ_FAILED;\n"},
		{"open comm memset", "sys_enter_openat", commCaptureLine,
			commCaptureLine + "    __builtin_memset(&(ev->comm), 0, sizeof(ev->comm));\n"},
		{"open comm captured conditionally", "sys_enter_openat", commCaptureLine,
			"    if (flags)\n        bpf_get_current_comm(&ev->comm, sizeof(ev->comm));\n"},
		{"exec failed read unterminated", "sys_enter_execve", execFailed, "            ev->filename_status = PATH_READ_FAILED;\n"},
		{"exec terminator erases every read", "sys_enter_execve",
			"            ev->filename[0] = 0;\n        }\n    }\n",
			"        }\n    }\n    ev->filename[0] = 0;\n"},
		{"named eventfd unterminated", "sys_enter_memfd_create", "            ev->filename[0] = 0;\n", ""},
		{"two-fd names unterminated", "sys_enter_move_mount", "            ev->newname[0] = 0;\n", ""},
		{"notification path unterminated", "sys_enter_inotify_add_watch",
			"            ev->pathname_status = PATH_READ_FAILED;\n            ev->pathname[0] = 0;\n",
			"            ev->pathname_status = PATH_READ_FAILED;\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := mutate(tc.handler, tc.old, tc.replacement)
			if body == handlers[tc.handler] {
				t.Fatal("mutation did not apply; the fixture shape changed")
			}
			if err := checkHandlerStringFields(tc.handler, body); err == nil {
				t.Errorf("checker accepted:\n%s", body)
			}
		})
	}
}
