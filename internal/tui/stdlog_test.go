package tui

import (
	"bytes"
	"context"
	"log"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// redirectStdLog points the process-wide standard logger at a buffer for the
// test and restores the previous writer afterwards. Tests using it must not
// run in parallel: the standard logger is global.
func redirectStdLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buf
}

// TestRunProgramDiscardsStdLogWhileTheProgramRuns pins that nothing written
// through the standard logger while Bubble Tea owns the terminal reaches it,
// and that the logger is restored once the program has exited.
func TestRunProgramDiscardsStdLogWhileTheProgramRuns(t *testing.T) {
	buf := redirectStdLog(t)
	original := runTeaProgram
	t.Cleanup(func() { runTeaProgram = original })

	runTeaProgram = func(m *Model) (tea.Model, error) {
		log.Print("written over the dashboard")
		return m, nil
	}
	if err := runProgram(NewModel(-1, func(context.Context, TraceRequest) error { return nil })); err != nil {
		t.Fatalf("runProgram() = %v", err)
	}

	if buf.Len() != 0 {
		t.Fatalf("std log reached the terminal during the program: %q", buf.String())
	}
	if log.Writer() != buf {
		t.Fatal("runProgram did not restore the std log output after the program exited")
	}
	log.Print("after exit")
	if buf.Len() == 0 {
		t.Fatal("std log stayed discarded after the program exited")
	}
}

// TestKeyboardEnhancementsMsgDoesNotLog is the Update-side half: handling the
// enhancement report runs inside the Bubble Tea loop and must stay silent even
// when the std log is not discarded (teatest and other in-process runs).
func TestKeyboardEnhancementsMsgDoesNotLog(t *testing.T) {
	buf := redirectStdLog(t)
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })

	m.Update(tea.KeyboardEnhancementsMsg{Flags: 1})

	if buf.Len() != 0 {
		t.Fatalf("keyboard enhancements handling logged: %q", buf.String())
	}
}
