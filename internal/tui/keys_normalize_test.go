package tui

import (
	"context"
	"regexp"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// ansiSGR matches the styling escapes lipgloss puts around the input text.
var ansiSGR = regexp.MustCompile("\x1b\\[[0-9;]*m")

func newKeyTestModel() *Model {
	return NewModel(-1, func(context.Context, TraceRequest) error { return nil })
}

// newEventTypeTestModel is a model whose terminal has answered the keyboard
// enhancements query with the kitty "report event types" flag.
func newEventTypeTestModel() *Model {
	m := newKeyTestModel()
	m.kb.enhancements = tea.KeyboardEnhancementsMsg{Flags: ansi.KittyReportEventTypes}
	m.kb.enhancementsKnown = true
	return m
}

// letterPress and letterRelease mirror what bubbletea v2 decodes from the kitty
// sequences "\x1b[97u" and "\x1b[97;1:3u": KeyPressMsg{Code:97, Text:"a"} and
// KeyReleaseMsg{Code:97, Text:"a"}. The release carries the text too, which is
// what makes a replayed release indistinguishable from a real press downstream.
func letterPress(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: r, Text: string(r)}
}

func letterRelease(r rune) tea.KeyReleaseMsg {
	return tea.KeyReleaseMsg{Code: r, Text: string(r)}
}

// deliveredKeys feeds the events through the normalizer and returns the
// strings of everything that would reach the screens.
func deliveredKeys(m *Model, events ...tea.Msg) []string {
	var got []string
	for _, ev := range events {
		out, ok := m.normalizeKeyEvent(ev)
		if !ok {
			continue
		}
		if k, isKey := out.(tea.KeyPressMsg); isKey {
			got = append(got, k.String())
		}
	}
	return got
}

func TestNormalizeKeyEventOverlappingKeystrokesAreNotDuplicated(t *testing.T) {
	m := newKeyTestModel()
	// Fast typing: b is pressed before a is released.
	got := deliveredKeys(m, letterPress('a'), letterPress('b'), letterRelease('a'), letterRelease('b'))
	if strings.Join(got, "") != "ab" {
		t.Fatalf("expected exactly one delivery per key (ab), got %v", got)
	}
}

func TestNormalizeKeyEventDeepRollover(t *testing.T) {
	m := newKeyTestModel()
	got := deliveredKeys(m,
		letterPress('a'), letterPress('b'), letterPress('c'),
		letterRelease('c'), letterRelease('a'), letterRelease('b'))
	if strings.Join(got, "") != "abc" {
		t.Fatalf("expected abc, got %v", got)
	}
}

// A key held past any fixed time window (X11 auto-repeat delay is 660ms) must
// still have its release recognised as the end of the press, not replayed.
func TestNormalizeKeyEventLongHoldReleaseIsDropped(t *testing.T) {
	m := newKeyTestModel()
	got := deliveredKeys(m, letterPress(' '))
	// Auto-repeat presses are separate keystrokes and are delivered.
	repeat := tea.KeyPressMsg{Code: ' ', Text: " ", IsRepeat: true}
	got = append(got, deliveredKeys(m, repeat, repeat)...)
	// Unrelated key typed while the space is held.
	got = append(got, deliveredKeys(m, letterPress('x'), letterRelease('x'))...)
	// Release much later: no fixed time heuristic may resurrect it.
	got = append(got, deliveredKeys(m, tea.KeyReleaseMsg{Code: ' ', Text: " "})...)
	if len(got) != 4 {
		t.Fatalf("expected press + 2 repeats + x, release dropped; got %v", got)
	}
}

func TestNormalizeKeyEventRepeatedKeyPressReleasePairs(t *testing.T) {
	m := newKeyTestModel()
	got := deliveredKeys(m,
		letterPress('a'), letterRelease('a'),
		letterPress('a'), letterRelease('a'))
	if strings.Join(got, "") != "aa" {
		t.Fatalf("expected two a keystrokes, got %v", got)
	}
}

// Shift can be released before the letter, so the release then carries
// different modifiers than the press; it must still pair with that press.
func TestNormalizeKeyEventReleaseWithDifferentModifiersPairsWithPress(t *testing.T) {
	m := newKeyTestModel()
	press := tea.KeyPressMsg{Code: 'a', ShiftedCode: 'A', Mod: tea.ModShift, Text: "A"}
	got := deliveredKeys(m, press, tea.KeyReleaseMsg{Code: 'a', Text: "a"})
	if len(got) != 1 {
		t.Fatalf("expected shifted press delivered once, got %v", got)
	}
}

// A release that was never preceded by a press is the only signal a
// release-only terminal gives, so it is still delivered once.
func TestNormalizeKeyEventUnpairedReleaseStillFallsBackToPress(t *testing.T) {
	m := newKeyTestModel()
	got := deliveredKeys(m, letterRelease('a'), letterRelease('a'))
	if strings.Join(got, "") != "aa" {
		t.Fatalf("expected each unpaired release delivered as a press, got %v", got)
	}
}

// On a terminal that reports event types, an unpaired release is not a
// keystroke (e.g. the Enter that launched the program, or a key held across a
// blur), so it must not be replayed as a press.
func TestNormalizeKeyEventUnpairedReleaseDroppedWhenEventTypesReported(t *testing.T) {
	m := newEventTypeTestModel()
	enter := tea.KeyReleaseMsg{Code: tea.KeyEnter}
	if got := deliveredKeys(m, enter, letterRelease('a')); len(got) != 0 {
		t.Fatalf("expected unpaired releases dropped, got %v", got)
	}
	// Normal press/release pairs still work on such a terminal.
	if got := deliveredKeys(m, letterPress('a'), letterRelease('a')); strings.Join(got, "") != "a" {
		t.Fatalf("expected paired keystroke delivered once, got %v", got)
	}
}

// Event types being known but NOT supported (flags without the event-type bit)
// must keep the release-only fallback.
func TestNormalizeKeyEventUnpairedReleaseFallsBackWhenEventTypesUnsupported(t *testing.T) {
	m := newKeyTestModel()
	m.kb.enhancements = tea.KeyboardEnhancementsMsg{Flags: ansi.KittyDisambiguateEscapeCodes}
	m.kb.enhancementsKnown = true
	if got := deliveredKeys(m, letterRelease('a')); len(got) != 1 {
		t.Fatalf("expected release delivered as press, got %v", got)
	}
}

// A release lost while the window was unfocused must not leave the key
// "held" forever and swallow a later genuine release-only keystroke.
func TestNormalizeKeyEventBlurForgetsHeldKeys(t *testing.T) {
	m := newKeyTestModel()
	deliveredKeys(m, letterPress('a'))
	if _, ok := m.normalizeKeyEvent(tea.BlurMsg{}); !ok {
		t.Fatalf("blur must pass through the normalizer")
	}
	if got := deliveredKeys(m, letterRelease('a')); len(got) != 1 {
		t.Fatalf("expected unpaired release after blur to fall back to a press, got %v", got)
	}
}

// Same blur scenario on a terminal that reports event types: the key was
// physically pressed before the blur, so its late release must not become a
// second keystroke.
func TestNormalizeKeyEventBlurThenReleaseDroppedWhenEventTypesReported(t *testing.T) {
	m := newEventTypeTestModel()
	deliveredKeys(m, letterPress('a'))
	m.normalizeKeyEvent(tea.BlurMsg{})
	if got := deliveredKeys(m, letterRelease('a')); len(got) != 0 {
		t.Fatalf("expected release after blur dropped, got %v", got)
	}
}

func TestNormalizeKeyEventHeldSetIsBounded(t *testing.T) {
	m := newKeyTestModel()
	for r := rune('A'); r < 'A'+3*maxTrackedPressedKeys; r++ {
		deliveredKeys(m, letterPress(r))
	}
	if n := len(m.kb.pressed); n > maxTrackedPressedKeys {
		t.Fatalf("held-key set grew to %d, cap is %d", n, maxTrackedPressedKeys)
	}
}

func TestNormalizeKeyEventNonKeyMessagesPassThrough(t *testing.T) {
	m := newKeyTestModel()
	in := tea.WindowSizeMsg{Width: 10, Height: 5}
	out, ok := m.normalizeKeyEvent(in)
	if !ok || out != tea.Msg(in) {
		t.Fatalf("expected non-key message unchanged, got %v ok=%v", out, ok)
	}
}

// End to end through Update: the raw kitty byte stream from the bug report,
// decoded into messages, must type "ab" into the picker filter, not "abab".
func TestPickerFilterOverlappingKeystrokesTypedOnce(t *testing.T) {
	m := newKeyTestModel()
	m.router = newScreenRouter(ScreenPIDPicker)
	m.width, m.height = 100, 30

	events := []tea.Msg{
		letterPress('a'), letterPress('b'), letterRelease('a'), letterRelease('b'),
	}
	for _, ev := range events {
		next, _ := m.Update(ev)
		m = next.(*Model)
	}
	view := ansiSGR.ReplaceAllString(m.View().Content, "")
	if !strings.Contains(view, "Filter: ab") || strings.Contains(view, "Filter: abab") {
		t.Fatalf("expected filter to show exactly 'ab', view:\n%s", view)
	}
}
