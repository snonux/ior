package dashboard

import (
	"strings"
	"testing"

	common "ior/internal/tui/common"
)

// noticeModel builds a dashboard sized to width x height with a pending filter
// refusal notice, i.e. the state the TUI model leaves behind when it refuses a
// filter the trace pipeline cannot honour.
func noticeModel(t *testing.T, width, height int, showHelp bool) *Model {
	t.Helper()
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.width = width
	m.height = height
	m.showHelp = showHelp
	m.SetFilterNotice("FILTER REFUSED (comm filter max size is 15 (got 20)) - keeping the previous filter")
	return m
}

// TestFilterNoticeIsVisibleOnANarrowDashboard pins the surface the l3 fix
// relies on. The refusal is reported in the chrome's status half, which used to
// be the half thrown away when the row could not hold both it and the static
// help text - so on an ordinary 80-column terminal with the expanded help bar
// open, a refused filter would have been silently trimmed off the end of the
// line and the user would be back to a dashboard that changed nothing for no
// stated reason.
func TestFilterNoticeIsVisibleOnANarrowDashboard(t *testing.T) {
	for _, showHelp := range []bool{false, true} {
		m := noticeModel(t, 80, 24, showHelp)
		view := stripANSIEscape(m.View().Content)
		if !strings.Contains(view, "FILTER REFUSED") {
			t.Fatalf("showHelp=%v: expected the refusal notice in the dashboard chrome, got:\n%s", showHelp, view)
		}
	}
}

// TestFilterNoticePrecedesTheFilterItKept pins the reading order: the notice
// explains why the summary next to it still shows the old filter, so it has to
// come first - and being first is also what keeps it out of the part of the
// row that gets trimmed.
func TestFilterNoticePrecedesTheFilterItKept(t *testing.T) {
	m := noticeModel(t, 200, 40, false)
	line := firstLineContaining(stripANSIEscape(m.View().Content), "FILTER REFUSED")
	if line == "" {
		t.Fatalf("expected a chrome line carrying the refusal notice")
	}
	notice := strings.Index(line, "FILTER REFUSED")
	summary := strings.Index(line, "filter: ")
	if summary < 0 {
		t.Fatalf("expected the kept filter summary on the same line, got %q", line)
	}
	if notice > summary {
		t.Fatalf("expected the refusal to be read before the filter it kept, got %q", line)
	}
}

// TestFilterNoticeClearsWhenUnset pins that the notice is not sticky chrome:
// an empty notice leaves the status row exactly as it was.
func TestFilterNoticeClearsWhenUnset(t *testing.T) {
	m := noticeModel(t, 200, 40, false)
	m.SetFilterNotice("")
	if view := stripANSIEscape(m.View().Content); strings.Contains(view, "FILTER REFUSED") {
		t.Fatalf("expected the notice to disappear once cleared, got:\n%s", view)
	}
}

// TestFamilyHintIsASeparateSlot pins that the family hint and the filter
// notice are independent (kp2): setting or clearing one leaves the other, and
// the refusal is rendered ahead of the hint so a narrow row trims the hint
// first.
func TestFamilyHintIsASeparateSlot(t *testing.T) {
	const hint = "Network not traced: press O, tab, space to attach"
	m := noticeModel(t, 200, 40, false)
	m.SetFamilyHint(hint)
	summary := m.filterSummary()
	refusal, hinted := strings.Index(summary, "FILTER REFUSED"), strings.Index(summary, hint)
	if refusal < 0 || hinted < 0 || refusal > hinted {
		t.Fatalf("expected the refusal, then the hint, got %q", summary)
	}

	m.SetFamilyHint("")
	if summary := m.filterSummary(); !strings.Contains(summary, "FILTER REFUSED") || strings.Contains(summary, "not traced") {
		t.Fatalf("clearing the hint must keep the refusal, got %q", summary)
	}

	m.SetFamilyHint(hint)
	m.SetFilterNotice("")
	if summary := m.filterSummary(); strings.Contains(summary, "FILTER REFUSED") || !strings.HasPrefix(summary, hint+" | filter: ") {
		t.Fatalf("clearing the notice must keep the hint, got %q", summary)
	}
}
