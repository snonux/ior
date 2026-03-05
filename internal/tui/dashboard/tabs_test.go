package dashboard

import (
	"strings"
	"testing"

	common "ior/internal/tui/common"
)

func TestTabNavigationWraps(t *testing.T) {
	if got := nextTab(TabLatency); got != TabStream {
		t.Fatalf("expected next after latency+gaps to be stream, got %v", got)
	}
	if got := nextTab(TabStream); got != TabFlame {
		t.Fatalf("expected next after stream to be flame, got %v", got)
	}
	if got := nextTab(TabFlame); got != TabOverview {
		t.Fatalf("expected wrap to overview from flame, got %v", got)
	}
	if got := prevTab(TabOverview); got != TabFlame {
		t.Fatalf("expected wrap to flame, got %v", got)
	}
}

func TestRenderTabBarContainsLabels(t *testing.T) {
	out := renderTabBar(TabOverview, 100)
	for _, label := range []string{"Overview", "Syscalls", "Files", "Processes", "Latency+Gaps", "Stream", "Flame"} {
		if !strings.Contains(out, label) {
			t.Fatalf("expected tab label %q in tab bar", label)
		}
	}
}

func TestRenderTabBarSmallWidthUsesSingleLine(t *testing.T) {
	out := renderTabBar(TabOverview, 70)
	lines := strings.Split(out, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected single-line tab bar at width 70, got %d lines", len(lines))
	}
	if strings.Contains(out, "7:Flam") {
		t.Fatalf("tab label should not be wrapped/split in small width output")
	}
}

func TestRenderHelpBarSmallWidthCanWrapToTwoLines(t *testing.T) {
	out := renderHelpBar(common.DefaultKeyMap(), 70)
	lines := strings.Split(out, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly two section lines at width 70, got %d lines", len(lines))
	}
	if !strings.Contains(lines[0], "Global:") {
		t.Fatalf("expected Global section line, got %q", lines[0])
	}
	if !strings.Contains(lines[1], "Dashboard:") {
		t.Fatalf("expected Dashboard section line, got %q", lines[1])
	}
}
