package dashboard

import (
	"strings"
	"testing"
)

func TestTabNavigationWraps(t *testing.T) {
	if got := nextTab(TabLatency); got != TabStream {
		t.Fatalf("expected next after latency+gaps to be stream, got %v", got)
	}
	if got := nextTab(TabStream); got != TabOverview {
		t.Fatalf("expected wrap to overview from stream, got %v", got)
	}
	if got := prevTab(TabOverview); got != TabStream {
		t.Fatalf("expected wrap to stream, got %v", got)
	}
}

func TestRenderTabBarContainsLabels(t *testing.T) {
	out := renderTabBar(TabOverview, 80)
	for _, label := range []string{"Overview", "Syscalls", "Files", "Processes", "Latency+Gaps", "Stream"} {
		if !strings.Contains(out, label) {
			t.Fatalf("expected tab label %q in tab bar", label)
		}
	}
}
