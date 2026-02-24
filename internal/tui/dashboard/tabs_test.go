package dashboard

import (
	"strings"
	"testing"
)

func TestTabNavigationWraps(t *testing.T) {
	if got := nextTab(TabGaps); got != TabOverview {
		t.Fatalf("expected wrap to overview, got %v", got)
	}
	if got := prevTab(TabOverview); got != TabGaps {
		t.Fatalf("expected wrap to gaps, got %v", got)
	}
}

func TestRenderTabBarContainsLabels(t *testing.T) {
	out := renderTabBar(TabOverview, 80)
	for _, label := range []string{"Overview", "Syscalls", "Files", "Processes", "Latency", "Gaps"} {
		if !strings.Contains(out, label) {
			t.Fatalf("expected tab label %q in tab bar", label)
		}
	}
}
