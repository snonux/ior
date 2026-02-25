package common

import "testing"

func TestDefaultKeyMapIncludesDirGroupBinding(t *testing.T) {
	keys := DefaultKeyMap()
	help := keys.DirGroup.Help()
	if help.Key != "d" || help.Desc != "dir group" {
		t.Fatalf("unexpected dir group binding help: key=%q desc=%q", help.Key, help.Desc)
	}

	probesHelp := keys.Probes.Help()
	if probesHelp.Key != "p" || probesHelp.Desc != "probes" {
		t.Fatalf("unexpected probes binding help: key=%q desc=%q", probesHelp.Key, probesHelp.Desc)
	}
}

func TestDashboardFullHelpIncludesDirGroupBinding(t *testing.T) {
	keys := DefaultKeyMap()
	groups := keys.DashboardFullHelp()
	if len(groups) < 2 {
		t.Fatalf("expected at least 2 help groups")
	}

	found := false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "d" && help.Desc == "dir group" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected dir group binding in dashboard full help controls")
	}

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "p" && help.Desc == "probes" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected probes binding in dashboard full help controls")
	}
}

func TestDashboardShortHelpIncludesProbesBinding(t *testing.T) {
	keys := DefaultKeyMap()
	short := keys.DashboardShortHelp()
	found := false
	for _, binding := range short {
		help := binding.Help()
		if help.Key == "p" && help.Desc == "probes" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected probes binding in dashboard short help")
	}
}
