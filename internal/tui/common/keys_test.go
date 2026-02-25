package common

import "testing"

func TestDefaultKeyMapIncludesDirGroupBinding(t *testing.T) {
	keys := DefaultKeyMap()
	help := keys.DirGroup.Help()
	if help.Key != "d" || help.Desc != "dir group" {
		t.Fatalf("unexpected dir group binding help: key=%q desc=%q", help.Key, help.Desc)
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
}
