package common

import "testing"

func TestDefaultKeyMapIncludesDirGroupBinding(t *testing.T) {
	keys := DefaultKeyMap()
	help := keys.DirGroup.Help()
	if help.Key != "d" || help.Desc != "dir group" {
		t.Fatalf("unexpected dir group binding help: key=%q desc=%q", help.Key, help.Desc)
	}

	probesHelp := keys.Probes.Help()
	if probesHelp.Key != "o" || probesHelp.Desc != "probes" {
		t.Fatalf("unexpected probes binding help: key=%q desc=%q", probesHelp.Key, probesHelp.Desc)
	}

	selectHelp := keys.SelectPID.Help()
	if selectHelp.Key != "p" || selectHelp.Desc != "select pid" {
		t.Fatalf("unexpected select pid binding help: key=%q desc=%q", selectHelp.Key, selectHelp.Desc)
	}

	selectTIDHelp := keys.SelectTID.Help()
	if selectTIDHelp.Key != "t" || selectTIDHelp.Desc != "select tid" {
		t.Fatalf("unexpected select tid binding help: key=%q desc=%q", selectTIDHelp.Key, selectTIDHelp.Desc)
	}

	flameHelp := keys.Seven.Help()
	if flameHelp.Key != "7" || flameHelp.Desc != "flame" {
		t.Fatalf("unexpected flame binding help: key=%q desc=%q", flameHelp.Key, flameHelp.Desc)
	}
}

func TestDashboardFullHelpIncludesDirGroupBinding(t *testing.T) {
	keys := DefaultKeyMap()
	groups := keys.DashboardFullHelp()
	if len(groups) < 2 {
		t.Fatalf("expected at least 2 help groups")
	}

	found := false
	foundSeven := false
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

	for _, binding := range groups[0] {
		help := binding.Help()
		if help.Key == "7" && help.Desc == "flame" {
			foundSeven = true
			break
		}
	}
	if !foundSeven {
		t.Fatalf("expected flame tab binding in dashboard full help tabs")
	}

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "o" && help.Desc == "probes" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected probes binding in dashboard full help controls")
	}

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "p" && help.Desc == "select pid" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected select pid binding in dashboard full help controls")
	}

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "t" && help.Desc == "select tid" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected select tid binding in dashboard full help controls")
	}
}

func TestDashboardStatusHelpIncludesProbesBinding(t *testing.T) {
	keys := DefaultKeyMap()
	short := keys.DashboardStatusHelp()
	found := false
	foundSelectTID := false
	foundSeven := false
	for _, binding := range short {
		help := binding.Help()
		if help.Key == "o" && help.Desc == "probes" {
			found = true
		}
		if help.Key == "t" && help.Desc == "select tid" {
			foundSelectTID = true
		}
		if help.Key == "7" && help.Desc == "flame" {
			foundSeven = true
		}
	}
	if !found {
		t.Fatalf("expected probes binding in dashboard short help")
	}
	if !foundSelectTID {
		t.Fatalf("expected select tid binding in dashboard short help")
	}
	if !foundSeven {
		t.Fatalf("expected flame tab binding in dashboard short help")
	}
}
