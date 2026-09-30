package common

import (
	"testing"

	"charm.land/bubbles/v2/key"
)

func TestDefaultKeyMapIncludesDirGroupBinding(t *testing.T) {
	keys := DefaultKeyMap()
	help := keys.DirGroup.Help()
	if help.Key != "d" || help.Desc != "dir group" {
		t.Fatalf("unexpected dir group binding help: key=%q desc=%q", help.Key, help.Desc)
	}

	probesHelp := keys.Probes.Help()
	if probesHelp.Key != "o" || probesHelp.Desc != "probes/families" {
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

	flameHelp := keys.One.Help()
	if flameHelp.Key != "1" || flameHelp.Desc != "flame" {
		t.Fatalf("unexpected flame binding help: key=%q desc=%q", flameHelp.Key, flameHelp.Desc)
	}

	visualizeHelp := keys.Visualize.Help()
	if visualizeHelp.Key != "v" || visualizeHelp.Desc != "viz" {
		t.Fatalf("unexpected visualize binding help: key=%q desc=%q", visualizeHelp.Key, visualizeHelp.Desc)
	}

	metricHelp := keys.Metric.Help()
	if metricHelp.Key != "b" || metricHelp.Desc != "metric" {
		t.Fatalf("unexpected metric binding help: key=%q desc=%q", metricHelp.Key, metricHelp.Desc)
	}

	sortHelp := keys.Sort.Help()
	if sortHelp.Key != "s" || sortHelp.Desc != "sort table" {
		t.Fatalf("unexpected sort binding help: key=%q desc=%q", sortHelp.Key, sortHelp.Desc)
	}
	reverseSortHelp := keys.ReverseSort.Help()
	if reverseSortHelp.Key != "S" || reverseSortHelp.Desc != "reverse sort" {
		t.Fatalf("unexpected reverse sort binding help: key=%q desc=%q", reverseSortHelp.Key, reverseSortHelp.Desc)
	}

	undoHelp := keys.FilterUndo.Help()
	if undoHelp.Key != "F" || undoHelp.Desc != "undo filter" {
		t.Fatalf("unexpected filter undo binding help: key=%q desc=%q", undoHelp.Key, undoHelp.Desc)
	}
}

func TestDashboardFullHelpIncludesDirGroupBinding(t *testing.T) {
	keys := DefaultKeyMap()
	groups := keys.DashboardFullHelp()
	if len(groups) < 2 {
		t.Fatalf("expected at least 2 help groups")
	}

	found := false
	foundOne := false
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
		if help.Key == "1" && help.Desc == "flame" {
			foundOne = true
			break
		}
	}
	if !foundOne {
		t.Fatalf("expected flame tab binding in dashboard full help tabs")
	}

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "o" && help.Desc == "probes/families" {
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

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "v" && help.Desc == "viz" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected viz binding in dashboard full help controls")
	}

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "b" && help.Desc == "metric" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected metric binding in dashboard full help controls")
	}

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "s" && help.Desc == "sort table" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected sort binding in dashboard full help controls")
	}

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "S" && help.Desc == "reverse sort" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected reverse sort binding in dashboard full help controls")
	}

	found = false
	for _, binding := range groups[1] {
		help := binding.Help()
		if help.Key == "F" && help.Desc == "undo filter" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected undo filter binding in dashboard full help controls")
	}
}

func TestDashboardStatusHelpIncludesProbesBinding(t *testing.T) {
	keys := DefaultKeyMap()
	short := keys.DashboardStatusHelp()
	found := false
	foundSelectTID := false
	foundOne := false
	foundUndo := false
	foundSort := false
	foundReverseSort := false
	for _, binding := range short {
		help := binding.Help()
		if help.Key == "o" && help.Desc == "probes/families" {
			found = true
		}
		if help.Key == "t" && help.Desc == "select tid" {
			foundSelectTID = true
		}
		if help.Key == "1" && help.Desc == "flame" {
			foundOne = true
		}
		if help.Key == "F" && help.Desc == "undo filter" {
			foundUndo = true
		}
		if help.Key == "s" && help.Desc == "sort table" {
			foundSort = true
		}
		if help.Key == "S" && help.Desc == "reverse sort" {
			foundReverseSort = true
		}
	}
	if !found {
		t.Fatalf("expected probes binding in dashboard short help")
	}
	if !foundSelectTID {
		t.Fatalf("expected select tid binding in dashboard short help")
	}
	if !foundOne {
		t.Fatalf("expected flame tab binding in dashboard short help")
	}
	if !foundUndo {
		t.Fatalf("expected undo filter binding in dashboard short help")
	}
	if !foundSort {
		t.Fatalf("expected sort binding in dashboard short help")
	}
	if !foundReverseSort {
		t.Fatalf("expected reverse sort binding in dashboard short help")
	}
}

// TestExportDisabledHidesStreamExportHints regresses the -tuiExport=false
// hint gating: with the Export binding blanked (what the top-level model does
// when the flag is false), neither the dashboard status bar nor the dashboard
// full help may advertise the stream export shortcuts (x/X/E).
func TestExportDisabledHidesStreamExportHints(t *testing.T) {
	blanked := DefaultKeyMap()
	blanked.Export = key.NewBinding()
	for _, tc := range []struct {
		name  string
		binds []key.Binding
	}{
		{"status help", blanked.DashboardStatusHelp()},
		{"full help", flattenedHelpGroups(blanked.DashboardFullHelp())},
	} {
		for _, binding := range tc.binds {
			help := binding.Help()
			if help.Key == "e" && help.Desc == "stream export" {
				t.Fatalf("%s: did not expect the e export binding when export is disabled", tc.name)
			}
			if desc := exportHintDescriptions[help.Desc]; desc {
				t.Fatalf("%s: did not expect export hint %q when export is disabled", tc.name, help.Desc)
			}
		}
	}

	enabled := DefaultKeyMap()
	for _, tc := range []struct {
		name  string
		binds []key.Binding
	}{
		{"status help", enabled.DashboardStatusHelp()},
		{"full help", flattenedHelpGroups(enabled.DashboardFullHelp())},
	} {
		found := map[string]bool{}
		for _, binding := range tc.binds {
			help := binding.Help()
			if exportHintDescriptions[help.Desc] {
				found[help.Desc] = true
			}
		}
		for desc := range exportHintDescriptions {
			if !found[desc] {
				t.Fatalf("%s: expected export hint %q when export is enabled", tc.name, desc)
			}
		}
	}
}

// flattenedHelpGroups flattens grouped help bindings into one slice.
func flattenedHelpGroups(groups [][]key.Binding) []key.Binding {
	var out []key.Binding
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

// exportHintDescriptions lists the stream export hint descriptions gated by
// the -tuiExport flag (all must appear when export is enabled).
var exportHintDescriptions = map[string]bool{
	"stream export":    true,
	"stream export as": true,
	"stream open last": true,
}
