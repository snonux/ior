package pidpicker

import (
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// refSel is the reference model's idea of the highlighted row.
type refSel struct {
	kind refKind
	pid  int // for refProcess
}

type refKind int

const (
	refAll refKind = iota
	refProcess
	refNone
)

// refPicker is an independent, deliberately naive model of the PID picker
// selection rules (tasks 6r2, hs2), written from the documented behaviour and
// not from selection.go: a selection is either derived from the filter text
// (initial state, or the All row handed back by a text edit) or the user's own
// (after Up/Down). The filter text itself is taken from the real input, so
// cursor handling is not modelled twice.
type refPicker struct {
	procs   []ProcessInfo
	sel     refSel
	derived bool
}

// visible lists the processes matching text, in scan order.
func (r *refPicker) visible(text string) []ProcessInfo {
	query := strings.TrimSpace(strings.ToLower(text))
	var out []ProcessInfo
	for _, p := range r.procs {
		if query == "" || strings.Contains(strconv.Itoa(p.Pid), query) ||
			strings.Contains(strings.ToLower(p.Comm), query) {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []ProcessInfo, pid int) bool {
	for _, p := range list {
		if p.Pid == pid {
			return true
		}
	}
	return false
}

// derive is the filter-decided selection: All without a query, else the first
// match, else nothing.
func (r *refPicker) derive(text string) refSel {
	vis := r.visible(text)
	switch {
	case strings.TrimSpace(text) == "":
		return refSel{kind: refAll}
	case len(vis) > 0:
		return refSel{kind: refProcess, pid: vis[0].Pid}
	}
	return refSel{kind: refNone}
}

// rescan applies a new scan result under the unchanged text.
func (r *refPicker) rescan(procs []ProcessInfo, text string) {
	r.procs = procs
	switch {
	case r.derived && r.sel.kind == refProcess && contains(r.visible(text), r.sel.pid):
		// A derived process row keeps its pid wherever the rescan put it.
	case r.derived:
		r.sel = r.derive(text)
	case r.sel.kind == refProcess && !contains(r.visible(text), r.sel.pid):
		r.sel = refSel{kind: refNone}
	}
}

// edited applies a change of the filter text.
func (r *refPicker) edited(text string) {
	switch {
	case r.derived || r.sel.kind == refAll:
		r.derived = true
		r.sel = r.derive(text)
	case r.sel.kind == refProcess && !contains(r.visible(text), r.sel.pid):
		r.sel = refSel{kind: refNone}
	}
}

// move is Up (-1) or Down (+1): the selection becomes the user's own.
func (r *refPicker) move(delta int, text string) {
	rows := []refSel{{kind: refAll}}
	cur := 0
	for i, p := range r.visible(text) {
		rows = append(rows, refSel{kind: refProcess, pid: p.Pid})
		if r.sel.kind == refProcess && r.sel.pid == p.Pid {
			cur = i + 1
		}
	}
	if r.sel.kind != refNone {
		cur += delta
	}
	if cur < 0 {
		cur = 0
	}
	if cur >= len(rows) {
		cur = len(rows) - 1
	}
	r.sel, r.derived = rows[cur], false
}

// wantEnter is what Enter must emit: nothing, All (pid 0) or the process.
func (r *refPicker) wantEnter() (msg messages.PidSelectedMsg, emits bool) {
	switch r.sel.kind {
	case refNone:
		return messages.PidSelectedMsg{}, false
	case refProcess:
		return messages.PidSelectedMsg{Pid: r.sel.pid}, true
	}
	return messages.PidSelectedMsg{}, true
}

// randomScan is a shuffled scan result of unique pids with comms that overlap
// the typing alphabet, so rescans reorder, add and drop matches.
func randomScan(rng *rand.Rand) []ProcessInfo {
	comms := []string{"mysqld", "mysqlx", "bash", "sshd", "ysl", "x-proxy"}
	var procs []ProcessInfo
	for _, pid := range rng.Perm(12) {
		if rng.Intn(3) > 0 {
			procs = append(procs, ProcessInfo{Pid: pid + 1, Comm: comms[rng.Intn(len(comms))]})
		}
	}
	return procs
}

// modelDriver pairs the picker with the reference and feeds both.
type modelDriver struct {
	m   Model
	ref *refPicker
	rng *rand.Rand
}

// send delivers msg to the picker; when it changed the filter text, the
// reference sees that edit too.
func (d *modelDriver) send(msg tea.Msg) {
	before := d.m.input.Value()
	next, _ := d.m.Update(msg)
	d.m = next.(Model)
	if after := d.m.input.Value(); after != before {
		d.ref.edited(after)
	}
}

// retype replaces the filter text by a random short word that the scans' comms
// and pids actually match, one real key at a time (random letters alone almost
// never match anything, which would leave the interesting states unvisited).
func (d *modelDriver) retype() {
	d.send(tea.KeyPressMsg{Code: tea.KeyEnd})
	for range d.m.input.Value() {
		d.send(tea.KeyPressMsg{Code: tea.KeyBackspace})
	}
	words := []string{"mysql", "my", "ysl", "1", "x", "mysqlx", "sh", ""}
	for _, r := range words[d.rng.Intn(len(words))] {
		d.send(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
}

// rescan delivers a random scan result, or now and then a failed one.
func (d *modelDriver) rescan() {
	procs := randomScan(d.rng)
	msg := processesLoadedMsg{processes: procs}
	if d.rng.Intn(10) == 0 {
		msg, procs = processesLoadedMsg{err: errors.New("scan failed")}, nil
	}
	next, _ := d.m.Update(msg)
	d.m = next.(Model)
	d.ref.rescan(procs, d.m.input.Value())
}

// step performs one random action on both sides.
func (d *modelDriver) step() {
	text := d.m.input.Value()
	switch op := d.rng.Intn(20); {
	case op < 3:
		d.retype()
	case op < 5:
		d.send(tea.KeyPressMsg{Code: tea.KeyBackspace})
	case op < 7:
		d.send(tea.KeyPressMsg{Code: 'x', Text: "x"})
	case op < 9:
		d.send(tea.KeyPressMsg{Code: tea.KeyUp})
		d.ref.move(-1, text)
	case op < 11:
		d.send(tea.KeyPressMsg{Code: tea.KeyDown})
		d.ref.move(1, text)
	case op < 15:
		d.rescan()
	default:
		quiet := []tea.Msg{
			tea.KeyPressMsg{Code: tea.KeyLeft}, tea.KeyPressMsg{Code: tea.KeyRight},
			tea.KeyPressMsg{Code: tea.KeyHome}, tea.KeyPressMsg{Code: tea.KeyEnd},
			tea.KeyPressMsg{Code: 'a', Mod: tea.ModCtrl}, tea.PasteMsg{Content: ""},
			tea.WindowSizeMsg{Width: 100, Height: 30}, struct{ unrelated int }{},
		}
		d.send(quiet[d.rng.Intn(len(quiet))])
	}
}

// checkAgainstRef compares what the user can observe with the reference.
func checkAgainstRef(t *testing.T, step int, m Model, ref *refPicker) {
	t.Helper()
	text := m.input.Value()
	if want := ref.visible(text); len(want) != len(m.filtered) {
		t.Fatalf("step %d: %d rows listed for %q, reference has %d", step, len(m.filtered), text, len(want))
	}
	if m.selectedIndex < noSelection || m.selectedIndex > len(m.filtered) {
		t.Fatalf("step %d: selectedIndex %d outside the %d visible rows", step, m.selectedIndex, len(m.filtered))
	}
	want, wantEmit := ref.wantEnter()
	cmd := enterCmd(m)
	if (cmd != nil) != wantEmit {
		t.Fatalf("step %d (text %q, selectedIndex %d): Enter emits=%v, want %v", step, text, m.selectedIndex, cmd != nil, wantEmit)
	}
	if cmd == nil {
		return
	}
	got, ok := cmd().(messages.PidSelectedMsg)
	if !ok || got != want {
		t.Fatalf("step %d (text %q, selectedIndex %d): Enter emitted %+v, want %+v", step, text, m.selectedIndex, got, want)
	}
	if got.Pid == 0 && m.selectedIndex != 0 {
		t.Fatalf("step %d: pid 0 (whole system) emitted with selectedIndex %d, only the All row may do that", step, m.selectedIndex)
	}
}

// TestRandomizedSelectionMatchesReferenceModel drives the picker with seeded
// random typing, deletion, Up/Down, rescans (also failed ones) and
// non-editing messages, and after every step compares the visible rows and
// what Enter would emit with refPicker: exactly the highlighted row's pid, pid
// 0 only for the All row, nothing without a selection. It is the lightweight,
// deterministic form of a fuzz test, a few thousand steps in well under a
// second.
func TestRandomizedSelectionMatchesReferenceModel(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		rng := rand.New(rand.NewSource(seed))
		d := &modelDriver{m: NewWithKeys(DefaultKeyMap()), ref: &refPicker{derived: true}, rng: rng}
		for step := 0; step < 2500; step++ {
			d.step()
			checkAgainstRef(t, step, d.m, d.ref)
		}
	}
}
