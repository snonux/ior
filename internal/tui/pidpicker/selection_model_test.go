package pidpicker

import (
	"errors"
	"fmt"
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
	pid  int // for refProcess (the tid in TID mode)
}

type refKind int

const (
	refAll refKind = iota
	refProcess
	refNone
)

// refThreadParent is the ParentPID of every row of a TID-mode random scan: the
// process whose threads the TID picker lists.
const refThreadParent = 500

// refPicker is an independent, deliberately naive model of the picker
// selection rules (tasks 6r2, hs2) in both modes, written from the documented
// behaviour and not from selection.go: a selection is either derived from the
// filter text (initial state, or the All row handed back by a text edit) or the
// user's own (after Up/Down). It also predicts the notice line word for word.
// The filter text itself is taken from the real input, so cursor handling is
// not modelled twice.
type refPicker struct {
	tid     bool // TID mode: lists threads, a lost pick falls back to All
	procs   []ProcessInfo
	sel     refSel
	derived bool
	held    int  // derived pid a failed scan emptied out, for the next scan
	scanned bool // a scan result (good or failed) has arrived
	failed  bool // the latest scan failed
	notice  string
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

// words returns the mode's row noun and id name used in notices.
func (r *refPicker) words() (row, id string) {
	if r.tid {
		return "thread", "tid"
	}
	return "process", "pid"
}

// reason says why pid left the list: still scanned means filtered out.
func (r *refPicker) reason(pid int) string {
	if contains(r.procs, pid) {
		return "no longer matches the filter"
	}
	return "exited"
}

// derive sets the filter-decided selection: All without a query, else the
// first match, else nothing, with the no-match notice only when a successful
// scan really found nothing.
func (r *refPicker) derive(text string) {
	vis := r.visible(text)
	r.notice = ""
	switch {
	case strings.TrimSpace(text) == "":
		r.sel = refSel{kind: refAll}
	case len(vis) > 0:
		r.sel = refSel{kind: refProcess, pid: vis[0].Pid}
	default:
		r.sel = refSel{kind: refNone}
		if row, _ := r.words(); r.scanned && !r.failed {
			r.notice = "no " + row + " matches the filter"
		}
	}
}

// loseUserPick handles a user-picked process that left the visible list: the
// TID picker falls back to All TIDs quietly, the PID picker selects nothing
// and says why.
func (r *refPicker) loseUserPick(text string) {
	if r.sel.kind != refProcess || contains(r.visible(text), r.sel.pid) {
		return
	}
	pid := r.sel.pid
	if r.tid {
		r.sel = refSel{kind: refAll}
		return
	}
	r.sel = refSel{kind: refNone}
	r.notice = fmt.Sprintf("pid %d %s - pick a process", pid, r.reason(pid))
}

// rescan applies a scan result (failed: no processes) under the unchanged text.
func (r *refPicker) rescan(procs []ProcessInfo, failed bool, text string) {
	tracked := 0
	switch {
	case r.derived && r.sel.kind == refProcess:
		tracked = r.sel.pid
	case r.derived:
		tracked = r.held
	}
	r.procs, r.scanned, r.failed, r.held = procs, true, failed, 0
	if !r.derived {
		r.loseUserPick(text)
		return
	}
	if tracked != 0 && contains(r.visible(text), tracked) {
		// A derived process row keeps its pid wherever the rescan put it.
		r.sel, r.notice = refSel{kind: refProcess, pid: tracked}, ""
		return
	}
	r.derive(text)
	switch {
	case tracked == 0:
	case failed:
		r.held = tracked
	case r.sel.kind == refProcess:
		_, id := r.words()
		r.notice = fmt.Sprintf("%s %d %s - selected %s %d instead", id, tracked, r.reason(tracked), id, r.sel.pid)
	}
}

// edited applies a change of the filter text.
func (r *refPicker) edited(text string) {
	r.held = 0
	if r.derived || r.sel.kind == refAll {
		r.derived = true
		r.derive(text)
		return
	}
	r.loseUserPick(text)
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
	cur = clamp(cur, 0, len(rows)-1)
	r.sel, r.derived, r.held, r.notice = rows[cur], false, 0, ""
}

// wantEnter is what Enter must emit: nil for nothing, else the mode's zero
// message for the All row or the process's message.
func (r *refPicker) wantEnter() tea.Msg {
	switch {
	case r.sel.kind == refNone:
		return nil
	case r.tid && r.sel.kind == refProcess:
		return messages.TidSelectedMsg{Pid: refThreadParent, Tid: r.sel.pid}
	case r.tid:
		return messages.TidSelectedMsg{}
	case r.sel.kind == refProcess:
		return messages.PidSelectedMsg{Pid: r.sel.pid}
	}
	return messages.PidSelectedMsg{}
}

// randomScan is a shuffled scan result of unique pids with comms that overlap
// the typing alphabet, so rescans reorder, add and drop matches. In TID mode
// the rows are threads of refThreadParent.
func randomScan(rng *rand.Rand, tid bool) []ProcessInfo {
	comms := []string{"mysqld", "mysqlx", "bash", "sshd", "ysl", "x-proxy"}
	var procs []ProcessInfo
	for _, pid := range rng.Perm(12) {
		if rng.Intn(3) > 0 {
			p := ProcessInfo{Pid: pid + 1, Comm: comms[rng.Intn(len(comms))]}
			if tid {
				p.ParentPID = refThreadParent
			}
			procs = append(procs, p)
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

// rescan delivers a random scan result, or now and then a failed one (often
// enough that a failed scan between two good ones, the heldPid case, is common).
func (d *modelDriver) rescan() {
	procs := randomScan(d.rng, d.ref.tid)
	msg := processesLoadedMsg{processes: procs}
	failed := d.rng.Intn(6) == 0
	if failed {
		msg, procs = processesLoadedMsg{err: errors.New("scan failed")}, nil
	}
	next, _ := d.m.Update(msg)
	d.m = next.(Model)
	d.ref.rescan(procs, failed, d.m.input.Value())
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

// checkAgainstRef compares what the user can observe with the reference: the
// listed rows, the notice line and what Enter emits.
func checkAgainstRef(t *testing.T, step int, m Model, ref *refPicker) {
	t.Helper()
	text := m.input.Value()
	if want := ref.visible(text); len(want) != len(m.filtered) {
		t.Fatalf("step %d: %d rows listed for %q, reference has %d", step, len(m.filtered), text, len(want))
	}
	if m.selectedIndex < noSelection || m.selectedIndex > len(m.filtered) {
		t.Fatalf("step %d: selectedIndex %d outside the %d visible rows", step, m.selectedIndex, len(m.filtered))
	}
	if m.notice != ref.notice {
		t.Fatalf("step %d (text %q, selectedIndex %d): notice %q, want %q", step, text, m.selectedIndex, m.notice, ref.notice)
	}
	want := ref.wantEnter()
	var got tea.Msg
	if cmd := enterCmd(m); cmd != nil {
		got = cmd()
	}
	if got != want {
		t.Fatalf("step %d (text %q, selectedIndex %d): Enter emitted %#v, want %#v", step, text, m.selectedIndex, got, want)
	}
	isAll := got == messages.PidSelectedMsg{} || got == messages.TidSelectedMsg{}
	if isAll && m.selectedIndex != 0 {
		t.Fatalf("step %d: the All message emitted with selectedIndex %d, only the All row may do that", step, m.selectedIndex)
	}
}

// TestRandomizedSelectionMatchesReferenceModel drives the PID and the TID
// picker with seeded random typing, deletion, Up/Down, rescans (also failed
// ones) and non-editing messages, and after every step compares the visible
// rows, the notice text and what Enter would emit with refPicker: exactly the
// highlighted row (pid 0 / All TIDs only for the All row, a TID pick hidden by
// the filter falling back to All TIDs), nothing without a selection. It is the
// lightweight, deterministic form of a fuzz test, a few thousand steps per mode
// in well under a second.
func TestRandomizedSelectionMatchesReferenceModel(t *testing.T) {
	modes := map[string]func() Model{
		"pid": func() Model { return NewWithKeys(DefaultKeyMap()) },
		"tid": func() Model { return NewTIDWithKeys(refThreadParent, DefaultKeyMap()) },
	}
	for name, newModel := range modes {
		t.Run(name, func(t *testing.T) {
			for seed := int64(1); seed <= 4; seed++ {
				rng := rand.New(rand.NewSource(seed))
				ref := &refPicker{tid: name == "tid", derived: true}
				d := &modelDriver{m: newModel(), ref: ref, rng: rng}
				for step := 0; step < 2500; step++ {
					d.step()
					checkAgainstRef(t, step, d.m, d.ref)
				}
			}
		})
	}
}
