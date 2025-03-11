package internal

import (
	"bytes"
	"fmt"
	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/generated/types"
	"strings"
)

// TODO: Move to event package
type eventFilter struct {
	commFilterEnable bool
	commFilterBytes  [types.MAX_PROGNAME_LENGTH]byte
	commFilter       string
	pathFilterEnable bool
	pathFilterBytes  [types.MAX_FILENAME_LENGTH]byte
	pathFilter       string
}

func newEventFilter(flags flags.Flags) *eventFilter {
	var ef eventFilter

	if flags.CommFilter != "" {
		if len(flags.CommFilter) > types.MAX_FILENAME_LENGTH {
			panic(fmt.Sprintf("Comm filter's max size is %d", types.MAX_PROGNAME_LENGTH))
		}
		ef.commFilterEnable = true
		ef.commFilter = flags.CommFilter
		copy(ef.commFilterBytes[:], []byte(flags.CommFilter))
	}

	if flags.PathFilter != "" {
		if len(flags.PathFilter) > types.MAX_FILENAME_LENGTH {
			panic(fmt.Sprintf("Path filter's max size is %d", types.MAX_FILENAME_LENGTH))
		}
		ef.pathFilterEnable = true
		ef.pathFilter = flags.PathFilter
		copy(ef.pathFilterBytes[:], []byte(flags.PathFilter))
	}

	return &ef
}

func (ef *eventFilter) eventPair(ev *event.Pair) bool {
	if ef.commFilterEnable && !strings.Contains(ev.Comm, ef.commFilter) {
		return false
	}
	if ef.pathFilterEnable && !strings.Contains(ev.File.Name(), ef.pathFilter) {
		return false
	}
	return true
}

func (ef *eventFilter) openEvent(ev *types.OpenEvent) (*types.OpenEvent, bool) {
	if ef.commFilterEnable && !bytes.Contains(ev.Comm[:], ef.commFilterBytes[:]) {
		return ev, false
	}
	if ef.pathFilterEnable && !bytes.Contains(ev.Filename[:], ef.pathFilterBytes[:]) {
		return ev, false
	}
	return ev, true
}

func (ef *eventFilter) pathEvent(ev *types.PathEvent) (*types.PathEvent, bool) {
	if ef.pathFilterEnable {
		return ev, bytes.Contains(ev.Pathname[:], ef.pathFilterBytes[:])
	}
	return ev, true
}

func (ef *eventFilter) nameEvent(ev *types.NameEvent) (*types.NameEvent, bool) {
	if ef.pathFilterEnable {
		return ev, bytes.Contains(ev.Oldname[:], ef.pathFilterBytes[:]) || bytes.Contains(ev.Newname[:], ef.pathFilterBytes[:])
	}
	return ev, true
}
