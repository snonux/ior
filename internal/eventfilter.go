package internal

import (
	"fmt"
	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/types"
	"strings"
)

type eventFilter struct {
	commFilterEnable bool
	commFilter       string
	pathFilterEnable bool
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
	}

	if flags.PathFilter != "" {
		if len(flags.PathFilter) > types.MAX_FILENAME_LENGTH {
			panic(fmt.Sprintf("Path filter's max size is %d", types.MAX_FILENAME_LENGTH))
		}
		ef.pathFilterEnable = true
		ef.pathFilter = flags.PathFilter
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
	if ef.commFilterEnable && !strings.Contains(string(ev.Comm[:]), ef.commFilter) {
		return ev, false
	}

	if ef.pathFilterEnable && !strings.Contains(string(ev.Filename[:]), ef.pathFilter) {
		return ev, false
	}
	return ev, true
}

func (ef *eventFilter) pathEvent(ev *types.PathEvent) (*types.PathEvent, bool) {
	if ef.pathFilterEnable {
		return ev, strings.Contains(string(ev.Pathname[:]), ef.pathFilter)
	}
	return ev, true
}

func (ef *eventFilter) nameEvent(ev *types.NameEvent) (*types.NameEvent, bool) {
	if ef.pathFilterEnable {
		return ev, strings.Contains(string(ev.Oldname[:]), ef.pathFilter) || strings.Contains(string(ev.Newname[:]), ef.pathFilter)
	}
	return ev, true
}
