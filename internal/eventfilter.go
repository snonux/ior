package internal

import (
	"bytes"
	"fmt"
	"strings"

	"ior/internal/event"
	"ior/internal/types"
)

type eventFilter struct {
	commFilterEnable bool
	commFilter       string
	commFilterBytes  []byte
	pathFilterEnable bool
	pathFilter       string
	pathFilterBytes  []byte
}

func newEventFilter(commFilter, pathFilter string) (*eventFilter, error) {
	var ef eventFilter

	if commFilter != "" {
		if len(commFilter) > types.MAX_PROGNAME_LENGTH {
			return nil, fmt.Errorf("comm filter max size is %d (got %d)", types.MAX_PROGNAME_LENGTH, len(commFilter))
		}
		ef.commFilterEnable = true
		ef.commFilter = commFilter
		ef.commFilterBytes = []byte(commFilter)
	}

	if pathFilter != "" {
		if len(pathFilter) > types.MAX_FILENAME_LENGTH {
			return nil, fmt.Errorf("path filter max size is %d (got %d)", types.MAX_FILENAME_LENGTH, len(pathFilter))
		}
		ef.pathFilterEnable = true
		ef.pathFilter = pathFilter
		ef.pathFilterBytes = []byte(pathFilter)
	}

	return &ef, nil
}

func (ef *eventFilter) eventPair(ev *event.Pair) bool {
	if ef.commFilterEnable && !strings.Contains(ev.Comm, ef.commFilter) {
		return false
	}
	if ef.pathFilterEnable && (ev.File == nil || !strings.Contains(ev.File.Name(), ef.pathFilter)) {
		return false
	}
	return true
}

func (ef *eventFilter) openEvent(ev *types.OpenEvent) (*types.OpenEvent, bool) {
	if ef.commFilterEnable && !bytes.Contains(ev.Comm[:], ef.commFilterBytes) {
		return ev, false
	}

	if ef.pathFilterEnable && !bytes.Contains(ev.Filename[:], ef.pathFilterBytes) {
		return ev, false
	}
	return ev, true
}

func (ef *eventFilter) pathEvent(ev *types.PathEvent) (*types.PathEvent, bool) {
	if ef.pathFilterEnable {
		return ev, bytes.Contains(ev.Pathname[:], ef.pathFilterBytes)
	}
	return ev, true
}

func (ef *eventFilter) nameEvent(ev *types.NameEvent) (*types.NameEvent, bool) {
	if ef.pathFilterEnable {
		return ev, bytes.Contains(ev.Oldname[:], ef.pathFilterBytes) || bytes.Contains(ev.Newname[:], ef.pathFilterBytes)
	}
	return ev, true
}
