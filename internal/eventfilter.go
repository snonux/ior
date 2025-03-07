package internal

import (
	"bytes"
	"fmt"
	"ior/internal/flags"
	"ior/internal/generated/types"
)

type eventFilter struct {
	commFilterEnable bool
	commFilter       [types.MAX_PROGNAME_LENGTH]byte
	pathFilterEnable bool
	pathFilter       [types.MAX_FILENAME_LENGTH]byte
}

func newEventFilter(flags flags.Flags) *eventFilter {
	var ef eventFilter

	if flags.CommFilter != "" {
		if len(flags.CommFilter) > types.MAX_FILENAME_LENGTH {
			panic(fmt.Sprintf("Comm filter's max size is %d", types.MAX_PROGNAME_LENGTH))
		}
		ef.commFilterEnable = true
		copy(ef.commFilter[:], []byte(flags.CommFilter))
	}
	if flags.PathFilter != "" {
		if len(flags.PathFilter) > types.MAX_FILENAME_LENGTH {
			panic(fmt.Sprintf("Path filter's max size is %d", types.MAX_FILENAME_LENGTH))
		}
		ef.pathFilterEnable = true
		copy(ef.pathFilter[:], []byte(flags.PathFilter))
	}

	return &ef
}

func (ef *eventFilter) openEvent(ev *types.OpenEvent) (*types.OpenEvent, bool) {
	commFilterPass := true
	if ef.commFilterEnable {
		commFilterPass = bytes.Contains(ev.Comm[:], ef.commFilter[:])
	}
	pathFilterPass := true
	if ef.pathFilterEnable {
		pathFilterPass = bytes.Contains(ev.Filename[:], ef.pathFilter[:])
	}
	return ev, commFilterPass && pathFilterPass
}

func (ef *eventFilter) pathEvent(ev *types.PathEvent) (*types.PathEvent, bool) {
	if ef.pathFilterEnable {
		return ev, bytes.Contains(ev.Pathname[:], ef.pathFilter[:])
	}
	return ev, true
}

func (ef *eventFilter) nameEvent(ev *types.NameEvent) (*types.NameEvent, bool) {
	if ef.pathFilterEnable {
		return ev, bytes.Contains(ev.Oldname[:], ef.pathFilter[:]) || bytes.Contains(ev.Newname[:], ef.pathFilter[:])
	}
	return ev, true
}
