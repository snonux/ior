package internal

import (
	"bytes"
	"ioriotng/internal/flags"
	"ioriotng/internal/generated/types"
)

type eventFilter struct {
	commFilterEnable bool
	commFilter       [types.MAX_PROGNAME_LENGTH]byte
}

func newEventFilter(flags flags.Flags) *eventFilter {
	var ef eventFilter

	if flags.CommFilter != "" {
		ef.commFilterEnable = true
		copy(ef.commFilter[:], []byte(flags.CommFilter))
	}

	return &ef
}

func (ef *eventFilter) openEvent(ev *types.OpenEvent) (*types.OpenEvent, bool) {
	if ef.commFilterEnable {
		return ev, bytes.Contains(ev.Comm[:], ef.commFilter[:])
	}
	return ev, true
}
