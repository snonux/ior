package probemanager

import "strings"

// lineError is several errors as one, like the error of errors.Join, with a
// text of one line: the parts are joined with "; " where errors.Join puts a
// line feed between them.
//
// The manager's errors are shown where a line feed has no place (task 223):
// the probes modal renders a probe's recorded error in its row and the error
// of a toggle in its error line, and a headless run prints "ior: skipping
// tracepoint for <syscall>: <error>" as one status line per syscall. An
// attach whose exit tracepoint failed and whose cleanup reported an error
// too carries two errors, and joined by errors.Join the second one began a
// line of its own.
type lineError struct {
	errs []error
}

func (e *lineError) Error() string {
	parts := make([]string, len(e.errs))
	for i, err := range e.errs {
		parts[i] = err.Error()
	}
	return strings.Join(parts, "; ")
}

// Unwrap hands errors.Is and errors.As every part, as the error of
// errors.Join does.
func (e *lineError) Unwrap() []error {
	return e.errs
}

// joinOnOneLine returns the non-nil errors of errs as one error whose text is
// one line (lineError), the one error itself when only one is non-nil, and
// nil when none is. The parts' own texts are taken as they are: a part that
// contains a line feed keeps it.
func joinOnOneLine(errs ...error) error {
	kept := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			kept = append(kept, err)
		}
	}
	switch len(kept) {
	case 0:
		return nil
	case 1:
		return kept[0]
	}
	return &lineError{errs: kept}
}
