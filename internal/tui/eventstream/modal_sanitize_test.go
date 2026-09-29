package eventstream

import (
	"strings"
	"testing"
)

const hostileModalErr = "bad /tmp/\x1b]8;;http://evil\aclick\x1b]8;;\a \x1b[8mhidden \x9b31m"

// TestExportAndSearchModalsSanitizeError checks the "Error:" line of the
// export and search modals, which can echo paths and regex error text.
func TestExportAndSearchModalsSanitizeError(t *testing.T) {
	export := NewExportModal().Open("out.csv")
	export.err = hostileModalErr
	search := NewSearchModal().Open(SearchForward, "")
	search.err = hostileModalErr
	for name, out := range map[string]string{
		"export modal": export.View(100, 30),
		"search modal": search.View(100, 30),
	} {
		assertNoInjectedEscapes(t, out)
		if !strings.Contains(out, "?]8;;http://evil?click") {
			t.Fatalf("%s lost its sanitised error line: %q", name, out)
		}
	}
}
