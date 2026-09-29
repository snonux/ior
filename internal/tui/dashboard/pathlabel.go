package dashboard

import (
	"path/filepath"
	"strconv"
	"strings"

	common "ior/internal/tui/common"
)

// rootPathLabelFromFSPath turns a traced directory path into the "root/..."
// display label used by the bubbles, treemap and icicle views. Traced paths
// are attacker-controlled, so the label is passed through common.Sanitize:
// it is only ever rendered, never used as a lookup key.
func rootPathLabelFromFSPath(path string) string {
	cleaned := filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	if cleaned == "" || cleaned == "." || cleaned == "/" {
		return "root"
	}
	if strings.HasPrefix(cleaned, "/") {
		return common.Sanitize("root" + cleaned)
	}
	return common.Sanitize("root/" + cleaned)
}

// dirRowLabel is the display label of one dir-grouped Files row in the
// treemap and bubbles views. Unlike rootPathLabelFromFSPath it does not Clean:
// the rows are keyed by the literal directory text (literalDir), so "./src",
// "src" and "//usr" are distinct rows and must not share a label. An
// absolute dir reads "root/..." ("root" for "/"); a relative one, which is
// not under "/", is shown as it is ("./src", "src", "."). Sanitised like
// every traced path; display-only (the item key stays the raw Dir).
func dirRowLabel(dir string) string {
	switch {
	case dir == "/":
		return "root"
	case strings.HasPrefix(dir, "/"):
		return common.Sanitize("root" + dir)
	default:
		return common.Sanitize(dir)
	}
}

// processLabel is the "pid:comm" display label of a process tile or bubble
// ("pid" alone without a comm). The traced comm is attacker-controlled and
// is sanitised; the label is display-only (selection uses processKey/ID).
func processLabel(pid uint32, comm string) string {
	if comm = strings.TrimSpace(comm); comm != "" {
		return strconv.FormatUint(uint64(pid), 10) + ":" + common.Sanitize(comm)
	}
	return strconv.FormatUint(uint64(pid), 10)
}
