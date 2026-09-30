package dashboard

import (
	"path/filepath"
	"strconv"
	"strings"

	common "ior/internal/tui/common"
)

// rootPathLabelFromFSPath turns a traced directory path into the "root/..."
// display label of an icicle node. Traced paths are attacker-controlled, so
// the label is passed through common.Sanitize: it is only ever rendered,
// never used as a lookup key. It Cleans the path, which suits the icicle's
// own segment tree; the dir rows of the treemap and bubbles views use
// dirRowLabel instead, because Cleaning would merge distinct literal rows
// ("./src" and "src") into one label.
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
// treemap and bubbles views: the literal directory text itself ("/", "/etc",
// "./src", "root/etc"), sanitised like every traced path. Unlike
// rootPathLabelFromFSPath it neither Cleans nor adds a "root" prefix. The
// rows are keyed by the literal text (literalDir), so "./src", "src" and
// "//usr" are distinct rows; Cleaning would merge them, and a "root" prefix
// on absolute dirs only would make "/etc" collide with a relative "root/etc"
// dir. Display-only: the item key stays the raw Dir.
func dirRowLabel(dir string) string {
	return common.Sanitize(dir)
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
