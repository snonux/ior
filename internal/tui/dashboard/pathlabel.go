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

// processLabel is the "pid:comm" display label of a process tile or bubble
// ("pid" alone without a comm). The traced comm is attacker-controlled and
// is sanitised; the label is display-only (selection uses processKey/ID).
func processLabel(pid uint32, comm string) string {
	if comm = strings.TrimSpace(comm); comm != "" {
		return strconv.FormatUint(uint64(pid), 10) + ":" + common.Sanitize(comm)
	}
	return strconv.FormatUint(uint64(pid), 10)
}
