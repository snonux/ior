package dashboard

import (
	"path/filepath"
	"strings"
)

func rootPathLabelFromFSPath(path string) string {
	cleaned := filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	if cleaned == "" || cleaned == "." || cleaned == "/" {
		return "root"
	}
	if strings.HasPrefix(cleaned, "/") {
		return "root" + cleaned
	}
	return "root/" + cleaned
}
