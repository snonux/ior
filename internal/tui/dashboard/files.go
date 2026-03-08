package dashboard

import (
	"path/filepath"
	"sort"
	"strconv"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

type DirSnapshot struct {
	Dir string

	Accesses     uint64
	BytesRead    uint64
	BytesWritten uint64

	AvgLatencyNs float64
	MaxLatencyNs uint64
	FileCount    uint64
}

func renderFiles(snap *statsengine.Snapshot, width, height int) string {
	return renderFilesWithOffset(snap, width, height, 0, 0)
}

func renderFilesWithOffset(snap *statsengine.Snapshot, width, height, offset, selectedCol int) string {
	if snap == nil {
		return "Files: waiting for stats..."
	}

	pathWidth := filePathWidth(width)
	rows := fileRows(snap.Files(), pathWidth)
	if len(rows) == 0 {
		return "Files: no data"
	}

	columns := fileColumns(width)
	return renderSelectableTable(columns, rows, height, offset, selectedCol, "enter:filter", "d:dirs", "v:mode in dirs")
}

func renderFilesDirGrouped(snap *statsengine.Snapshot, width, height, offset, selectedCol int) string {
	if snap == nil {
		return "Files (dirs): waiting for stats..."
	}

	pathWidth := dirPathWidth(width)
	rows := dirRows(aggregateFilesByDir(snap.Files()), pathWidth)
	if len(rows) == 0 {
		return "Files (dirs): no data"
	}

	columns := fileDirColumns(width)
	return renderSelectableTable(columns, rows, height, offset, selectedCol, "enter:filter", "d:files", "v:mode", "b:metric")
}

func fileRows(files []statsengine.FileSnapshot, pathWidth int) [][]string {
	rows := make([][]string, 0, len(files))
	for _, f := range files {
		rows = append(rows, []string{
			strconv.FormatUint(f.Accesses, 10),
			formatBytes(float64(f.BytesRead)),
			formatBytes(float64(f.BytesWritten)),
			formatDurationNs(f.AvgLatencyNs),
			formatDurationUintNs(f.MaxLatencyNs),
			truncatePathMiddle(f.Path, pathWidth),
		})
	}
	return rows
}

func filePathWidth(width int) int {
	if width <= 0 {
		return 24
	}
	// Keep fixed metrics visible and let path consume the remaining space.
	// Fixed columns sum to 48 chars; reserve extra for separators/padding.
	w := width - 58
	if w < 14 {
		return 14
	}
	return w
}

func dirPathWidth(width int) int {
	if width <= 0 {
		return 24
	}
	// Directory view adds a 5-char Files column (+1 spacing), so reserve 6 more.
	w := width - 64
	if w < 14 {
		return 14
	}
	return w
}

func fileColumns(width int) []common.TableColumn {
	pathWidth := filePathWidth(width)
	return []common.TableColumn{
		{Title: "Accesses", Width: 8},
		{Title: "Read", Width: 9},
		{Title: "Write", Width: 9},
		{Title: "Avg Latency", Width: 11},
		{Title: "Max Latency", Width: 11},
		{Title: "Path", Width: pathWidth},
	}
}

func fileDirColumns(width int) []common.TableColumn {
	pathWidth := dirPathWidth(width)
	return []common.TableColumn{
		{Title: "Accesses", Width: 8},
		{Title: "Read", Width: 9},
		{Title: "Write", Width: 9},
		{Title: "Avg Latency", Width: 11},
		{Title: "Max Latency", Width: 11},
		{Title: "Files", Width: 5},
		{Title: "Directory", Width: pathWidth},
	}
}

func truncatePathMiddle(path string, limit int) string {
	if len(path) <= limit {
		return path
	}
	if limit <= 3 {
		return path[:limit]
	}

	head := (limit - 3) / 2
	tail := limit - 3 - head
	if tail <= 0 {
		return path[:limit]
	}
	return path[:head] + "..." + path[len(path)-tail:]
}

func aggregateFilesByDir(files []statsengine.FileSnapshot) []DirSnapshot {
	if len(files) == 0 {
		return nil
	}

	dirs := make(map[string]DirSnapshot, len(files))
	weightedLatency := make(map[string]float64, len(files))
	for _, f := range files {
		dir := filepath.Dir(f.Path)
		s := dirs[dir]
		s.Dir = dir
		s.Accesses += f.Accesses
		s.BytesRead += f.BytesRead
		s.BytesWritten += f.BytesWritten
		if f.MaxLatencyNs > s.MaxLatencyNs {
			s.MaxLatencyNs = f.MaxLatencyNs
		}
		s.FileCount++
		weightedLatency[dir] += f.AvgLatencyNs * float64(f.Accesses)
		dirs[dir] = s
	}

	out := make([]DirSnapshot, 0, len(dirs))
	for dir, s := range dirs {
		if s.Accesses > 0 {
			s.AvgLatencyNs = weightedLatency[dir] / float64(s.Accesses)
		}
		out = append(out, s)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Accesses != out[j].Accesses {
			return out[i].Accesses > out[j].Accesses
		}
		return out[i].Dir < out[j].Dir
	})
	return out
}

func dirRows(dirs []DirSnapshot, pathWidth int) [][]string {
	rows := make([][]string, 0, len(dirs))
	for _, d := range dirs {
		rows = append(rows, []string{
			strconv.FormatUint(d.Accesses, 10),
			formatBytes(float64(d.BytesRead)),
			formatBytes(float64(d.BytesWritten)),
			formatDurationNs(d.AvgLatencyNs),
			formatDurationUintNs(d.MaxLatencyNs),
			strconv.FormatUint(d.FileCount, 10),
			truncatePathMiddle(d.Dir, pathWidth),
		})
	}
	return rows
}
