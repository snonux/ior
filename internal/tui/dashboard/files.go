package dashboard

import (
	"cmp"
	"path/filepath"
	"slices"
	"strconv"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

type DirSnapshot struct {
	Dir string

	Accesses     uint64
	BytesRead    uint64
	BytesWritten uint64

	AvgLatencyNs   float64
	MaxLatencyNs   uint64
	TotalLatencyNs uint64
	FileCount      uint64
}

type fileSortKey uint8

const (
	fileSortKeyAccesses fileSortKey = iota
	fileSortKeyRead
	fileSortKeyWrite
	fileSortKeyAvgLatency
	fileSortKeyMaxLatency
	fileSortKeyPath
)

type fileDirSortKey uint8

const (
	fileDirSortKeyAccesses fileDirSortKey = iota
	fileDirSortKeyRead
	fileDirSortKeyWrite
	fileDirSortKeyAvgLatency
	fileDirSortKeyMaxLatency
	fileDirSortKeyFileCount
	fileDirSortKeyDir
)

func renderFiles(snap *statsengine.Snapshot, width, height int) string {
	return renderFilesWithSort(snap, width, height, 0, 0, tableSortState[fileSortKey]{})
}

func renderFilesWithOffset(snap *statsengine.Snapshot, width, height, offset, selectedCol int) string {
	return renderFilesWithSort(snap, width, height, offset, selectedCol, tableSortState[fileSortKey]{})
}

func renderFilesWithSort(snap *statsengine.Snapshot, width, height, offset, selectedCol int, sortState tableSortState[fileSortKey]) string {
	if snap == nil {
		return "Files: waiting for stats..."
	}

	pathWidth := filePathWidth(width)
	rows := fileRows(sortedFileSnapshots(snap.Files(), sortState), pathWidth)
	if len(rows) == 0 {
		return "Files: no data"
	}

	columns := fileColumns(width)
	return renderSelectableTable(
		columns,
		rows,
		height,
		offset,
		selectedCol,
		"enter:filter",
		"s/S:sort",
		fileSortHint(sortState),
		"d:dirs",
		"v:mode in dirs",
	)
}

func renderFilesDirGrouped(snap *statsengine.Snapshot, width, height, offset, selectedCol int) string {
	return renderFilesDirGroupedWithSort(snap, width, height, offset, selectedCol, tableSortState[fileDirSortKey]{})
}

func renderFilesDirGroupedWithSort(snap *statsengine.Snapshot, width, height, offset, selectedCol int, sortState tableSortState[fileDirSortKey]) string {
	if snap == nil {
		return "Files (dirs): waiting for stats..."
	}

	pathWidth := dirPathWidth(width)
	rows := dirRows(sortedDirSnapshots(aggregateFilesByDir(snap.Files()), sortState), pathWidth)
	if len(rows) == 0 {
		return "Files (dirs): no data"
	}

	columns := fileDirColumns(width)
	return renderSelectableTable(
		columns,
		rows,
		height,
		offset,
		selectedCol,
		"enter:filter",
		"s/S:sort",
		fileDirSortHint(sortState),
		"d:files",
		"v:mode",
		"b:metric",
	)
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

func sortedFileSnapshots(rows []statsengine.FileSnapshot, sortState tableSortState[fileSortKey]) []statsengine.FileSnapshot {
	return sortedWithState(rows, sortState, compareFileBySort, compareFileDefault)
}

func sortedDirSnapshots(rows []DirSnapshot, sortState tableSortState[fileDirSortKey]) []DirSnapshot {
	return sortedWithState(rows, sortState, compareDirBySort, compareDirDefault)
}

func compareFileBySort(left, right statsengine.FileSnapshot, key fileSortKey) int {
	switch key {
	case fileSortKeyAccesses:
		return compareUint64Desc(left.Accesses, right.Accesses)
	case fileSortKeyRead:
		return compareUint64Desc(left.BytesRead, right.BytesRead)
	case fileSortKeyWrite:
		return compareUint64Desc(left.BytesWritten, right.BytesWritten)
	case fileSortKeyAvgLatency:
		return compareFloat64Desc(left.AvgLatencyNs, right.AvgLatencyNs)
	case fileSortKeyMaxLatency:
		return compareUint64Desc(left.MaxLatencyNs, right.MaxLatencyNs)
	case fileSortKeyPath:
		return compareStringAsc(left.Path, right.Path)
	default:
		return 0
	}
}

func compareFileDefault(left, right statsengine.FileSnapshot) int {
	if cmp := compareUint64Desc(left.Accesses, right.Accesses); cmp != 0 {
		return cmp
	}
	return compareStringAsc(left.Path, right.Path)
}

func compareDirBySort(left, right DirSnapshot, key fileDirSortKey) int {
	switch key {
	case fileDirSortKeyAccesses:
		return compareUint64Desc(left.Accesses, right.Accesses)
	case fileDirSortKeyRead:
		return compareUint64Desc(left.BytesRead, right.BytesRead)
	case fileDirSortKeyWrite:
		return compareUint64Desc(left.BytesWritten, right.BytesWritten)
	case fileDirSortKeyAvgLatency:
		return compareFloat64Desc(left.AvgLatencyNs, right.AvgLatencyNs)
	case fileDirSortKeyMaxLatency:
		return compareUint64Desc(left.MaxLatencyNs, right.MaxLatencyNs)
	case fileDirSortKeyFileCount:
		return compareUint64Desc(left.FileCount, right.FileCount)
	case fileDirSortKeyDir:
		return compareStringAsc(left.Dir, right.Dir)
	default:
		return 0
	}
}

func compareDirDefault(left, right DirSnapshot) int {
	if cmp := compareUint64Desc(left.Accesses, right.Accesses); cmp != 0 {
		return cmp
	}
	return compareStringAsc(left.Dir, right.Dir)
}

func fileSortKeyForColumn(column int) (fileSortKey, bool) {
	switch column {
	case 0:
		return fileSortKeyAccesses, true
	case 1:
		return fileSortKeyRead, true
	case 2:
		return fileSortKeyWrite, true
	case 3:
		return fileSortKeyAvgLatency, true
	case 4:
		return fileSortKeyMaxLatency, true
	case 5:
		return fileSortKeyPath, true
	default:
		return 0, false
	}
}

func fileDirSortKeyForColumn(column int) (fileDirSortKey, bool) {
	switch column {
	case 0:
		return fileDirSortKeyAccesses, true
	case 1:
		return fileDirSortKeyRead, true
	case 2:
		return fileDirSortKeyWrite, true
	case 3:
		return fileDirSortKeyAvgLatency, true
	case 4:
		return fileDirSortKeyMaxLatency, true
	case 5:
		return fileDirSortKeyFileCount, true
	case 6:
		return fileDirSortKeyDir, true
	default:
		return 0, false
	}
}

func fileSortHint(sortState tableSortState[fileSortKey]) string {
	return "sort: " + fileSortLabel(sortState)
}

func fileSortLabel(sortState tableSortState[fileSortKey]) string {
	if !sortState.active {
		return "default"
	}
	switch sortState.key {
	case fileSortKeyAccesses:
		return sortLabelWithDirection("Accesses", false, sortState.reverse)
	case fileSortKeyRead:
		return sortLabelWithDirection("Read", false, sortState.reverse)
	case fileSortKeyWrite:
		return sortLabelWithDirection("Write", false, sortState.reverse)
	case fileSortKeyAvgLatency:
		return sortLabelWithDirection("Avg Latency", false, sortState.reverse)
	case fileSortKeyMaxLatency:
		return sortLabelWithDirection("Max Latency", false, sortState.reverse)
	case fileSortKeyPath:
		return sortLabelWithDirection("Path", true, sortState.reverse)
	default:
		return "default"
	}
}

func fileDirSortHint(sortState tableSortState[fileDirSortKey]) string {
	return "sort: " + fileDirSortLabel(sortState)
}

func fileDirSortLabel(sortState tableSortState[fileDirSortKey]) string {
	if !sortState.active {
		return "default"
	}
	switch sortState.key {
	case fileDirSortKeyAccesses:
		return sortLabelWithDirection("Accesses", false, sortState.reverse)
	case fileDirSortKeyRead:
		return sortLabelWithDirection("Read", false, sortState.reverse)
	case fileDirSortKeyWrite:
		return sortLabelWithDirection("Write", false, sortState.reverse)
	case fileDirSortKeyAvgLatency:
		return sortLabelWithDirection("Avg Latency", false, sortState.reverse)
	case fileDirSortKeyMaxLatency:
		return sortLabelWithDirection("Max Latency", false, sortState.reverse)
	case fileDirSortKeyFileCount:
		return sortLabelWithDirection("Files", false, sortState.reverse)
	case fileDirSortKeyDir:
		return sortLabelWithDirection("Directory", true, sortState.reverse)
	default:
		return "default"
	}
}

func findFileOffset(rows []statsengine.FileSnapshot, path string) (int, bool) {
	for idx, row := range rows {
		if row.Path == path {
			return idx, true
		}
	}
	return 0, false
}

func findDirOffset(rows []DirSnapshot, dir string) (int, bool) {
	for idx, row := range rows {
		if row.Dir == dir {
			return idx, true
		}
	}
	return 0, false
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
		s.TotalLatencyNs += f.TotalLatencyNs
		dirs[dir] = s
	}

	out := make([]DirSnapshot, 0, len(dirs))
	for _, s := range dirs {
		if s.Accesses > 0 {
			s.AvgLatencyNs = float64(s.TotalLatencyNs) / float64(s.Accesses)
		}
		out = append(out, s)
	}

	slices.SortFunc(out, func(a, b DirSnapshot) int {
		if a.Accesses != b.Accesses {
			return cmp.Compare(b.Accesses, a.Accesses)
		}
		return cmp.Compare(a.Dir, b.Dir)
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
