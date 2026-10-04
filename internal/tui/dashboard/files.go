package dashboard

import (
	"fmt"
	"strconv"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

// DirSnapshot is one aggregated directory row of the Files tab's dir-grouped
// view: the directory's access, byte, latency and file-count totals. The
// stats engine ranks directories over all traffic (not only the top-N
// files), and its remainder row - the directories outside the top-N summed
// up - is a DirSnapshot with Folded > 0 (see DirSnapshot.IsRemainder).
type DirSnapshot = statsengine.DirSnapshot

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

// renderFilesWithSort renders the per-file table. Every line is at most width
// cells wide: the placeholders are cut, the table is fitted by
// renderSelectableTable (fileTableSpec), which also cuts each shown path to
// its column, keeping both ends.
func renderFilesWithSort(snap *statsengine.Snapshot, width, height, offset, selectedCol int, sortState tableSortState[fileSortKey]) string {
	if snap == nil {
		return fitTableLine("Files: waiting for stats...", width)
	}

	rows := fileRows(sortedFileSnapshots(snap.Files(), sortState))
	if len(rows) == 0 {
		return fitTableLine("Files: no data", width)
	}

	return renderSelectableTable(
		fileTableSpec(width),
		rows,
		width,
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

// renderFilesDirGroupedWithSort renders the dir-grouped table, fitted to the
// width like renderFilesWithSort (fileDirTableSpec).
func renderFilesDirGroupedWithSort(snap *statsengine.Snapshot, width, height, offset, selectedCol int, sortState tableSortState[fileDirSortKey]) string {
	if snap == nil {
		return fitTableLine("Files (dirs): waiting for stats...", width)
	}

	rows := dirRows(sortedDirSnapshots(snapshotDirRows(snap), sortState))
	if len(rows) == 0 {
		return fitTableLine("Files (dirs): no data", width)
	}

	return renderSelectableTable(
		fileDirTableSpec(width),
		rows,
		width,
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

// fileRows returns the per-file table rows. The path cell is the whole
// sanitised path: renderSelectableTable cuts it (truncatePathMiddle) to the
// width its column gets on the terminal, which only the fit knows.
func fileRows(files []statsengine.FileSnapshot) [][]string {
	rows := make([][]string, 0, len(files))
	for _, f := range files {
		rows = append(rows, []string{
			strconv.FormatUint(f.Accesses, 10),
			formatBytes(float64(f.BytesRead)),
			formatBytes(float64(f.BytesWritten)),
			formatDurationNs(f.AvgLatencyNs),
			formatDurationUintNs(f.MaxLatencyNs),
			common.Sanitize(f.Path),
		})
	}
	return rows
}

// filePathWidth is the natural width of the Path column: whatever the 48
// cells of metric columns and their separators leave, at least 14 cells (so
// the natural row is width-5 cells from 72 columns up and 67 below; narrower
// terminals are fitted by fileTableSpec's policy).
func filePathWidth(width int) int {
	if width <= 0 {
		return 24
	}
	w := width - 58
	if w < 14 {
		return 14
	}
	return w
}

// dirPathWidth is filePathWidth for the dir-grouped table, whose extra 5-cell
// Files column (+1 separator) it reserves as well.
func dirPathWidth(width int) int {
	if width <= 0 {
		return 24
	}
	w := width - 64
	if w < 14 {
		return 14
	}
	return w
}

// fileColumns returns the logical per-file columns at their natural widths;
// their indexes are what fileSortKeyForColumn and the selection refer to.
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

// fileDirColumns returns the logical dir-grouped columns at their natural
// widths; their indexes are what fileDirSortKeyForColumn refers to.
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

// filePathMinWidth is the narrowest a Path or Directory column gets before
// the table gives way to its notice: "/da...ile0" still shows both ends.
const filePathMinWidth = 10

// fileTableSpec is the per-file table with its narrow-terminal policy
// (fitTableColumns): Max Latency goes first, then Write, Read and Avg
// Latency; Accesses and the path (cut in the middle, down to
// filePathMinWidth) are required.
func fileTableSpec(width int) tableSpec {
	return tableSpec{
		title:   "Files",
		columns: fileColumns(width),
		flex:    5,
		flexMin: filePathMinWidth,
		cut:     truncatePathMiddle,
		// 0 Accesses, 1 Read, 2 Write, 3 Avg Latency, 4 Max Latency, 5 Path.
		dropOrder: []int{4, 2, 1, 3},
	}
}

// fileDirTableSpec is fileTableSpec for the dir-grouped table, which drops
// its extra Files count after Read and before Avg Latency.
func fileDirTableSpec(width int) tableSpec {
	return tableSpec{
		title:   "Files (dirs)",
		columns: fileDirColumns(width),
		flex:    6,
		flexMin: filePathMinWidth,
		cut:     truncatePathMiddle,
		// 0 Accesses, 1 Read, 2 Write, 3 Avg Latency, 4 Max Latency,
		// 5 Files, 6 Directory.
		dropOrder: []int{4, 2, 1, 5, 3},
	}
}

func sortedFileSnapshots(rows []statsengine.FileSnapshot, sortState tableSortState[fileSortKey]) []statsengine.FileSnapshot {
	return sortedWithState(rows, sortState, compareFileBySort, compareFileDefault)
}

// sortedDirSnapshots orders the dir-grouped rows by the sort state. The
// remainder row is not a directory to rank against the others - it is their
// leftover - so it stays last whatever the sort key and direction.
func sortedDirSnapshots(rows []DirSnapshot, sortState tableSortState[fileDirSortKey]) []DirSnapshot {
	dirs := rows
	var remainder []DirSnapshot
	if n := len(rows); n > 0 && rows[n-1].IsRemainder() {
		dirs, remainder = rows[:n-1], rows[n-1:]
	}
	sorted := sortedWithState(dirs, sortState, compareDirBySort, compareDirDefault)
	if len(remainder) == 0 {
		return sorted
	}
	out := make([]DirSnapshot, 0, len(sorted)+1)
	return append(append(out, sorted...), remainder...)
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

// truncatePathMiddle sanitises the traced path (common.Sanitize: no escape
// sequences reach the terminal) and shortens it to at most limit display
// cells, keeping both ends joined by "...". It delegates to common.TruncateMiddle, which cuts
// on grapheme boundaries so multi-byte (e.g. CJK) paths stay valid UTF-8.
func truncatePathMiddle(path string, limit int) string {
	return common.TruncateMiddle(common.Sanitize(path), limit, common.ASCIIEllipsis)
}

// noDirGroup is the Dir of the dir-grouped row collecting every name without
// a separator (see statsengine.NoDirGroup). The engine groups files by
// statsengine.DirOf, the same literal-directory rule the row filter's
// directory-children pattern uses (globalfilter.DirPattern), so a row's
// filter selects exactly the files the row counts.
const noDirGroup = statsengine.NoDirGroup

// remainderDirKey is the selection identity of the remainder row. A real
// directory key is a path, which cannot contain NUL, so it never collides
// with one - whatever the traced directories are called.
const remainderDirKey = "\x00other"

// dirKey is the stable identity of a dir-grouped row: the literal directory
// text, or remainderDirKey for the remainder row.
func dirKey(d DirSnapshot) string {
	if d.IsRemainder() {
		return remainderDirKey
	}
	return d.Dir
}

// dirDisplayLabel is the display text of a dir-grouped row: the sanitised
// directory, or "(other: N dirs)" for the remainder row.
func dirDisplayLabel(d DirSnapshot) string {
	if d.IsRemainder() {
		return fmt.Sprintf("(other: %d dirs)", d.Folded)
	}
	return dirRowLabel(d.Dir)
}

// snapshotDirRows returns the dir-grouped rows of a snapshot: the engine's
// top-N directories followed by the remainder row when directories fell
// outside the top-N. The result is a fresh slice the caller may reorder.
func snapshotDirRows(snap *statsengine.Snapshot) []DirSnapshot {
	if snap == nil {
		return nil
	}
	dirs := snap.Dirs()
	other, hasOther := snap.DirsOther()
	if len(dirs) == 0 && !hasOther {
		return nil
	}
	rows := make([]DirSnapshot, 0, len(dirs)+1)
	rows = append(rows, dirs...)
	if hasOther {
		rows = append(rows, other)
	}
	return rows
}

// dirRows returns the dir-grouped table rows; like fileRows, the directory
// cell is the whole (sanitised) label, cut to its column when rendered.
func dirRows(dirs []DirSnapshot) [][]string {
	rows := make([][]string, 0, len(dirs))
	for _, d := range dirs {
		rows = append(rows, []string{
			strconv.FormatUint(d.Accesses, 10),
			formatBytes(float64(d.BytesRead)),
			formatBytes(float64(d.BytesWritten)),
			formatDurationNs(d.AvgLatencyNs),
			formatDurationUintNs(d.MaxLatencyNs),
			strconv.FormatUint(d.FileCount, 10),
			dirDisplayLabel(d),
		})
	}
	return rows
}
