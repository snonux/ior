package dashboard

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"

	"ior/internal/statsengine"
)

type icicleNode struct {
	name     string
	fullPath string
	accesses uint64
	bytes    uint64
	children map[string]*icicleNode
}

type icicleTile struct {
	node      *icicleNode
	depth     int
	x         int
	w         int
	colorSlot int
}

func renderFilesIcicle(snap *statsengine.Snapshot, width, height int, metric bubbleMetric, selected int, isDark bool) string {
	if snap == nil {
		return "Files icicle: waiting for stats..."
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 18
	}
	header := fmt.Sprintf("Files icicle | metric:%s | v mode | b metric | j/k select", treemapMetricLabel(metric))
	dirs := aggregateFilesByDir(snap.Files())
	if len(dirs) == 0 {
		return header + "\nFiles icicle: no directory data\nsel: none"
	}

	root := buildIcicleTree(dirs)
	children := sortedIcicleChildren(root, metric)
	if len(children) == 0 {
		return header + "\nFiles icicle: no directory data\nsel: none"
	}

	chartHeight := height - 2
	if chartHeight < 4 {
		chartHeight = 4
	}

	tiles := make([]icicleTile, 0, 64)
	layoutIcicle(children, 0, width, 0, chartHeight, 0, metric, &tiles)
	if len(tiles) == 0 {
		return header + "\nFiles icicle: no visible tiles\nsel: none"
	}

	selected = clampOffset(selected, len(tiles))
	grid := make([][]treemapCell, chartHeight)
	for row := 0; row < chartHeight; row++ {
		grid[row] = make([]treemapCell, width)
		for col := range grid[row] {
			grid[row][col] = treemapCell{char: ' ', colorSlot: -1}
		}
	}
	fillIcicleGrid(grid, tiles, selected)
	palette := treemapPalette(isDark)

	lines := make([]string, 0, chartHeight+2)
	lines = append(lines, padOrTrim(header, width))
	for _, row := range grid {
		lines = append(lines, renderTreemapRow(row, palette))
	}
	lines = append(lines, padOrTrim(icicleStatusLine(tiles, selected, metric), width))
	return strings.Join(lines, "\n")
}

func buildIcicleTree(dirs []DirSnapshot) *icicleNode {
	root := &icicleNode{
		name:     "/",
		fullPath: "/",
		children: make(map[string]*icicleNode),
	}
	for _, dir := range dirs {
		segments := splitIcicleSegments(dir.Dir)
		current := root
		metricBytes := dir.BytesRead + dir.BytesWritten
		current.accesses += dir.Accesses
		current.bytes += metricBytes
		currentPath := "/"
		for _, segment := range segments {
			if segment == "" {
				continue
			}
			if currentPath == "/" {
				currentPath = "/" + segment
			} else {
				currentPath = currentPath + "/" + segment
			}
			child := current.children[segment]
			if child == nil {
				child = &icicleNode{
					name:     segment,
					fullPath: currentPath,
					children: make(map[string]*icicleNode),
				}
				current.children[segment] = child
			}
			child.accesses += dir.Accesses
			child.bytes += metricBytes
			current = child
		}
	}
	return root
}

func splitIcicleSegments(dir string) []string {
	cleaned := filepath.Clean(strings.TrimSpace(dir))
	if cleaned == "." || cleaned == "/" || cleaned == "" {
		return nil
	}
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" {
		return nil
	}
	return strings.Split(cleaned, "/")
}

func sortedIcicleChildren(node *icicleNode, metric bubbleMetric) []*icicleNode {
	if node == nil || len(node.children) == 0 {
		return nil
	}
	out := make([]*icicleNode, 0, len(node.children))
	for _, child := range node.children {
		out = append(out, child)
	}
	sort.Slice(out, func(i, j int) bool {
		vi := icicleValue(out[i], metric)
		vj := icicleValue(out[j], metric)
		if vi != vj {
			return vi > vj
		}
		return out[i].name < out[j].name
	})
	return out
}

func layoutIcicle(nodes []*icicleNode, x, width, depth, maxDepth, rootSlot int, metric bubbleMetric, out *[]icicleTile) {
	if len(nodes) == 0 || width <= 0 || depth >= maxDepth {
		return
	}
	total := uint64(0)
	for _, node := range nodes {
		total += icicleValue(node, metric)
	}
	if total == 0 {
		return
	}

	remainingWidth := width
	remainingValue := total
	cursor := x
	for idx, node := range nodes {
		value := icicleValue(node, metric)
		tileWidth := remainingWidth
		if idx < len(nodes)-1 {
			tileWidth = int(math.Round(float64(remainingWidth) * float64(value) / float64(remainingValue)))
			minRemaining := len(nodes) - idx - 1
			if tileWidth < 1 {
				tileWidth = 1
			}
			if tileWidth > remainingWidth-minRemaining {
				tileWidth = remainingWidth - minRemaining
			}
		}
		if tileWidth <= 0 {
			continue
		}
		colorSlot := rootSlot
		if depth == 0 {
			colorSlot = idx
		}
		*out = append(*out, icicleTile{
			node:      node,
			depth:     depth,
			x:         cursor,
			w:         tileWidth,
			colorSlot: colorSlot,
		})
		if depth+1 < maxDepth {
			layoutIcicle(sortedIcicleChildren(node, metric), cursor, tileWidth, depth+1, maxDepth, colorSlot, metric, out)
		}

		cursor += tileWidth
		remainingWidth -= tileWidth
		remainingValue -= value
		if remainingWidth <= 0 {
			break
		}
	}
}

func fillIcicleGrid(grid [][]treemapCell, tiles []icicleTile, selected int) {
	height := len(grid)
	if height == 0 {
		return
	}
	width := len(grid[0])
	if width == 0 {
		return
	}
	for idx, tile := range tiles {
		if tile.depth < 0 || tile.depth >= height {
			continue
		}
		isSelected := idx == selected
		for col := tile.x; col < minInt(width, tile.x+tile.w); col++ {
			if col < 0 {
				continue
			}
			grid[tile.depth][col] = treemapCell{
				char:      '█',
				colorSlot: tile.colorSlot,
				bold:      isSelected,
			}
		}
		drawIcicleLabel(grid, tile, isSelected)
	}
}

func drawIcicleLabel(grid [][]treemapCell, tile icicleTile, selected bool) {
	height := len(grid)
	if height == 0 || tile.depth < 0 || tile.depth >= height || tile.w <= 1 {
		return
	}
	width := len(grid[0])
	maxLabel := tile.w - 1
	label := abbreviateTreemapLabel(rootPathLabelFromFSPath(tile.node.fullPath), maxLabel)
	col := tile.x
	for _, r := range []rune(label) {
		if col < 0 {
			col++
			continue
		}
		if col >= width {
			break
		}
		grid[tile.depth][col] = treemapCell{
			char:      r,
			colorSlot: tile.colorSlot,
			bold:      selected,
		}
		col++
	}
}

func icicleStatusLine(tiles []icicleTile, selected int, metric bubbleMetric) string {
	if len(tiles) == 0 {
		return "sel:none"
	}
	selected = clampOffset(selected, len(tiles))
	tile := tiles[selected]
	metricValue := icicleValue(tile.node, metric)
	metricText := fmt.Sprintf("%d", metricValue)
	if metric == bubbleMetricBytes {
		metricText = formatBytes(float64(metricValue))
	}
	return fmt.Sprintf(
		"sel:%d/%d %s | %s=%s | accesses=%d | bytes=%s",
		selected+1,
		len(tiles),
		rootPathLabelFromFSPath(tile.node.fullPath),
		treemapMetricLabel(metric),
		metricText,
		tile.node.accesses,
		formatBytes(float64(tile.node.bytes)),
	)
}

func icicleValue(node *icicleNode, metric bubbleMetric) uint64 {
	if node == nil {
		return 0
	}
	if metric == bubbleMetricBytes {
		return node.bytes
	}
	return node.accesses
}
