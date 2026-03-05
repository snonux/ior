package flamegraph

import (
	"hash/fnv"
	"image/color"
	"math"
	"strings"
)

const pathSeparator = "\x1f"

// BuildTerminalLayout converts a live trie snapshot into terminal frame cells.
func BuildTerminalLayout(snapshot *snapshotNode, width, height int) []tuiFrame {
	if snapshot == nil || width <= 0 || height <= 0 {
		return nil
	}
	rootTotal := snapshotTotal(snapshot)
	if rootTotal == 0 {
		return nil
	}

	rootName := frameName(snapshot.Name, 0)
	frames := make([]tuiFrame, 0, len(snapshot.Children)+1)
	collectTerminalLayout(&frames, snapshot, rootTotal, width, height, 0, 0, rootName)
	return frames
}

func collectTerminalLayout(out *[]tuiFrame, node *snapshotNode, rootTotal uint64, width, height, depth, col int, path string) {
	if node == nil || depth >= height {
		return
	}
	total := snapshotTotal(node)
	frameWidth := int(math.Floor(float64(width) * (float64(total) / float64(rootTotal))))
	if frameWidth < 1 {
		return
	}

	name := frameName(node.Name, depth)
	*out = append(*out, tuiFrame{
		Name:    name,
		Col:     col,
		Row:     depth,
		Width:   frameWidth,
		Total:   total,
		Percent: 100 * float64(total) / float64(rootTotal),
		Fill:    terminalFrameColor(name),
		Depth:   depth,
		Path:    path,
	})

	cursor := col
	for _, child := range node.Children {
		childTotal := snapshotTotal(child)
		childWidth := int(math.Floor(float64(width) * (float64(childTotal) / float64(rootTotal))))
		if childWidth < 1 {
			continue
		}
		childName := frameName(child.Name, depth+1)
		childPath := strings.Join([]string{path, childName}, pathSeparator)
		collectTerminalLayout(out, child, rootTotal, width, height, depth+1, cursor, childPath)
		cursor += childWidth
	}
}

func snapshotTotal(node *snapshotNode) uint64 {
	if node == nil {
		return 0
	}
	total := node.Value
	for _, child := range node.Children {
		total += snapshotTotal(child)
	}
	if node.Total > total {
		return node.Total
	}
	return total
}

func frameName(name string, depth int) string {
	if name != "" {
		return name
	}
	if depth == 0 {
		return "root"
	}
	return "(unknown)"
}

func terminalFrameColor(name string) color.Color {
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(name))
	h := hasher.Sum32()
	return color.RGBA{
		R: uint8(200 + int(h%35)),
		G: uint8(80 + int((h>>8)%120)),
		B: uint8(40 + int((h>>16)%90)),
		A: 255,
	}
}
