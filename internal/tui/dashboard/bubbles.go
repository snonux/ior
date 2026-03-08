package dashboard

import (
	"fmt"
	"hash/fnv"
	"image/color"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"ior/internal/statsengine"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/harmonica"
)

type bubbleMetric string

const (
	bubbleMetricCount bubbleMetric = "count"
	bubbleMetricBytes bubbleMetric = "bytes"
)

const (
	bubbleFPS             = 30
	bubbleAngularVelocity = 6.0
	bubbleDamping         = 1.0
	bubbleSpringEpsilon   = 0.01
	bubbleMaxItems        = 28
)

type bubbleDatum struct {
	ID     string
	Label  string
	Count  uint64
	Bytes  uint64
	Detail string
}

type bubbleNode struct {
	ID     string
	Label  string
	Detail string
	Count  uint64
	Bytes  uint64
	Value  uint64

	radiusSpring harmonica.Spring
	xSpring      harmonica.Spring
	ySpring      harmonica.Spring

	targetRadius float64
	anchorX      float64
	anchorY      float64
	targetX      float64
	targetY      float64

	radius float64
	x      float64
	y      float64

	velocityRadius float64
	velocityX      float64
	velocityY      float64

	driftPhase float64
	driftSpeed float64
	driftAmpX  float64
	driftAmpY  float64
}

type bubbleCell struct {
	char      rune
	colorSlot int
	bold      bool
}

type bubbleChart struct {
	nodes      []bubbleNode
	selected   int
	metric     bubbleMetric
	width      int
	height     int
	animating  bool
	statusHint string
	isDark     bool
	driftTime  float64
}

func newBubbleChart() bubbleChart {
	return bubbleChart{
		metric: bubbleMetricCount,
		isDark: true,
	}
}

func (c *bubbleChart) SetViewport(width, height int) {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 18
	}
	if c.width == width && c.height == height {
		return
	}
	c.width = width
	c.height = height
	if len(c.nodes) == 0 {
		return
	}
	data := make([]bubbleDatum, 0, len(c.nodes))
	for _, node := range c.nodes {
		data = append(data, bubbleDatum{
			ID:     node.ID,
			Label:  node.Label,
			Count:  node.Count,
			Bytes:  node.Bytes,
			Detail: node.Detail,
		})
	}
	c.SetData(data)
}

func (c *bubbleChart) SetMetric(metric bubbleMetric) {
	if metric != bubbleMetricBytes {
		metric = bubbleMetricCount
	}
	c.metric = metric
}

func (c *bubbleChart) Metric() bubbleMetric {
	if c.metric == bubbleMetricBytes {
		return bubbleMetricBytes
	}
	return bubbleMetricCount
}

func (c *bubbleChart) SetStatusHint(hint string) {
	c.statusHint = hint
}

func (c *bubbleChart) SetDarkMode(isDark bool) {
	c.isDark = isDark
}

func (c *bubbleChart) SetData(data []bubbleDatum) bool {
	targets := buildBubbleTargets(data, c.Metric(), c.width, c.height)

	selectedID := ""
	if c.selected >= 0 && c.selected < len(c.nodes) {
		selectedID = c.nodes[c.selected].ID
	}

	existing := make(map[string]bubbleNode, len(c.nodes))
	for _, node := range c.nodes {
		existing[node.ID] = node
	}

	next := make([]bubbleNode, 0, len(targets))
	for _, target := range targets {
		node := bubbleNode{
			ID:           target.ID,
			Label:        target.Label,
			Detail:       target.Detail,
			Count:        target.Count,
			Bytes:        target.Bytes,
			Value:        target.Value,
			targetRadius: target.targetRadius,
			anchorX:      target.targetX,
			anchorY:      target.targetY,
			targetX:      target.targetX,
			targetY:      target.targetY,
			radiusSpring: harmonica.NewSpring(harmonica.FPS(bubbleFPS), bubbleAngularVelocity, bubbleDamping),
			xSpring:      harmonica.NewSpring(harmonica.FPS(bubbleFPS), bubbleAngularVelocity, bubbleDamping),
			ySpring:      harmonica.NewSpring(harmonica.FPS(bubbleFPS), bubbleAngularVelocity, bubbleDamping),
		}
		if prev, ok := existing[target.ID]; ok {
			node.radius = prev.radius
			node.x = prev.x
			node.y = prev.y
			node.velocityRadius = prev.velocityRadius
			node.velocityX = prev.velocityX
			node.velocityY = prev.velocityY
			node.driftPhase = prev.driftPhase
			node.driftSpeed = prev.driftSpeed
			node.driftAmpX = prev.driftAmpX
			node.driftAmpY = prev.driftAmpY
			// New metrics or topology can otherwise produce stale springs.
			if node.radius == 0 {
				node.radius = target.targetRadius
			}
			if node.driftSpeed == 0 {
				c.initNodeDrift(&node)
			} else {
				c.updateNodeDriftAmplitude(&node)
			}
		} else {
			node.radius = target.targetRadius
			node.x = target.targetX
			node.y = target.targetY
			c.initNodeDrift(&node)
		}
		node.applyDrift(c.driftTime, c.width, c.height)
		next = append(next, node)
	}
	c.nodes = next
	if len(c.nodes) == 0 {
		c.selected = 0
		c.animating = false
		return false
	}
	c.selected = c.selectIndexByID(selectedID)
	c.animating = c.hasMotion()
	if c.animating {
		c.Tick(0)
	}
	return c.animating
}

func (c *bubbleChart) selectIndexByID(id string) int {
	if id == "" {
		return 0
	}
	for idx, node := range c.nodes {
		if node.ID == id {
			return idx
		}
	}
	return 0
}

func (c *bubbleChart) hasMotion() bool {
	for _, node := range c.nodes {
		if math.Abs(node.radius-node.targetRadius) > bubbleSpringEpsilon {
			return true
		}
		if math.Abs(node.x-node.targetX) > bubbleSpringEpsilon {
			return true
		}
		if math.Abs(node.y-node.targetY) > bubbleSpringEpsilon {
			return true
		}
		if math.Abs(node.velocityRadius) > bubbleSpringEpsilon ||
			math.Abs(node.velocityX) > bubbleSpringEpsilon ||
			math.Abs(node.velocityY) > bubbleSpringEpsilon {
			return true
		}
	}
	return false
}

func (c *bubbleChart) Tick(delta float64) bool {
	if len(c.nodes) == 0 {
		c.animating = false
		return false
	}
	baseDelta := harmonica.FPS(bubbleFPS)
	if delta <= 0 {
		delta = baseDelta
	}
	c.driftTime += delta

	active := false
	for idx := range c.nodes {
		node := &c.nodes[idx]
		node.applyDrift(c.driftTime, c.width, c.height)
		if delta != baseDelta {
			node.radiusSpring = harmonica.NewSpring(delta, bubbleAngularVelocity, bubbleDamping)
			node.xSpring = harmonica.NewSpring(delta, bubbleAngularVelocity, bubbleDamping)
			node.ySpring = harmonica.NewSpring(delta, bubbleAngularVelocity, bubbleDamping)
		}
		node.radius, node.velocityRadius = node.radiusSpring.Update(node.radius, node.velocityRadius, node.targetRadius)
		node.x, node.velocityX = node.xSpring.Update(node.x, node.velocityX, node.targetX)
		node.y, node.velocityY = node.ySpring.Update(node.y, node.velocityY, node.targetY)
		if c.nodeAnimating(*node) {
			active = true
		}
	}
	c.animating = active
	return active
}

func (c *bubbleChart) nodeAnimating(node bubbleNode) bool {
	if math.Abs(node.radius-node.targetRadius) > bubbleSpringEpsilon {
		return true
	}
	if math.Abs(node.x-node.targetX) > bubbleSpringEpsilon {
		return true
	}
	if math.Abs(node.y-node.targetY) > bubbleSpringEpsilon {
		return true
	}
	if math.Abs(node.velocityRadius) > bubbleSpringEpsilon ||
		math.Abs(node.velocityX) > bubbleSpringEpsilon ||
		math.Abs(node.velocityY) > bubbleSpringEpsilon {
		return true
	}
	return false
}

func (c *bubbleChart) initNodeDrift(node *bubbleNode) {
	if node == nil {
		return
	}
	h := stableHash(node.ID)
	node.driftPhase = float64(h%628) / 100.0
	node.driftSpeed = 0.12 + float64((h>>8)%35)/1000.0
	c.updateNodeDriftAmplitude(node)
}

func (c *bubbleChart) updateNodeDriftAmplitude(node *bubbleNode) {
	if node == nil {
		return
	}
	h := stableHash(node.ID)
	baseAmp := clampFloat(node.targetRadius*0.32, 0.45, 1.8)
	node.driftAmpX = baseAmp * (0.85 + float64((h>>16)%31)/100.0)
	node.driftAmpY = baseAmp * 0.75 * (0.85 + float64((h>>24)%31)/100.0)
}

func (n *bubbleNode) applyDrift(t float64, width, height int) {
	if n == nil {
		return
	}
	phase := n.driftPhase + t*n.driftSpeed
	n.targetX = n.anchorX + math.Sin(phase)*n.driftAmpX
	n.targetY = n.anchorY + math.Cos(phase*0.91+0.37)*n.driftAmpY

	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 18
	}
	minX := n.targetRadius + 1.0
	maxX := float64(width-1) - n.targetRadius - 1.0
	minY := n.targetRadius
	maxY := float64(height-1) - n.targetRadius
	n.targetX = clampFloat(n.targetX, minX, maxX)
	n.targetY = clampFloat(n.targetY, minY, maxY)
}

func stableHash(value string) uint32 {
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(value))
	return hasher.Sum32()
}

func (c *bubbleChart) MoveSelection(delta int) bool {
	if len(c.nodes) == 0 {
		return false
	}
	next := c.selected + delta
	if next < 0 {
		next = 0
	}
	if next >= len(c.nodes) {
		next = len(c.nodes) - 1
	}
	if next == c.selected {
		return false
	}
	c.selected = next
	return true
}

func (c bubbleChart) HasNodes() bool {
	return len(c.nodes) > 0
}

func (c *bubbleChart) Render(tabLabel string, width, height int) string {
	if width <= 0 {
		width = c.width
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = c.height
	}
	if height <= 0 {
		height = 18
	}
	header := fmt.Sprintf("%s bubbles | metric:%s | v mode | b metric | j/k select", tabLabel, c.metricLabel())
	if len(c.nodes) == 0 {
		body := "No data yet."
		if c.statusHint != "" {
			body = c.statusHint
		}
		return header + "\n" + body + "\n" + "sel: none"
	}

	chartHeight := height - 2
	if chartHeight < 4 {
		chartHeight = 4
	}
	grid := make([][]bubbleCell, chartHeight)
	for row := 0; row < chartHeight; row++ {
		grid[row] = make([]bubbleCell, width)
		for col := range grid[row] {
			grid[row][col] = bubbleCell{
				char:      ' ',
				colorSlot: -1,
			}
		}
	}
	c.renderBubblesToGrid(grid, width, chartHeight)
	lines := make([]string, 0, chartHeight+2)
	lines = append(lines, padOrTrim(header, width))
	palette := c.palette()
	for _, row := range grid {
		lines = append(lines, renderBubbleRow(row, palette))
	}
	lines = append(lines, padOrTrim(c.statusLine(width), width))
	return strings.Join(lines, "\n")
}

func (c *bubbleChart) renderBubblesToGrid(grid [][]bubbleCell, width, height int) {
	order := make([]int, 0, len(c.nodes))
	for idx := range c.nodes {
		order = append(order, idx)
	}
	sort.Slice(order, func(i, j int) bool {
		return c.nodes[order[i]].radius < c.nodes[order[j]].radius
	})
	if c.selected >= 0 && c.selected < len(c.nodes) {
		filtered := order[:0]
		for _, idx := range order {
			if idx != c.selected {
				filtered = append(filtered, idx)
			}
		}
		order = append(filtered, c.selected)
	}

	for _, idx := range order {
		node := c.nodes[idx]
		drawBubble(grid, width, height, node, idx == c.selected, idx)
	}

	for idx, node := range c.nodes {
		drawBubbleLabel(grid, width, height, node, idx == c.selected, idx)
	}
}

func drawBubble(grid [][]bubbleCell, width, height int, node bubbleNode, selected bool, colorSlot int) {
	if len(grid) == 0 || width == 0 || height == 0 {
		return
	}
	radius := node.radius
	if radius < 1.0 {
		radius = 1.0
	}
	cx := int(math.Round(node.x))
	cy := int(math.Round(node.y))
	minX := maxInt(0, int(math.Floor(float64(cx)-radius)))
	maxX := minInt(width-1, int(math.Ceil(float64(cx)+radius)))
	minY := maxInt(0, int(math.Floor(float64(cy)-radius)))
	maxY := minInt(height-1, int(math.Ceil(float64(cy)+radius)))
	fill := '█'
	innerFill := fill
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			dx := float64(x - cx)
			dy := float64(y - cy)
			dist := math.Sqrt(dx*dx + dy*dy)
			switch {
			case dist <= radius-0.65:
				grid[y][x] = bubbleCell{char: fill, colorSlot: colorSlot, bold: selected}
			case dist <= radius:
				grid[y][x] = bubbleCell{char: innerFill, colorSlot: colorSlot, bold: selected}
			}
		}
	}
}

func drawBubbleLabel(grid [][]bubbleCell, width, height int, node bubbleNode, selected bool, colorSlot int) {
	if len(grid) == 0 || width == 0 || height == 0 {
		return
	}
	maxLabelRunes := maxInt(2, int(math.Round(node.radius*1.6)))
	label := abbreviateLabel(node.Label, maxLabelRunes)
	if selected {
		label = "[" + abbreviateLabel(node.Label, maxInt(1, maxLabelRunes-2)) + "]"
	}
	cx := int(math.Round(node.x))
	cy := int(math.Round(node.y))
	if cy < 0 || cy >= height {
		return
	}
	labelRunes := []rune(label)
	start := cx - len(labelRunes)/2
	for idx, r := range labelRunes {
		x := start + idx
		if x < 0 || x >= width {
			continue
		}
		grid[cy][x] = bubbleCell{char: r, colorSlot: colorSlot, bold: selected}
	}
}

func abbreviateLabel(label string, maxRunes int) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return "?"
	}
	if maxRunes <= 0 {
		return ""
	}
	if utf8.RuneCountInString(label) <= maxRunes {
		return label
	}
	if maxRunes == 1 {
		return "…"
	}
	r := []rune(label)
	return string(r[:maxRunes-1]) + "…"
}

func (c *bubbleChart) statusLine(width int) string {
	if len(c.nodes) == 0 {
		return padOrTrim("sel: none", width)
	}
	if c.selected < 0 {
		c.selected = 0
	}
	if c.selected >= len(c.nodes) {
		c.selected = len(c.nodes) - 1
	}
	node := c.nodes[c.selected]
	metricText := fmt.Sprintf("%s=%s", c.metricLabel(), c.formatMetricValue(node))
	base := fmt.Sprintf("sel:%d/%d %s | %s | bytes=%s", c.selected+1, len(c.nodes), node.Label, metricText, formatBytes(float64(node.Bytes)))
	if c.statusHint != "" {
		base += " | " + c.statusHint
	}
	if node.Detail != "" {
		base += " | " + node.Detail
	}
	return padOrTrim(base, width)
}

func (c *bubbleChart) metricLabel() string {
	if c.Metric() == bubbleMetricBytes {
		return "bytes"
	}
	return "events"
}

func (c *bubbleChart) formatMetricValue(node bubbleNode) string {
	if c.Metric() == bubbleMetricBytes {
		return formatBytes(float64(node.Bytes))
	}
	return fmt.Sprintf("%d", node.Count)
}

func (c *bubbleChart) palette() []color.Color {
	if c.isDark {
		return []color.Color{
			lipgloss.Color("81"),
			lipgloss.Color("75"),
			lipgloss.Color("117"),
			lipgloss.Color("186"),
			lipgloss.Color("214"),
			lipgloss.Color("177"),
			lipgloss.Color("39"),
			lipgloss.Color("203"),
		}
	}
	return []color.Color{
		lipgloss.Color("24"),
		lipgloss.Color("31"),
		lipgloss.Color("30"),
		lipgloss.Color("64"),
		lipgloss.Color("94"),
		lipgloss.Color("130"),
		lipgloss.Color("161"),
		lipgloss.Color("25"),
	}
}

func renderBubbleRow(cells []bubbleCell, palette []color.Color) string {
	if len(cells) == 0 {
		return ""
	}
	var b strings.Builder
	styleCache := make(map[string]lipgloss.Style, 8)
	selectedColor := lipgloss.Color("129")
	for _, cell := range cells {
		if cell.colorSlot < 0 {
			if cell.bold {
				b.WriteString(lipgloss.NewStyle().Bold(true).Render(string(cell.char)))
			} else {
				b.WriteRune(cell.char)
			}
			continue
		}
		slot := cell.colorSlot
		if len(palette) > 0 {
			slot = slot % len(palette)
		}
		key := fmt.Sprintf("%d/%t", slot, cell.bold)
		style, ok := styleCache[key]
		if !ok {
			style = lipgloss.NewStyle().Foreground(palette[slot])
			if cell.bold {
				style = style.Foreground(selectedColor)
			}
			if cell.bold {
				style = style.Bold(true)
			}
			styleCache[key] = style
		}
		b.WriteString(style.Render(string(cell.char)))
	}
	return b.String()
}

func buildBubbleTargets(data []bubbleDatum, metric bubbleMetric, width, height int) []bubbleNode {
	if len(data) == 0 {
		return nil
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 18
	}
	chartHeight := height - 2
	if chartHeight < 4 {
		chartHeight = 4
	}
	filtered := make([]bubbleDatum, 0, len(data))
	for _, datum := range data {
		if datum.ID == "" {
			continue
		}
		filtered = append(filtered, datum)
	}
	if len(filtered) == 0 {
		return nil
	}
	sort.Slice(filtered, func(i, j int) bool {
		vi := bubbleValue(filtered[i], metric)
		vj := bubbleValue(filtered[j], metric)
		if vi != vj {
			return vi > vj
		}
		return filtered[i].Label < filtered[j].Label
	})
	if len(filtered) > bubbleMaxItems {
		filtered = filtered[:bubbleMaxItems]
	}
	maxValue := uint64(0)
	for _, datum := range filtered {
		value := bubbleValue(datum, metric)
		if value > maxValue {
			maxValue = value
		}
	}
	if maxValue == 0 {
		maxValue = 1
	}
	minRadius := 1.7
	maxRadius := math.Min(float64(width)/6.0, float64(chartHeight)/2.6)
	if maxRadius < 2.4 {
		maxRadius = 2.4
	}
	targets := make([]bubbleNode, 0, len(filtered))
	cx := float64(width-1) / 2.0
	cy := float64(chartHeight-1) / 2.0
	goldenAngle := math.Pi * (3.0 - math.Sqrt(5.0))
	spacingBase := maxRadius * 0.95
	for idx, datum := range filtered {
		value := bubbleValue(datum, metric)
		ratio := math.Sqrt(float64(value) / float64(maxValue))
		targetRadius := minRadius + ratio*(maxRadius-minRadius)
		distance := spacingBase * math.Sqrt(float64(idx)+0.6)
		angle := float64(idx) * goldenAngle
		targetX := cx + math.Cos(angle)*distance
		targetY := cy + math.Sin(angle)*distance*0.68
		targets = append(targets, bubbleNode{
			ID:           datum.ID,
			Label:        datum.Label,
			Detail:       datum.Detail,
			Count:        datum.Count,
			Bytes:        datum.Bytes,
			Value:        value,
			targetRadius: targetRadius,
			targetX:      targetX,
			targetY:      targetY,
		})
	}
	relaxTargets(targets, width, chartHeight)
	return targets
}

func relaxTargets(nodes []bubbleNode, width, height int) {
	if len(nodes) <= 1 {
		for idx := range nodes {
			clampNodeToViewport(&nodes[idx], width, height)
		}
		return
	}
	for iter := 0; iter < 28; iter++ {
		for left := 0; left < len(nodes); left++ {
			for right := left + 1; right < len(nodes); right++ {
				a := &nodes[left]
				b := &nodes[right]
				dx := b.targetX - a.targetX
				dy := b.targetY - a.targetY
				distSq := dx*dx + dy*dy
				minDist := a.targetRadius + b.targetRadius + 0.8
				if distSq >= minDist*minDist {
					continue
				}
				if distSq < 0.0001 {
					dx = 0.01
					dy = 0.01
					distSq = dx*dx + dy*dy
				}
				dist := math.Sqrt(distSq)
				overlap := (minDist - dist) / 2.0
				nx := dx / dist
				ny := dy / dist
				a.targetX -= nx * overlap
				a.targetY -= ny * overlap
				b.targetX += nx * overlap
				b.targetY += ny * overlap
			}
		}
		for idx := range nodes {
			clampNodeToViewport(&nodes[idx], width, height)
		}
	}
}

func clampNodeToViewport(node *bubbleNode, width, height int) {
	minX := node.targetRadius + 1.0
	maxX := float64(width-1) - node.targetRadius - 1.0
	minY := node.targetRadius
	maxY := float64(height-1) - node.targetRadius
	if maxX < minX {
		mid := float64(width-1) / 2.0
		node.targetX = mid
	} else {
		node.targetX = clampFloat(node.targetX, minX, maxX)
	}
	if maxY < minY {
		mid := float64(height-1) / 2.0
		node.targetY = mid
	} else {
		node.targetY = clampFloat(node.targetY, minY, maxY)
	}
}

func clampFloat(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func bubbleValue(d bubbleDatum, metric bubbleMetric) uint64 {
	if metric == bubbleMetricBytes {
		return d.Bytes
	}
	return d.Count
}

func syscallBubbleData(snap *statsengine.Snapshot) []bubbleDatum {
	if snap == nil {
		return nil
	}
	rows := snap.Syscalls()
	data := make([]bubbleDatum, 0, len(rows))
	for _, syscall := range rows {
		detail := fmt.Sprintf("rate %.1f/s, errors %d, p95 %s", syscall.RatePerSec, syscall.Errors, formatDurationUintNs(syscall.LatencyP95Ns))
		data = append(data, bubbleDatum{
			ID:     syscall.Name,
			Label:  syscall.Name,
			Count:  syscall.Count,
			Bytes:  syscall.Bytes,
			Detail: detail,
		})
	}
	return data
}

func filesDirBubbleData(snap *statsengine.Snapshot) []bubbleDatum {
	if snap == nil {
		return nil
	}
	dirs := aggregateFilesByDir(snap.Files())
	data := make([]bubbleDatum, 0, len(dirs))
	for _, dir := range dirs {
		totalBytes := dir.BytesRead + dir.BytesWritten
		detail := fmt.Sprintf("dir %s, files %d, read %s, write %s", dir.Dir, dir.FileCount, formatBytes(float64(dir.BytesRead)), formatBytes(float64(dir.BytesWritten)))
		data = append(data, bubbleDatum{
			ID:     dir.Dir,
			Label:  rootPathLabelFromFSPath(dir.Dir),
			Count:  dir.Accesses,
			Bytes:  totalBytes,
			Detail: detail,
		})
	}
	return data
}

func processBubbleData(snap *statsengine.Snapshot) []bubbleDatum {
	if snap == nil {
		return nil
	}
	rows := snap.Processes()
	data := make([]bubbleDatum, 0, len(rows))
	for _, proc := range rows {
		label := fmt.Sprintf("%d", proc.PID)
		if comm := strings.TrimSpace(proc.Comm); comm != "" {
			label = fmt.Sprintf("%d:%s", proc.PID, comm)
		}
		detail := fmt.Sprintf("pid %d, rate %.1f/s, avg %s", proc.PID, proc.RatePerSec, formatDurationNs(proc.AvgLatencyNs))
		data = append(data, bubbleDatum{
			ID:     fmt.Sprintf("%d/%s", proc.PID, proc.Comm),
			Label:  label,
			Count:  proc.Syscalls,
			Bytes:  proc.Bytes,
			Detail: detail,
		})
	}
	return data
}

func padOrTrim(value string, width int) string {
	if width <= 0 {
		return value
	}
	value = truncatePlain(value, width)
	padding := width - utf8.RuneCountInString(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
