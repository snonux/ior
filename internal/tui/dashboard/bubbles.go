package dashboard

import (
	"cmp"
	"fmt"
	"hash/fnv"
	"image/color"
	"math"
	"slices"
	"strings"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/harmonica"
)

type bubbleMetric string

const (
	bubbleMetricCount    bubbleMetric = "count"
	bubbleMetricBytes    bubbleMetric = "bytes"
	bubbleMetricDuration bubbleMetric = "duration"
)

const (
	bubbleFPS             = 30
	bubbleAngularVelocity = 6.0
	bubbleDamping         = 1.0
	bubbleSpringEpsilon   = 0.01
	bubbleMaxItems        = 28

	// bubbleDriftSeconds is how long the ambient drift wobble keeps running
	// after the chart last moved for a real reason (new data, a resize). The
	// wobble is cosmetic; running it forever kept the 30fps tick chain, and
	// with it a full re-render, alive on a chart that had nothing to show
	// (34-78% CPU idle). It now fades out over bubbleDriftFadeSeconds, the
	// springs settle, and the chain ends until the next data change.
	// Every real change resets it to the full duration, so data that
	// reshuffles the bubbles on each stats tick keeps the chain running:
	// only quiet workloads settle (the cost per frame is what got cheaper).
	bubbleDriftSeconds     = 6.0
	bubbleDriftFadeSeconds = 2.0

	// bubbleRetargetEpsilon is the smallest change of a bubble's anchor or
	// target radius that counts as new data. Smaller changes keep the old
	// anchor (see inheritPrevNodeState), so a stream of sub-cell wiggles from
	// live counters neither restarts the animation nor is lost: it
	// accumulates against the kept anchor until it crosses the threshold.
	bubbleRetargetEpsilon = 0.02
)

type bubbleDatum struct {
	ID       string
	Label    string
	Count    uint64
	Bytes    uint64
	Duration uint64
	Detail   string
	// row is the index of the source row the datum was built from, so the
	// builders can format Detail for the datums that survive the cut only
	// (rankBubbleData).
	row int
}

type bubbleNode struct {
	ID       string
	Label    string
	Detail   string
	Count    uint64
	Bytes    uint64
	Duration uint64
	Value    uint64

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
	// driftRemaining is the seconds of drift wobble left (see
	// bubbleDriftSeconds). While it is positive the chart keeps animating;
	// driftTime only advances during that time, so a resumed wobble
	// continues where it stopped instead of jumping.
	driftRemaining float64
	// frame caches the last rendered view (see bubbleFrameCache).
	frame bubbleFrameCache
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
			ID:       node.ID,
			Label:    node.Label,
			Count:    node.Count,
			Bytes:    node.Bytes,
			Duration: node.Duration,
			Detail:   node.Detail,
		})
	}
	c.SetData(data)
}

func (c *bubbleChart) SetMetric(metric bubbleMetric) {
	switch metric {
	case bubbleMetricBytes, bubbleMetricDuration:
		c.metric = metric
	default:
		c.metric = bubbleMetricCount
	}
}

func (c *bubbleChart) Metric() bubbleMetric {
	switch c.metric {
	case bubbleMetricBytes:
		return bubbleMetricBytes
	case bubbleMetricDuration:
		return bubbleMetricDuration
	default:
		return bubbleMetricCount
	}
}

func (c *bubbleChart) SetStatusHint(hint string) {
	c.statusHint = hint
}

func (c *bubbleChart) SetDarkMode(isDark bool) {
	c.isDark = isDark
}

// SetData recomputes bubble targets from data and merges them with existing
// animation state so that live updates animate smoothly. Returns true when
// the chart is animating and a Tick should be scheduled: either the springs
// have not settled or the drift wobble is still running. A data update that
// moves no bubble (the common idle case) returns false once settled, so the
// tick chain stays stopped.
func (c *bubbleChart) SetData(data []bubbleDatum) bool {
	targets := buildBubbleTargets(data, c.Metric(), c.width, c.height)

	selectedID := c.selectedID()

	existing := make(map[string]bubbleNode, len(c.nodes))
	for _, node := range c.nodes {
		existing[node.ID] = node
	}

	var retargeted bool
	c.nodes, retargeted = c.mergeTargetNodes(targets, existing)
	if len(c.nodes) == 0 {
		c.selected = 0
		c.animating = false
		c.driftRemaining = 0
		return false
	}
	// A vanished bubble is a change too, though no remaining node shows it.
	if retargeted || len(existing) != len(c.nodes) {
		c.driftRemaining = bubbleDriftSeconds
	}
	c.selected = c.selectIndexByID(selectedID)
	c.animating = c.driftRemaining > 0 || c.hasMotion()
	if c.animating {
		c.Tick(0)
	}
	return c.animating
}

// mergeTargetNodes converts target positions into live nodes, carrying over
// spring velocities and drift state from existing nodes where available. It
// also reports whether any bubble is new or was moved or resized by more than
// bubbleRetargetEpsilon, i.e. whether the animation needs to (re)start.
func (c *bubbleChart) mergeTargetNodes(targets []bubbleNode, existing map[string]bubbleNode) ([]bubbleNode, bool) {
	retargeted := false
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
			if c.inheritPrevNodeState(&node, prev, target) {
				retargeted = true
			}
		} else {
			node.radius = target.targetRadius
			node.x = target.targetX
			node.y = target.targetY
			c.initNodeDrift(&node)
			retargeted = true
		}
		node.applyDrift(c.driftTime, c.driftEnvelope(), c.width, c.height)
		next = append(next, node)
	}
	return next, retargeted
}

// inheritPrevNodeState copies physics and drift state from a previous node
// into node so that the transition animates rather than snapping. When the
// new target differs from the previous anchor and radius by no more than
// bubbleRetargetEpsilon the previous anchor and radius are kept (hysteresis)
// and false is returned; otherwise the new ones apply and it returns true.
func (c *bubbleChart) inheritPrevNodeState(node *bubbleNode, prev bubbleNode, target bubbleNode) bool {
	retargeted := math.Abs(target.targetX-prev.anchorX) > bubbleRetargetEpsilon ||
		math.Abs(target.targetY-prev.anchorY) > bubbleRetargetEpsilon ||
		math.Abs(target.targetRadius-prev.targetRadius) > bubbleRetargetEpsilon
	if !retargeted {
		node.anchorX, node.anchorY = prev.anchorX, prev.anchorY
		node.targetRadius = prev.targetRadius
	}
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
		c.initNodeDrift(node)
	} else {
		c.updateNodeDriftAmplitude(node)
	}
	return retargeted
}

// selectedID returns the ID (selection key) of the highlighted bubble, or ""
// when the chart has no such bubble. Consumers that act on the selection
// (Enter's filter) resolve it by this key against their own rows instead of
// re-deriving the chart's order, which only the chart itself can reproduce.
func (c *bubbleChart) selectedID() string {
	if c.selected >= 0 && c.selected < len(c.nodes) {
		return c.nodes[c.selected].ID
	}
	return ""
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

// hasMotion reports whether any bubble is still away from its target or
// still moving.
func (c *bubbleChart) hasMotion() bool {
	for _, node := range c.nodes {
		if c.nodeAnimating(node) {
			return true
		}
	}
	return false
}

// driftEnvelope scales the drift amplitude: full while the wobble has more
// than bubbleDriftFadeSeconds left, fading linearly to zero so the bubbles
// glide back to their anchors instead of stopping mid-wobble.
func (c *bubbleChart) driftEnvelope() float64 {
	return clampFloat(c.driftRemaining/bubbleDriftFadeSeconds, 0, 1)
}

// Tick advances the animation by one frame (delta seconds, 0 for one frame at
// bubbleFPS) and reports whether it is still animating. A false result means
// the springs settled and the drift wobble ended: the caller should stop the
// tick chain, because further ticks would change nothing.
func (c *bubbleChart) Tick(delta float64) bool {
	if len(c.nodes) == 0 {
		c.animating = false
		return false
	}
	baseDelta := harmonica.FPS(bubbleFPS)
	if delta <= 0 {
		delta = baseDelta
	}
	// The wobble clock only runs while drift is left, so a chart at rest is
	// bit-for-bit stable across the (skipped) ticks.
	if c.driftRemaining > 0 {
		c.driftTime += delta
		c.driftRemaining = math.Max(0, c.driftRemaining-delta)
	}
	envelope := c.driftEnvelope()

	active := c.driftRemaining > 0
	for idx := range c.nodes {
		node := &c.nodes[idx]
		node.applyDrift(c.driftTime, envelope, c.width, c.height)
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
	if !active {
		c.snapToTargets()
	}
	c.animating = active
	return active
}

// snapToTargets puts every bubble exactly on its target with zero velocity.
// Tick calls it when the chart settles: the springs stop within
// bubbleSpringEpsilon of the target, and the chain is about to end, so the
// resting picture would otherwise keep that sub-epsilon residue (and any
// later Tick would still nudge it). Snapping makes the settled state exact
// and stable; the jump is under a hundredth of a cell.
func (c *bubbleChart) snapToTargets() {
	for i := range c.nodes {
		n := &c.nodes[i]
		n.radius, n.x, n.y = n.targetRadius, n.targetX, n.targetY
		n.velocityRadius, n.velocityX, n.velocityY = 0, 0, 0
	}
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

// applyDrift moves the node's spring target around its anchor by the drift
// wobble at time t, scaled by envelope (0 puts the target on the anchor).
func (n *bubbleNode) applyDrift(t, envelope float64, width, height int) {
	if n == nil {
		return
	}
	phase := n.driftPhase + t*n.driftSpeed
	n.targetX = n.anchorX + math.Sin(phase)*n.driftAmpX*envelope
	n.targetY = n.anchorY + math.Cos(phase*0.91+0.37)*n.driftAmpY*envelope

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

func (c *bubbleChart) HasNodes() bool {
	return len(c.nodes) > 0
}

// Render draws the chart as a width x height block. The painted view is
// cached (bubbleFrameCache): every key press, focus event or unrelated
// message makes Bubble Tea call View, and re-painting an unchanged chart
// each time was a full frame of work for identical output.
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
		// Each line is cut to the width (task cz2): a narrow terminal shows
		// this empty state right at startup, and the header alone is ~65
		// cells.
		return fitPlaceholderLines(width, header, body, "sel: none")
	}

	chartHeight := height - 2
	if chartHeight < 4 {
		chartHeight = 4
	}
	// statusLine clamps c.selected, so it runs before the cache key is read.
	status := padOrTrim(c.statusLine(width), width)
	if view, ok := c.frame.lookup(c, header, status, width, chartHeight); ok {
		return view
	}
	grid := newGridRows(width, chartHeight)
	c.renderBubblesToGrid(grid, width, chartHeight)
	lines := make([]string, 0, chartHeight+2)
	lines = append(lines, padOrTrim(header, width))
	lines = append(lines, renderGridRows(grid, c.palette())...)
	lines = append(lines, status)
	view := strings.Join(lines, "\n")
	c.frame.store(view)
	return view
}

func (c *bubbleChart) renderBubblesToGrid(grid [][]gridCell, width, height int) {
	order := make([]int, 0, len(c.nodes))
	for idx := range c.nodes {
		order = append(order, idx)
	}
	slices.SortFunc(order, func(a, b int) int {
		return cmp.Compare(c.nodes[a].radius, c.nodes[b].radius)
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

func drawBubble(grid [][]gridCell, width, height int, node bubbleNode, selected bool, colorSlot int) {
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
				grid[y][x] = gridCell{char: fill, colorSlot: colorSlot, bold: selected}
			case dist <= radius:
				grid[y][x] = gridCell{char: innerFill, colorSlot: colorSlot, bold: selected}
			}
		}
	}
}

// drawBubbleLabel centres the node's label on the bubble's middle row. The
// label budget and the centring offset are measured in terminal cells, not
// runes, and the label is placed grapheme by grapheme (writeGridLabel), so
// wide CJK/emoji labels stay inside the bubble and the row keeps its width.
// The selected bubble's label is bracketed within the same budget.
func drawBubbleLabel(grid [][]gridCell, width, height int, node bubbleNode, selected bool, colorSlot int) {
	if len(grid) == 0 || width == 0 || height == 0 {
		return
	}
	maxLabelCells := maxInt(2, int(math.Round(node.radius*1.6)))
	label := abbreviateLabel(node.Label, maxLabelCells)
	if selected {
		label = "[" + abbreviateLabel(node.Label, maxInt(1, maxLabelCells-2)) + "]"
	}
	cx := int(math.Round(node.x))
	cy := int(math.Round(node.y))
	if cy < 0 || cy >= height {
		return
	}
	start := cx - common.DisplayWidth(label)/2
	writeGridLabel(grid[cy], start, label, colorSlot, selected)
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
	// Use a Builder to avoid extra allocations for the optional hint/detail suffixes
	// that are appended conditionally on every render.
	var b strings.Builder
	b.WriteString(fmt.Sprintf("sel:%d/%d %s | %s | bytes=%s", c.selected+1, len(c.nodes), node.Label, metricText, formatBytes(float64(node.Bytes))))
	if c.statusHint != "" {
		b.WriteString(" | ")
		b.WriteString(c.statusHint)
	}
	if node.Detail != "" {
		b.WriteString(" | ")
		b.WriteString(node.Detail)
	}
	return padOrTrim(b.String(), width)
}

func (c *bubbleChart) metricLabel() string {
	switch c.Metric() {
	case bubbleMetricBytes:
		return "bytes"
	case bubbleMetricDuration:
		return "duration"
	default:
		return "events"
	}
}

func (c *bubbleChart) formatMetricValue(node bubbleNode) string {
	switch c.Metric() {
	case bubbleMetricBytes:
		return formatBytes(float64(node.Bytes))
	case bubbleMetricDuration:
		return formatDurationUintNs(node.Duration)
	default:
		return fmt.Sprintf("%d", node.Count)
	}
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

// buildBubbleTargets computes initial target positions and radii for each
// bubble, then runs a short relaxation pass to reduce overlap. Returns nil
// when there is nothing to render.
func buildBubbleTargets(data []bubbleDatum, metric bubbleMetric, width, height int) []bubbleNode {
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

	filtered := filterAndSortBubbleData(data, metric)
	if len(filtered) == 0 {
		return nil
	}

	targets := placeBubbleNodes(filtered, metric, width, chartHeight)
	relaxTargets(targets, width, chartHeight)
	return targets
}

// filterAndSortBubbleData removes datums without an ID, sorts by descending
// metric value (ties broken by label), and caps the result to bubbleMaxItems.
func filterAndSortBubbleData(data []bubbleDatum, metric bubbleMetric) []bubbleDatum {
	filtered := make([]bubbleDatum, 0, len(data))
	for _, datum := range data {
		if datum.ID == "" {
			continue
		}
		filtered = append(filtered, datum)
	}
	slices.SortFunc(filtered, func(a, b bubbleDatum) int {
		va := bubbleValue(a, metric)
		vb := bubbleValue(b, metric)
		if va != vb {
			return cmp.Compare(vb, va)
		}
		return cmp.Compare(a.Label, b.Label)
	})
	if len(filtered) > bubbleMaxItems {
		filtered = filtered[:bubbleMaxItems]
	}
	return filtered
}

// placeBubbleNodes converts sorted bubble data into node structs with target
// positions arranged in a golden-angle spiral around the chart centre.
func placeBubbleNodes(filtered []bubbleDatum, metric bubbleMetric, width, chartHeight int) []bubbleNode {
	maxValue := uint64(0)
	for _, datum := range filtered {
		if v := bubbleValue(datum, metric); v > maxValue {
			maxValue = v
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

	cx := float64(width-1) / 2.0
	cy := float64(chartHeight-1) / 2.0
	goldenAngle := math.Pi * (3.0 - math.Sqrt(5.0))
	spacingBase := maxRadius * 0.95

	targets := make([]bubbleNode, 0, len(filtered))
	for idx, datum := range filtered {
		value := bubbleValue(datum, metric)
		ratio := math.Sqrt(float64(value) / float64(maxValue))
		targetRadius := minRadius + ratio*(maxRadius-minRadius)
		distance := spacingBase * math.Sqrt(float64(idx)+0.6)
		angle := float64(idx) * goldenAngle
		targets = append(targets, bubbleNode{
			ID:           datum.ID,
			Label:        datum.Label,
			Detail:       datum.Detail,
			Count:        datum.Count,
			Bytes:        datum.Bytes,
			Duration:     datum.Duration,
			Value:        value,
			targetRadius: targetRadius,
			targetX:      cx + math.Cos(angle)*distance,
			targetY:      cy + math.Sin(angle)*distance*0.68,
		})
	}
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
	switch metric {
	case bubbleMetricBytes:
		return d.Bytes
	case bubbleMetricDuration:
		return d.Duration
	default:
		return d.Count
	}
}

// rankBubbleData is the shared tail of the bubble data builders: it ranks
// data by metric and keeps the bubbleMaxItems largest (the same cut SetData
// would make, so nothing visible changes), then formats Detail for those
// survivors only via describe, the Detail text of one source row. Formatting
// every row up front cost milliseconds per stats tick on a snapshot with
// thousands of processes, to show at most bubbleMaxItems of them.
func rankBubbleData(data []bubbleDatum, metric bubbleMetric, describe func(row int) string) []bubbleDatum {
	data = filterAndSortBubbleData(data, metric)
	for i := range data {
		data[i].Detail = describe(data[i].row)
	}
	return data
}

// syscallBubbleData builds bubble-chart data from the already filter-scoped
// syscall rows (see Model.visibleSyscallRows) so the bubble view matches the
// table view under an active family/syscall filter.
func syscallBubbleData(rows []statsengine.SyscallSnapshot, metric bubbleMetric) []bubbleDatum {
	data := make([]bubbleDatum, 0, len(rows))
	for i, syscall := range rows {
		data = append(data, bubbleDatum{
			ID:       syscall.Name,
			Label:    syscall.Name,
			Count:    syscall.Count,
			Bytes:    syscall.Bytes,
			Duration: syscall.TotalLatencyNs,
			row:      i,
		})
	}
	return rankBubbleData(data, metric, func(row int) string {
		syscall := rows[row]
		return fmt.Sprintf("rate %.1f/s, errors %d, p95 %s", syscall.RatePerSec, syscall.Errors, latencyCellUint(syscall.NoPercentileData(), syscall.LatencyP95Ns))
	})
}

func filesDirBubbleData(snap *statsengine.Snapshot, metric bubbleMetric) []bubbleDatum {
	if snap == nil {
		return nil
	}
	dirs := snapshotDirRows(snap)
	data := make([]bubbleDatum, 0, len(dirs))
	for i, dir := range dirs {
		data = append(data, bubbleDatum{
			ID:       dirKey(dir),
			Label:    dirDisplayLabel(dir),
			Count:    dir.Accesses,
			Bytes:    dir.BytesRead + dir.BytesWritten,
			Duration: dir.TotalLatencyNs,
			row:      i,
		})
	}
	return rankBubbleData(data, metric, func(row int) string {
		dir := dirs[row]
		return fmt.Sprintf("dir %s, files %d, read %s, write %s", dirDisplayLabel(dir), dir.FileCount, formatBytes(float64(dir.BytesRead)), formatBytes(float64(dir.BytesWritten)))
	})
}

// processBubbleData builds the Processes bubble data. It runs for every
// stats tick over every process row (thousands on a busy host), so the
// per-row work excludes fmt: see rankBubbleData.
func processBubbleData(snap *statsengine.Snapshot, metric bubbleMetric) []bubbleDatum {
	if snap == nil {
		return nil
	}
	rows := snap.Processes()
	data := make([]bubbleDatum, 0, len(rows))
	for i, proc := range rows {
		data = append(data, bubbleDatum{
			ID:       processRowKey(proc),
			Label:    processLabel(proc),
			Count:    proc.Syscalls,
			Bytes:    proc.Bytes,
			Duration: proc.TotalLatencyNs,
			row:      i,
		})
	}
	return rankBubbleData(data, metric, func(row int) string {
		proc := rows[row]
		return fmt.Sprintf("pid %d, rate %.1f/s, avg %s", proc.PID, proc.RatePerSec, latencyCell(proc.NoLatency, proc.AvgLatencyNs))
	})
}

// padOrTrim fits value into exactly width display cells for the bubble,
// treemap and icicle header/status lines: cut with "…" when too wide, then
// space-padded (common.FitRight). Both steps measure terminal cells, so wide
// CJK/emoji text cannot overflow the line. A width of zero or less means
// "unconstrained" and returns value unchanged.
func padOrTrim(value string, width int) string {
	if width <= 0 {
		return value
	}
	return common.FitRight(value, width, common.Ellipsis)
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
