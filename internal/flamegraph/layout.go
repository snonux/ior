package flamegraph

import "fmt"

// FrameLayout captures renderer-agnostic flamegraph geometry for a single frame.
//
// The layout is reusable by non-SVG renderers (for example SDL or WASM UIs) so
// they can render the same hierarchy without depending on SVG internals.
type FrameLayout struct {
	Name    string
	Title   string
	Fill    string
	X       float64
	Y       float64
	Width   float64
	Height  float64
	Depth   int
	Total   uint64
	Percent float64
}

func sanitizeSVGConfig(cfg SVGConfig) SVGConfig {
	if cfg.Width <= 0 || cfg.FrameHeight <= 0 || cfg.FontSize <= 0 || cfg.MinWidthPx <= 0 {
		return defaultSVGConfig()
	}
	if cfg.Title == "" {
		cfg.Title = defaultSVGConfig().Title
	}
	return cfg
}

func canvasHeightFor(cfg SVGConfig, t *trie) int {
	return cfg.FrameHeight*(t.maxDepth+1) + 80
}

// BuildFrameLayout builds renderer-agnostic frame coordinates from a flamegraph trie.
func BuildFrameLayout(t *trie, cfg SVGConfig) []FrameLayout {
	if t == nil || t.root == nil || t.root.total == 0 {
		return nil
	}
	cfg = sanitizeSVGConfig(cfg)
	canvasHeight := canvasHeightFor(cfg, t)
	out := make([]FrameLayout, 0, len(t.root.children))
	collectFrameLayout(&out, t.root, t.root.total, cfg, 0, 0, canvasHeight, true)
	return out
}

func collectFrameLayout(out *[]FrameLayout, node *trieNode, rootTotal uint64,
	cfg SVGConfig, x float64, depth int, canvasHeight int, isRoot bool) {

	if !isRoot {
		w := float64(cfg.Width) * (float64(node.total) / float64(rootTotal))
		if w < cfg.MinWidthPx {
			return
		}
		y := float64(canvasHeight - (depth+1)*cfg.FrameHeight)
		pct := 100 * float64(node.total) / float64(rootTotal)
		*out = append(*out, FrameLayout{
			Name:    node.name,
			Title:   fmt.Sprintf("%s (%d, %.2f%%)", node.name, node.total, pct),
			Fill:    frameColor(node.name),
			X:       x,
			Y:       y,
			Width:   w,
			Height:  float64(cfg.FrameHeight - 1),
			Depth:   depth,
			Total:   node.total,
			Percent: pct,
		})
	}

	cursor := x
	for _, child := range node.children {
		cw := float64(cfg.Width) * (float64(child.total) / float64(rootTotal))
		collectFrameLayout(out, child, rootTotal, cfg, cursor, depth+1, canvasHeight, false)
		cursor += cw
	}
}
