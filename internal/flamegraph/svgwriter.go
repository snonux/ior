package flamegraph

import (
	"bufio"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"strings"
	"sync"
)

var svgEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

var fnv32aPool = sync.Pool{
	New: func() any {
		return fnv.New32a()
	},
}

type SVGConfig struct {
	Title       string
	Width       int
	FrameHeight int
	FontSize    int
	MinWidthPx  float64
}

func defaultSVGConfig() SVGConfig {
	return SVGConfig{
		Title:       "I/O Flame Graph",
		Width:       1200,
		FrameHeight: 16,
		FontSize:    12,
		MinWidthPx:  1.0,
	}
}

func WriteSVG(w io.Writer, t *trie, cfg SVGConfig) error {
	if cfg.Width <= 0 || cfg.FrameHeight <= 0 || cfg.FontSize <= 0 || cfg.MinWidthPx <= 0 {
		cfg = defaultSVGConfig()
	}
	if cfg.Title == "" {
		cfg.Title = defaultSVGConfig().Title
	}

	canvasHeight := cfg.FrameHeight*(t.maxDepth+1) + 80
	bw := bufio.NewWriter(w)
	if err := writeSVGHeader(bw, cfg, canvasHeight); err != nil {
		return err
	}
	if t.root.total > 0 {
		if err := renderFrames(bw, t.root, t.root.total, cfg, 0, 0, canvasHeight, true); err != nil {
			return err
		}
	}
	if err := writeSVGFooter(bw); err != nil {
		return err
	}
	return bw.Flush()
}

func writeSVGHeader(bw *bufio.Writer, cfg SVGConfig, height int) error {
	_, err := fmt.Fprintf(bw, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`+"\n",
		cfg.Width, height, cfg.Width, height)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(bw, "<style><![CDATA[%s]]></style>\n", flamegraphCSS(cfg))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(bw, "<script><![CDATA[%s]]></script>\n", flamegraphJS)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(bw, `<text class="title" x="10" y="22">%s</text>`+"\n", svgEscape(cfg.Title))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(bw, `<g class="controls"><text x="10" y="42" onclick="fgSearch()">Search</text><text x="80" y="42" onclick="fgResetSearch()">Reset Search</text><text x="190" y="42" onclick="fgUndoZoom()">Undo Zoom</text><text x="280" y="42" onclick="fgResetZoom()">Reset Zoom</text><text id="fg-info" x="390" y="42"></text></g>`+"\n")
	return err
}

func writeSVGFooter(bw *bufio.Writer) error {
	_, err := fmt.Fprintln(bw, "</svg>")
	return err
}

func renderFrames(bw *bufio.Writer, node *trieNode, rootTotal uint64, cfg SVGConfig, x float64, depth int, canvasHeight int, isRoot bool) error {
	if !isRoot {
		w := float64(cfg.Width) * (float64(node.total) / float64(rootTotal))
		if w < cfg.MinWidthPx {
			return nil
		}
		y := float64(canvasHeight - (depth+1)*cfg.FrameHeight)
		fill := frameColor(node.name)
		pct := 100 * float64(node.total) / float64(rootTotal)
		title := fmt.Sprintf("%s (%d, %.2f%%)", node.name, node.total, pct)
		if err := writeFrame(bw, node.name, title, fill, x, y, w, float64(cfg.FrameHeight-1), depth, cfg.FontSize); err != nil {
			return err
		}
	}

	cursor := x
	for _, child := range node.children {
		cw := float64(cfg.Width) * (float64(child.total) / float64(rootTotal))
		if err := renderFrames(bw, child, rootTotal, cfg, cursor, depth+1, canvasHeight, false); err != nil {
			return err
		}
		cursor += cw
	}
	return nil
}

func writeFrame(bw *bufio.Writer, name, title, fill string, x, y, w, h float64, depth, fontSize int) error {
	textStyle := ""
	labelStyle := ""
	if w <= float64(fontSize*2) {
		labelStyle = ` style="display:none"`
	}
	if labelStyle != "" {
		textStyle = labelStyle
	}
	_, err := fmt.Fprintf(bw, `<g class="frame" data-name="%s" data-x="%.3f" data-w="%.3f" data-depth="%d" data-base-fill="%s">
<title>%s</title><rect x="%.3f" y="%.3f" width="%.3f" height="%.3f" fill="%s"/>
<text x="%.3f" y="%.3f"%s>%s</text>
</g>
`,
		svgEscape(name), x, w, depth, fill,
		svgEscape(title), x, y, w, h, fill,
		x+3, y+float64(fontSize), textStyle, svgEscape(name))
	return err
}

func frameColor(name string) string {
	hasher := fnv32aPool.Get().(hash.Hash32)
	hasher.Reset()
	_, _ = io.WriteString(hasher, name)
	h := hasher.Sum32()
	fnv32aPool.Put(hasher)
	r := 200 + int(h%35)
	g := 80 + int((h>>8)%120)
	b := 40 + int((h>>16)%90)
	return fmt.Sprintf("rgb(%d,%d,%d)", r, g, b)
}

func flamegraphCSS(cfg SVGConfig) string {
	return fmt.Sprintf(`
.title { font-size: %dpx; font-family: monospace; }
.controls text { font-size: %dpx; font-family: monospace; cursor: pointer; fill: #444; }
.frame text { font-size: %dpx; font-family: monospace; pointer-events: none; fill: #111; }
.frame rect { stroke: rgba(0,0,0,0.18); stroke-width: 0.5; }
.title, .controls text, .frame text { user-select: none; -webkit-user-select: none; }
`, cfg.FontSize+2, cfg.FontSize, cfg.FontSize-1)
}

func svgEscape(s string) string {
	return svgEscaper.Replace(s)
}
