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

// SVGConfig controls the layout and styling of generated flamegraph SVGs.
//
// Width is the virtual canvas width in pixels, FrameHeight is the height of each
// stack frame row, FontSize is the base font size, and MinWidthPx controls the
// minimum rendered width for a frame (smaller frames are skipped to avoid noise).
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

// DefaultSVGConfig returns the default SVG configuration values.
func DefaultSVGConfig() SVGConfig {
	return defaultSVGConfig()
}

// WriteSVG renders a flamegraph trie into an interactive SVG document.
//
// The output is a self-contained SVG that includes embedded CSS and JavaScript
// for zoom, search, and highlighting, and is designed to be served directly to
// a browser (for example via ServeSVG) without any external assets.
func WriteSVG(w io.Writer, t *trie, cfg SVGConfig) error {
	cfg = sanitizeSVGConfig(cfg)

	canvasHeight := canvasHeightFor(cfg, t)
	bw := bufio.NewWriter(w)
	if err := writeSVGHeader(bw, cfg, canvasHeight); err != nil {
		return err
	}
	for _, frame := range BuildFrameLayout(t, cfg) {
		if err := writeFrame(bw, frame.Name, frame.Title, frame.Fill,
			frame.X, frame.Y, frame.Width, frame.Height, frame.Depth, cfg.FontSize); err != nil {
			return err
		}
	}
	if err := writeSVGFooter(bw); err != nil {
		return err
	}
	return bw.Flush()
}

func writeSVGHeader(bw *bufio.Writer, cfg SVGConfig, height int) error {
	_, err := fmt.Fprintf(bw, `<svg xmlns="http://www.w3.org/2000/svg" width="100%%" height="%d" viewBox="0 0 %d %d" preserveAspectRatio="xMinYMin meet">`+"\n",
		height, cfg.Width, height)
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
