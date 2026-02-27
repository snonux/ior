package flamegraph

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type jsFrame struct {
	Name  string  `json:"name"`
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
	W     float64 `json:"w"`
	H     float64 `json:"h"`
	Depth int     `json:"depth"`
}

type liveJSResult struct {
	Colors         map[string]string `json:"colors"`
	KnownFrames    []jsFrame         `json:"knownFrames"`
	SVGHTML        string            `json:"svgHTML"`
	ViewBox        string            `json:"viewBox"`
	TallViewBox    string            `json:"tallViewBox"`
	TallHeight     string            `json:"tallHeight"`
	SingleCount    int               `json:"singleCount"`
	DeepMaxDepth   int               `json:"deepMaxDepth"`
	WideFrameCount int               `json:"wideFrameCount"`
}

func TestLiveHTMLJSRenderingParity(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	out := runLiveHTMLJSHarness(t)
	var got liveJSResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal node output: %v\nraw:\n%s", err, out)
	}

	names := []string{"read", "write", "io_uring_enter", "nested/path"}
	for _, name := range names {
		want := frameColor(name)
		if got.Colors[name] != want {
			t.Fatalf("fgFrameColor(%q) = %q, want %q", name, got.Colors[name], want)
		}
	}

	if len(got.KnownFrames) != 3 {
		t.Fatalf("known frame count = %d, want 3", len(got.KnownFrames))
	}
	assertFrame(t, got.KnownFrames[0], "A", 0, 96, 720, 15, 1)
	assertFrame(t, got.KnownFrames[1], "A1", 0, 80, 720, 15, 2)
	assertFrame(t, got.KnownFrames[2], "B", 720, 96, 480, 15, 1)

	if !strings.Contains(got.SVGHTML, `<g class="frame"`) {
		t.Fatalf("svg markup missing frame group")
	}
	if !strings.Contains(got.SVGHTML, `data-name="A"`) {
		t.Fatalf("svg markup missing data-name for A")
	}
	if !strings.Contains(got.SVGHTML, `data-x="0.000"`) {
		t.Fatalf("svg markup missing data-x")
	}
	if !strings.Contains(got.SVGHTML, `data-w="720.000"`) {
		t.Fatalf("svg markup missing data-w")
	}
	if !strings.Contains(got.SVGHTML, `data-depth="1"`) {
		t.Fatalf("svg markup missing data-depth")
	}
	if !strings.Contains(got.SVGHTML, `data-base-fill="rgb(`) {
		t.Fatalf("svg markup missing data-base-fill")
	}
	if got.ViewBox != "0 0 1200 128" {
		t.Fatalf("viewBox = %q, want %q", got.ViewBox, "0 0 1200 128")
	}
	if got.TallViewBox != "0 0 1200 844" {
		t.Fatalf("tall viewBox = %q, want %q", got.TallViewBox, "0 0 1200 844")
	}
	if got.TallHeight != "844px" {
		t.Fatalf("tall style height = %q, want %q", got.TallHeight, "844px")
	}

	if got.SingleCount != 1 {
		t.Fatalf("single-frame case count = %d, want 1", got.SingleCount)
	}
	if got.DeepMaxDepth < 50 {
		t.Fatalf("deep max depth = %d, want at least 50", got.DeepMaxDepth)
	}
	if got.WideFrameCount != 1000 {
		t.Fatalf("wide frame count = %d, want 1000", got.WideFrameCount)
	}
}

func assertFrame(t *testing.T, got jsFrame, name string, x, y, w, h float64, depth int) {
	t.Helper()
	if got.Name != name {
		t.Fatalf("frame name = %q, want %q", got.Name, name)
	}
	if got.Depth != depth {
		t.Fatalf("frame %q depth = %d, want %d", got.Name, got.Depth, depth)
	}
	const eps = 0.001
	if diff(got.X, x) > eps || diff(got.Y, y) > eps || diff(got.W, w) > eps || diff(got.H, h) > eps {
		t.Fatalf("frame %q geometry = {x:%f y:%f w:%f h:%f}, want {x:%f y:%f w:%f h:%f}",
			got.Name, got.X, got.Y, got.W, got.H, x, y, w, h)
	}
}

func diff(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return b - a
}

func runLiveHTMLJSHarness(t *testing.T) string {
	t.Helper()

	script := extractLiveHTMLScript(t)
	harness := fmt.Sprintf(`
const vm = require("vm");
const liveScript = %q;

function makeElement(id) {
  return {
    id,
    textContent: "",
    innerHTML: "",
    style: {},
    dataset: {},
    attrs: {},
    classList: { toggle: function(){}, add: function(){}, remove: function(){} },
    addEventListener: function(){},
    getBoundingClientRect: function() { return { height: id === "controls" ? 56 : 0 }; },
    setAttribute: function(k, v) { this.attrs[k] = String(v); },
    getAttribute: function(k) { return this.attrs[k] || ""; },
    querySelectorAll: function() { return []; },
    querySelector: function() { return null; }
  };
}

const elements = {};
["controls", "flamegraph", "status", "btn-pause", "btn-search", "btn-reset-search", "btn-undo-zoom", "btn-reset-zoom", "btn-reset-baseline"].forEach((id) => {
  elements[id] = makeElement(id);
});
elements["body"] = makeElement("body");

global.document = {
  body: elements["body"],
  getElementById: function(id) {
    if (!elements[id]) elements[id] = makeElement(id);
    return elements[id];
  },
  addEventListener: function(){},
};
global.window = global;
global.prompt = function(){ return ""; };
global.requestAnimationFrame = function(cb){ cb(); };
global.EventSource = function() {
  this.onmessage = null;
  this.onerror = null;
};
window.addEventListener = function(){};

vm.runInThisContext(liveScript);

const names = ["read", "write", "io_uring_enter", "nested/path"];
const colors = {};
for (const n of names) {
  colors[n] = fgFrameColor(n);
}

const knownTree = {
  n: "",
  v: 0,
  t: 10,
  c: [
    { n: "A", v: 0, t: 6, c: [{ n: "A1", v: 6, t: 6 }] },
    { n: "B", v: 4, t: 4 }
  ]
};
const maxDepth = fgMaxDepth(knownTree, 0);
const canvasHeight = (liveFlamegraphState.cfg.frameHeight * (maxDepth + 1)) + 80;
const knownFramesRaw = [];
fgBuildFrames(knownTree, knownTree.t, 0, 0, canvasHeight, true, knownFramesRaw, "");
const knownFrames = knownFramesRaw.map((f) => ({
  name: f.name,
  x: Number(f.x.toFixed(3)),
  y: Number(f.y.toFixed(3)),
  w: Number(f.w.toFixed(3)),
  h: Number(f.h.toFixed(3)),
  depth: f.depth,
}));

fgRender(knownTree);
const svgHTML = elements["flamegraph"].innerHTML;
const viewBox = elements["flamegraph"].attrs["viewBox"] || "";

window.innerHeight = 900;
fgRender(knownTree);
const tallViewBox = elements["flamegraph"].attrs["viewBox"] || "";
const tallHeight = elements["flamegraph"].style.height || "";

const singleTree = { n: "", v: 0, t: 1, c: [{ n: "only", v: 1, t: 1 }] };
const singleFrames = [];
const singleCanvas = (liveFlamegraphState.cfg.frameHeight * (fgMaxDepth(singleTree, 0) + 1)) + 80;
fgBuildFrames(singleTree, singleTree.t, 0, 0, singleCanvas, true, singleFrames, "");

let deepTree = { n: "", v: 0, t: 1, c: [] };
let cursor = deepTree;
for (let i = 0; i < 55; i++) {
  const child = { n: "d" + i, v: i === 54 ? 1 : 0, t: 1, c: [] };
  cursor.c = [child];
  cursor = child;
}
const deepMaxDepth = fgMaxDepth(deepTree, 0);

const wideChildren = [];
for (let i = 0; i < 1000; i++) {
  wideChildren.push({ n: "w" + i, v: 1, t: 1 });
}
const wideTree = { n: "", v: 0, t: 1000, c: wideChildren };
const wideCanvas = (liveFlamegraphState.cfg.frameHeight * (fgMaxDepth(wideTree, 0) + 1)) + 80;
const wideFrames = [];
fgBuildFrames(wideTree, wideTree.t, 0, 0, wideCanvas, true, wideFrames, "");

console.log(JSON.stringify({
  colors,
  knownFrames,
  svgHTML,
  viewBox,
  tallViewBox,
  tallHeight,
  singleCount: singleFrames.length,
  deepMaxDepth,
  wideFrameCount: wideFrames.length,
}));
`, script)

	tmp, err := os.CreateTemp("", "livehtml-js-*.cjs")
	if err != nil {
		t.Fatalf("create temp script: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(harness); err != nil {
		_ = tmp.Close()
		t.Fatalf("write temp script: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp script: %v", err)
	}

	out, err := exec.Command("node", tmp.Name()).CombinedOutput()
	if err != nil {
		t.Fatalf("node harness failed: %v\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func extractLiveHTMLScript(t *testing.T) string {
	t.Helper()
	const openTag = "<script>"
	const closeTag = "</script>"
	start := strings.Index(liveHTML, openTag)
	if start < 0 {
		t.Fatalf("script tag not found in liveHTML")
	}
	start += len(openTag)
	end := strings.Index(liveHTML[start:], closeTag)
	if end < 0 {
		t.Fatalf("closing script tag not found in liveHTML")
	}
	return strings.TrimSpace(liveHTML[start : start+end])
}
