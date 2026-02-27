package flamegraph

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type zoomSearchStateResult struct {
	BeforePath         string `json:"beforePath"`
	AfterPath          string `json:"afterPath"`
	DeepPathStable     bool   `json:"deepPathStable"`
	SearchPersisted    bool   `json:"searchPersisted"`
	ZoomedBranchStable bool   `json:"zoomedBranchStable"`
	NonZoomedHidden    bool   `json:"nonZoomedHidden"`
	NewChildVisible    bool   `json:"newChildVisible"`
	PauseUnpauseKeeps  bool   `json:"pauseUnpauseKeeps"`
}

func TestLiveHTMLJSZoomSearchStatePreservedAcrossUpdates(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	snippet := `
const fg = liveFlamegraphState;

const frameA = makeFrame("A", "A", 1, 0, 700);
const frameAChild = makeFrame("Achild", "A\u001fAchild", 2, 0, 400);
const frameB = makeFrame("B", "B", 1, 700, 500);
fg.frames = [frameA, frameAChild, frameB];
fg.rootWidth = 1200;

fgZoom(frameA);
const beforePath = fg.zoomRange.path;
prompt = function(){ return "A"; };
fgSearch();

const frameA2 = makeFrame("A", "A", 1, 0, 800);
const frameAChild2 = makeFrame("Achild", "A\u001fAchild", 2, 0, 500);
const frameAnew2 = makeFrame("Anew", "A\u001fAnew", 2, 500, 300);
const frameB2 = makeFrame("B", "B", 1, 800, 400);
fg.frames = [frameA2, frameAChild2, frameAnew2, frameB2];
fg.rootWidth = 1200;
fgApplyZoom();
prompt = function(_msg, prev){ return prev || "A"; };
fgSearch();

const afterPath = fg.zoomRange.path;
const searchPersisted = frameA2.querySelector("rect").getAttribute("fill") === fg.matchColor;
const nonZoomedHidden = frameB2.style.display === "none";
const newChildVisible = frameAnew2.style.display !== "none";
const zoomedBranchStable = frameA2.style.display !== "none" && frameAChild2.style.display !== "none";

const deep1 = makeFrame("A2", "A\u001fA1\u001fA2", 3, 100, 200);
fg.frames = [deep1];
fg.rootWidth = 1200;
fgZoom(deep1);
const deepPath = fg.zoomRange.path;

const deep2 = makeFrame("A2", "A\u001fA1\u001fA2", 3, 120, 240);
fg.frames = [deep2];
fgApplyZoom();
const deep3 = makeFrame("A2", "A\u001fA1\u001fA2", 3, 140, 260);
fg.frames = [deep3];
fgApplyZoom();
const deepPathStable = fg.zoomRange.path === deepPath && deep3.style.display !== "none";

fg.pendingData = "{\"n\":\"\",\"v\":0,\"t\":0}";
fgTogglePause();
fgTogglePause();
const pauseUnpauseKeeps = fg.zoomRange.path === deepPath;

console.log(JSON.stringify({
  beforePath,
  afterPath,
  deepPathStable,
  searchPersisted,
  zoomedBranchStable,
  nonZoomedHidden,
  newChildVisible,
  pauseUnpauseKeeps
}));
`

	out := runLiveHTMLNodeSnippet(t, snippet)
	var got zoomSearchStateResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode node result: %v\nraw:\n%s", err, out)
	}

	if got.BeforePath != "A" || got.AfterPath != "A" {
		t.Fatalf("zoom path changed unexpectedly: before=%q after=%q", got.BeforePath, got.AfterPath)
	}
	if !got.SearchPersisted {
		t.Fatalf("expected search highlight to persist across update")
	}
	if !got.ZoomedBranchStable {
		t.Fatalf("expected zoomed branch to remain visible across update")
	}
	if !got.NonZoomedHidden {
		t.Fatalf("expected non-zoomed branch to be hidden while zoomed")
	}
	if !got.NewChildVisible {
		t.Fatalf("expected newly added child in zoomed branch to remain visible")
	}
	if !got.DeepPathStable {
		t.Fatalf("expected deep zoom path to remain stable across multiple updates")
	}
	if !got.PauseUnpauseKeeps {
		t.Fatalf("expected pause/unpause to preserve zoom state")
	}
}

func runLiveHTMLNodeSnippet(t *testing.T, snippet string) string {
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
    listeners: {},
    addEventListener: function(event, cb) { this.listeners[event] = cb; },
    setAttribute: function(k, v) { this.attrs[k] = String(v); },
    getAttribute: function(k) { return this.attrs[k] || ""; },
    querySelectorAll: function() { return []; },
    querySelector: function() { return null; }
  };
}

function makeRect(fill) {
  return {
    attrs: { fill: fill || "" },
    dataset: {},
    style: {},
    setAttribute: function(k, v) { this.attrs[k] = String(v); },
    getAttribute: function(k) { return this.attrs[k] || ""; }
  };
}

function makeText(name) {
  return {
    textContent: name || "",
    dataset: { full: name || "", hidden: "0", ox: "0" },
    style: {},
    setAttribute: function(k, v) {
      this[k] = String(v);
    },
    getAttribute: function(k) {
      return this[k] || "";
    }
  };
}

function makeFrame(name, path, depth, x, w) {
  const rect = makeRect("rgb(1,2,3)");
  rect.dataset.ox = String(x);
  rect.dataset.ow = String(w);
  rect.setAttribute("x", String(x));
  rect.setAttribute("width", String(w));

  const text = makeText(name);
  text.dataset.ox = String(x + 3);
  text.setAttribute("x", String(x + 3));

  const title = { textContent: name + " title" };
  return {
    dataset: {
      name: name,
      path: path,
      depth: String(depth),
      x: String(x),
      w: String(w),
      ox: String(x),
      ow: String(w),
      baseFill: "rgb(1,2,3)"
    },
    style: {},
    listeners: {},
    addEventListener: function(event, cb) { this.listeners[event] = cb; },
    querySelector: function(selector) {
      if (selector === "rect") return rect;
      if (selector === "text") return text;
      if (selector === "title") return title;
      return null;
    },
    querySelectorAll: function() { return []; },
  };
}

const elements = {};
["flamegraph", "status", "btn-pause", "btn-search", "btn-reset-search", "btn-undo-zoom", "btn-reset-zoom"].forEach((id) => {
  elements[id] = makeElement(id);
});
elements["body"] = makeElement("body");

const docListeners = {};
global.document = {
  body: elements["body"],
  getElementById: function(id) {
    if (!elements[id]) elements[id] = makeElement(id);
    return elements[id];
  },
  addEventListener: function(event, cb) { docListeners[event] = cb; },
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

global.makeFrame = makeFrame;
global.__docListeners = docListeners;

%s
`, script, snippet)

	tmp, err := os.CreateTemp("", "livehtml-node-snippet-*.cjs")
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
		t.Fatalf("node snippet failed: %v\n%s", err, string(out))
	}
	return strings.TrimSpace(string(out))
}
