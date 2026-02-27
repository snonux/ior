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

type pauseKeyboardResult struct {
	PausedBySpace          bool `json:"pausedBySpace"`
	NoUpdateWhilePaused    bool `json:"noUpdateWhilePaused"`
	ZoomSearchWhilePaused  bool `json:"zoomSearchWhilePaused"`
	UnpauseRendersLatest   bool `json:"unpauseRendersLatest"`
	RapidToggleStable      bool `json:"rapidToggleStable"`
	SlashSearchWorks       bool `json:"slashSearchWorks"`
	EscapeResets           bool `json:"escapeResets"`
	ButtonMatchesKeyboard  bool `json:"buttonMatchesKeyboard"`
	TypingIgnoresShortcuts bool `json:"typingIgnoresShortcuts"`
}

type resetBaselineResult struct {
	HotkeyPrevented    bool `json:"hotkeyPrevented"`
	ShiftHotkeyIgnored bool `json:"shiftHotkeyIgnored"`
	HotkeyResetApplied bool `json:"hotkeyResetApplied"`
	ButtonResetApplied bool `json:"buttonResetApplied"`
	ResetCallsValid    bool `json:"resetCallsValid"`
}

type orderToggleResult struct {
	OrderButtonUpdated bool `json:"orderButtonUpdated"`
	OrderCallValid     bool `json:"orderCallValid"`
	OrderSnapshotShown bool `json:"orderSnapshotShown"`
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

func TestLiveHTMLJSPauseResumeAndKeyboard(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	snippet := `
const fg = liveFlamegraphState;
const keydown = __docListeners["keydown"];

function keyEvent(key, code, target) {
  let prevented = false;
  keydown({
    key: key,
    code: code,
    target: target || { tagName: "BODY", isContentEditable: false },
    preventDefault: function(){ prevented = true; }
  });
  return prevented;
}

let promptCalls = 0;
prompt = function(_msg, prev) {
  promptCalls++;
  return prev || "needle";
};

const pausePayload = "{\"n\":\"\",\"v\":0,\"t\":10,\"c\":[{\"n\":\"latest\",\"v\":10,\"t\":10}]}";
const beforeHTML = fg.svg.innerHTML;
const pausedBySpacePrevented = keyEvent(" ", "Space");
const pausedBySpace = pausedBySpacePrevented && fg.paused && fg.pauseBtn.textContent === "Resume" && fg.status.textContent.indexOf("PAUSED") === 0;

fg.eventSource.onmessage({ data: pausePayload });
const noUpdateWhilePaused = fg.pendingData === pausePayload && fg.svg.innerHTML === beforeHTML;

const pausedFrame = makeFrame("needle", "needle", 1, 0, 1200);
fg.frames = [pausedFrame];
fg.rootWidth = 1200;
fgZoom(pausedFrame);
prompt = function(_msg, prev) {
  promptCalls++;
  return prev || "needle";
};
fgSearch();
const zoomSearchWhilePaused = fg.zoomRange && fg.zoomRange.path === "needle" &&
  pausedFrame.querySelector("rect").getAttribute("fill") === fg.matchColor;

const resumedBySpacePrevented = keyEvent(" ", "Space");
const unpauseRendersLatest = resumedBySpacePrevented && !fg.paused && fg.pendingData === null &&
  fg.pauseBtn.textContent === "Pause" && fg.svg.innerHTML.indexOf('data-name="latest"') >= 0;

let rapidToggleStable = true;
for (let i = 0; i < 20; i++) {
  try {
    fgTogglePause();
  } catch (err) {
    rapidToggleStable = false;
  }
}
if (fg.paused) {
  fgTogglePause();
}
rapidToggleStable = rapidToggleStable && !fg.paused && fg.pauseBtn.textContent === "Pause";

promptCalls = 0;
prompt = function() {
  promptCalls++;
  return "slash";
};
const slashPrevented = keyEvent("/", "Slash");
const slashSearchWorks = slashPrevented && promptCalls === 1 && fg.searchQuery === "slash";

const escFrame = makeFrame("slash", "slash", 1, 0, 1200);
fg.frames = [escFrame];
fg.rootWidth = 1200;
fgZoom(escFrame);
fgSearch();
const escapePrevented = keyEvent("Escape", "Escape");
const escapeResets = escapePrevented && fg.zoomRange === null &&
  escFrame.querySelector("rect").getAttribute("fill") === escFrame.dataset.baseFill;

let buttonPromptCalls = 0;
prompt = function() {
  buttonPromptCalls++;
  return "button";
};
document.getElementById("btn-pause").listeners.click();
const pauseViaButton = fg.paused && fg.pauseBtn.textContent === "Resume";
document.getElementById("btn-pause").listeners.click();
const resumeViaButton = !fg.paused && fg.pauseBtn.textContent === "Pause";
document.getElementById("btn-search").listeners.click();
const searchViaButton = buttonPromptCalls === 1 && fg.searchQuery === "button";

const btnFrame = makeFrame("button", "button", 1, 0, 1200);
fg.frames = [btnFrame];
fg.rootWidth = 1200;
fgZoom(btnFrame);
document.getElementById("btn-reset-search").listeners.click();
document.getElementById("btn-reset-zoom").listeners.click();
const resetViaButton = fg.zoomRange === null &&
  btnFrame.querySelector("rect").getAttribute("fill") === btnFrame.dataset.baseFill;
const buttonMatchesKeyboard = pauseViaButton && resumeViaButton && searchViaButton && resetViaButton;

const typingTarget = { tagName: "INPUT", isContentEditable: false };
fg.searchQuery = "typed";
fg.zoomRange = { path: "typed", x: 0, w: 1200, depth: 1 };
promptCalls = 0;
const typingSpacePrevented = keyEvent(" ", "Space", typingTarget);
const typingSlashPrevented = keyEvent("/", "Slash", typingTarget);
const typingEscapePrevented = keyEvent("Escape", "Escape", typingTarget);
const typingIgnoresShortcuts = !typingSpacePrevented && !typingSlashPrevented && !typingEscapePrevented &&
  !fg.paused && promptCalls === 0 && fg.zoomRange !== null && fg.searchQuery === "typed";

console.log(JSON.stringify({
  pausedBySpace,
  noUpdateWhilePaused,
  zoomSearchWhilePaused,
  unpauseRendersLatest,
  rapidToggleStable,
  slashSearchWorks,
  escapeResets,
  buttonMatchesKeyboard,
  typingIgnoresShortcuts
}));
`

	out := runLiveHTMLNodeSnippet(t, snippet)
	var got pauseKeyboardResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode node result: %v\nraw:\n%s", err, out)
	}

	if !got.PausedBySpace {
		t.Fatalf("expected Space shortcut to pause and update status/button state")
	}
	if !got.NoUpdateWhilePaused {
		t.Fatalf("expected stream updates to queue while paused without rerendering")
	}
	if !got.ZoomSearchWhilePaused {
		t.Fatalf("expected zoom and search to work while paused")
	}
	if !got.UnpauseRendersLatest {
		t.Fatalf("expected unpause to render latest queued update immediately")
	}
	if !got.RapidToggleStable {
		t.Fatalf("expected rapid pause/unpause toggles to remain stable")
	}
	if !got.SlashSearchWorks {
		t.Fatalf("expected '/' shortcut to open search flow")
	}
	if !got.EscapeResets {
		t.Fatalf("expected Escape shortcut to reset zoom/search highlighting")
	}
	if !got.ButtonMatchesKeyboard {
		t.Fatalf("expected button actions to match keyboard behavior")
	}
	if !got.TypingIgnoresShortcuts {
		t.Fatalf("expected keyboard shortcuts to be ignored while typing in an input")
	}
}

func TestLiveHTMLJSResetBaselineHotkeyAndButton(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	snippet := `
const fg = liveFlamegraphState;
const keydown = __docListeners["keydown"];

function keyEvent(key, code, target) {
  let prevented = false;
  keydown({
    key: key,
    code: code,
    target: target || { tagName: "BODY", isContentEditable: false },
    preventDefault: function(){ prevented = true; }
  });
  return prevented;
}

const frame = makeFrame("needle", "needle", 1, 0, 1200);
fg.frames = [frame];
fg.rootWidth = 1200;
fgZoom(frame);
prompt = function(){ return "needle"; };
fgSearch();

const resetPayload = "{\"n\":\"\",\"v\":0,\"t\":0}";
const resetCalls = [];
fetch = function(url, opts) {
  resetCalls.push({
    url: url,
    method: (opts && opts.method) || "GET"
  });
  return Promise.resolve({
    ok: true,
    text: function() { return Promise.resolve(resetPayload); }
  });
};

const hotkeyPrevented = keyEvent("r", "KeyR");
const shiftHotkeyPrevented = keyEvent("R", "KeyR");
const shiftHotkeyIgnored = !shiftHotkeyPrevented && resetCalls.length === 1;

setTimeout(function() {
  const hotkeyResetApplied = fg.zoomRange === null && fg.searchQuery === "" && fg.frames.length === 0;

  const frame2 = makeFrame("again", "again", 1, 0, 1200);
  fg.frames = [frame2];
  fg.rootWidth = 1200;
  fgZoom(frame2);
  fg.searchQuery = "again";
  document.getElementById("btn-reset-baseline").listeners.click();

  setTimeout(function() {
    const buttonResetApplied = fg.zoomRange === null && fg.searchQuery === "" && fg.frames.length === 0;
    const resetCallsValid = resetCalls.length === 2 &&
      resetCalls[0].url === "/reset" && resetCalls[0].method === "POST" &&
      resetCalls[1].url === "/reset" && resetCalls[1].method === "POST";

    console.log(JSON.stringify({
      hotkeyPrevented,
      shiftHotkeyIgnored,
      hotkeyResetApplied,
      buttonResetApplied,
      resetCallsValid
    }));
  }, 0);
}, 0);
`

	out := runLiveHTMLNodeSnippet(t, snippet)
	var got resetBaselineResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode node result: %v\nraw:\n%s", err, out)
	}

	if !got.HotkeyPrevented {
		t.Fatalf("expected reset hotkey to prevent default browser handling")
	}
	if !got.ShiftHotkeyIgnored {
		t.Fatalf("expected uppercase 'R' to be ignored for baseline reset")
	}
	if !got.HotkeyResetApplied {
		t.Fatalf("expected 'r' hotkey to reset baseline and clear UI state")
	}
	if !got.ButtonResetApplied {
		t.Fatalf("expected Reset Baseline button to clear UI state")
	}
	if !got.ResetCallsValid {
		t.Fatalf("expected reset interactions to POST /reset")
	}
}

func TestLiveHTMLJSOrderToggle(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	snippet := `
const fg = liveFlamegraphState;
const orderCalls = [];
fetch = function(url, opts) {
  orderCalls.push({
    url: url,
    method: (opts && opts.method) || "GET",
    body: (opts && opts.body) || ""
  });
  return Promise.resolve({
    ok: true,
    json: function() {
      return Promise.resolve({
        fields: ["path", "tracepoint", "comm"],
        snapshot: {
          n: "",
          v: 0,
          t: 1,
          c: [{ n: "/tmp", v: 1, t: 1 }]
        }
      });
    }
  });
};

document.getElementById("btn-toggle-order").listeners.click();

setTimeout(function() {
  const orderButtonUpdated = document.getElementById("btn-toggle-order").textContent.indexOf("path > tracepoint > comm") >= 0;
  const orderSnapshotShown = fg.svg.innerHTML.indexOf('data-name="/tmp"') >= 0;
  const req = orderCalls[0] || {};
  let bodyFields = [];
  try {
    bodyFields = JSON.parse(req.body || "{}").fields || [];
  } catch (err) {
    bodyFields = [];
  }
  const orderCallValid = orderCalls.length === 1 &&
    req.url === "/order" &&
    req.method === "POST" &&
    JSON.stringify(bodyFields) === JSON.stringify(["path", "tracepoint", "comm"]);

  console.log(JSON.stringify({
    orderButtonUpdated,
    orderCallValid,
    orderSnapshotShown
  }));
}, 0);
`

	out := runLiveHTMLNodeSnippet(t, snippet)
	var got orderToggleResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode node result: %v\nraw:\n%s", err, out)
	}

	if !got.OrderButtonUpdated {
		t.Fatalf("expected toggle button label to update to next order")
	}
	if !got.OrderCallValid {
		t.Fatalf("expected toggle to POST /order with next preset fields")
	}
	if !got.OrderSnapshotShown {
		t.Fatalf("expected returned order snapshot to render immediately")
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
    getBoundingClientRect: function() { return { height: id === "controls" ? 56 : 0 }; },
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
["controls", "flamegraph", "status", "btn-pause", "btn-search", "btn-reset-search", "btn-undo-zoom", "btn-reset-zoom", "btn-reset-baseline", "btn-toggle-order"].forEach((id) => {
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
global.fetch = function() {
  return Promise.resolve({
    ok: true,
    json: function() { return Promise.resolve({ fields: ["comm", "path", "tracepoint"], snapshot: { n: "", v: 0, t: 0 } }); },
    text: function() { return Promise.resolve("{\"n\":\"\",\"v\":0,\"t\":0}"); }
  });
};
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
