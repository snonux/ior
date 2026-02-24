//go:build !js

package flamegraph

const flamegraphJS = `
const fg = {
  frames: [],
  info: null,
  matchColor: "rgb(220, 30, 70)",
  zoomStack: [],
  zoomRange: null,
  rootWidth: 0,
};

function fgInit() {
  fg.frames = Array.from(document.querySelectorAll("g.frame"));
  fg.info = document.getElementById("fg-info");
  fg.rootWidth = fgDetectRootWidth();
  fg.frames.forEach((frame) => {
    fgSnapshotOriginalGeometry(frame);
    frame.addEventListener("click", (ev) => {
      if (ev.detail > 1) return;
      ev.stopPropagation();
      fgZoom(ev.currentTarget);
    });
    frame.addEventListener("dblclick", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      fgResetZoom();
    });
    frame.addEventListener("mouseenter", (ev) => fgHover(ev.currentTarget));
  });
  document.addEventListener("dblclick", (ev) => {
    ev.preventDefault();
    fgResetZoom();
  });
}

function fgHover(frame) {
  if (!fg.info) return;
  const title = frame.querySelector("title");
  fg.info.textContent = title ? title.textContent : "";
}

function fgZoom(frame) {
  const x = fgOriginalX(frame);
  const w = fgOriginalW(frame);
  if (w <= 0) return;
  if (fg.zoomRange) {
    fg.zoomStack.push(fg.zoomRange);
  }
  fg.zoomRange = { x: x, w: w, depth: Number(frame.dataset.depth || "0") };
  fgApplyZoom();
}

function fgApplyZoom() {
  if (!fg.zoomRange) {
    fg.frames.forEach((frame) => {
      frame.style.display = "";
    });
    return;
  }
  const x = fg.zoomRange.x;
  const end = x + fg.zoomRange.w;
  const width = fg.zoomRange.w;
  const minDepth = fg.zoomRange.depth;
  const eps = 1e-6;
  const scale = fg.rootWidth / width;
  fg.frames.forEach((other) => {
    const ox = fgOriginalX(other);
    const ow = fgOriginalW(other);
    const depth = Number(other.dataset.depth || "0");
    const inSelectedRange = ox >= x-eps && ox+ow <= end+eps;
    const isAncestor = depth < minDepth && ox <= x+eps && ox+ow >= end-eps;

    if (isAncestor || (depth >= minDepth && inSelectedRange)) {
      if (isAncestor) {
        fgSetFrameGeometry(other, 0, fg.rootWidth);
      } else {
        fgSetFrameGeometry(other, (ox-x)*scale, ow*scale);
      }
      other.style.display = "";
    } else {
      other.style.display = "none";
    }
  });
}

function fgUndoZoom() {
  if (fg.zoomStack.length === 0) {
    fgResetZoom();
    return;
  }
  fg.zoomRange = fg.zoomStack.pop();
  fgApplyZoom();
}

function fgResetZoom() {
  fg.zoomStack = [];
  fg.zoomRange = null;
  fg.frames.forEach((frame) => {
    fgRestoreFrameGeometry(frame);
    frame.style.display = "";
  });
}

function fgSearch() {
  const needle = prompt("Search frames (substring):", "");
  if (needle === null) return;
  const q = needle.trim().toLowerCase();
  fg.frames.forEach((frame) => {
    const rect = frame.querySelector("rect");
    const base = frame.dataset.baseFill || "";
    const name = (frame.dataset.name || "").toLowerCase();
    if (!rect) return;
    if (q !== "" && name.includes(q)) {
      rect.style.fill = fg.matchColor;
    } else {
      rect.style.fill = base;
    }
  });
}

function fgResetSearch() {
  fg.frames.forEach((frame) => {
    const rect = frame.querySelector("rect");
    if (!rect) return;
    rect.style.fill = frame.dataset.baseFill || "";
  });
}

function fgDetectRootWidth() {
  let maxEnd = 0;
  fg.frames.forEach((frame) => {
    const x = Number(frame.dataset.x || "0");
    const w = Number(frame.dataset.w || "0");
    maxEnd = Math.max(maxEnd, x + w);
  });
  return maxEnd;
}

function fgSnapshotOriginalGeometry(frame) {
  const rect = frame.querySelector("rect");
  const text = frame.querySelector("text");
  frame.dataset.ox = frame.dataset.x || "0";
  frame.dataset.ow = frame.dataset.w || "0";
  if (rect) {
    rect.dataset.ox = rect.getAttribute("x") || "0";
    rect.dataset.ow = rect.getAttribute("width") || "0";
  }
  if (text) {
    text.dataset.ox = text.getAttribute("x") || "0";
    text.dataset.hidden = text.style.display === "none" ? "1" : "0";
    text.dataset.full = text.textContent || frame.dataset.name || "";
  }
}

function fgOriginalX(frame) {
  return Number(frame.dataset.ox || frame.dataset.x || "0");
}

function fgOriginalW(frame) {
  return Number(frame.dataset.ow || frame.dataset.w || "0");
}

function fgSetFrameGeometry(frame, x, w) {
  const rect = frame.querySelector("rect");
  const text = frame.querySelector("text");
  if (rect) {
    rect.setAttribute("x", String(x));
    rect.setAttribute("width", String(w));
  }
  if (text) {
    text.setAttribute("x", String(x + 3));
    fgFitLabel(text, w);
  }
}

function fgRestoreFrameGeometry(frame) {
  const rect = frame.querySelector("rect");
  const text = frame.querySelector("text");
  if (rect) {
    rect.setAttribute("x", rect.dataset.ox || "0");
    rect.setAttribute("width", rect.dataset.ow || "0");
  }
  if (text) {
    text.setAttribute("x", text.dataset.ox || "0");
    if (text.dataset.hidden === "1") {
      text.style.display = "none";
      text.textContent = text.dataset.full || "";
    } else {
      fgFitLabel(text, Number(rect ? (rect.dataset.ow || "0") : "0"));
    }
  }
}

function fgFitLabel(text, width) {
  const full = text.dataset.full || text.textContent || "";
  const maxChars = Math.floor((width - 6) / 7);
  if (maxChars < 3) {
    text.style.display = "none";
    text.textContent = full;
    return;
  }
  text.style.display = "";
  if (full.length <= maxChars) {
    text.textContent = full;
    return;
  }
  text.textContent = full.slice(0, maxChars - 1) + "…";
}

window.addEventListener("DOMContentLoaded", fgInit);
`
