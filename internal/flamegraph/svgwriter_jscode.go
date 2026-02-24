//go:build !js

package flamegraph

const flamegraphJS = `
const fg = {
  frames: [],
  info: null,
  matchColor: "rgb(220, 30, 70)",
};

function fgInit() {
  fg.frames = Array.from(document.querySelectorAll("g.frame"));
  fg.info = document.getElementById("fg-info");
  fg.frames.forEach((frame) => {
    frame.addEventListener("click", (ev) => fgZoom(ev.currentTarget));
    frame.addEventListener("mouseenter", (ev) => fgHover(ev.currentTarget));
  });
  document.addEventListener("dblclick", () => fgResetZoom());
}

function fgHover(frame) {
  if (!fg.info) return;
  const title = frame.querySelector("title");
  fg.info.textContent = title ? title.textContent : "";
}

function fgZoom(frame) {
  const x = Number(frame.dataset.x || "0");
  const w = Number(frame.dataset.w || "0");
  if (w <= 0) return;
  const end = x + w;
  fg.frames.forEach((other) => {
    const ox = Number(other.dataset.x || "0");
    const ow = Number(other.dataset.w || "0");
    const sameBand = Number(other.dataset.depth || "0") >= Number(frame.dataset.depth || "0");
    if (sameBand && ox >= x && ox + ow <= end) {
      other.style.display = "";
    } else {
      other.style.display = "none";
    }
  });
}

function fgResetZoom() {
  fg.frames.forEach((frame) => {
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

window.addEventListener("DOMContentLoaded", fgInit);
`
