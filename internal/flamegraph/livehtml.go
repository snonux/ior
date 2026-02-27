package flamegraph

const liveHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>I/O Flame Graph (Live)</title>
  <style>
    :root {
      --fg-bg: #f6f1ea;
      --fg-panel: #fbf7f1;
      --fg-border: #d8cdc0;
      --fg-text: #232323;
      --fg-muted: #5f5f5f;
      --fg-accent: #7b2d1f;
      --fg-btn: #efe2d2;
      --fg-btn-hover: #e6d5c1;
      --fg-paused: #b02222;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background: linear-gradient(180deg, #f8f2ea 0%, #f2e9dc 100%);
      color: var(--fg-text);
      font-family: monospace;
    }

    #controls {
      position: sticky;
      top: 0;
      z-index: 1;
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      padding: 10px 12px;
      background: var(--fg-panel);
      border-bottom: 1px solid var(--fg-border);
    }

    #controls button {
      border: 1px solid var(--fg-border);
      background: var(--fg-btn);
      color: var(--fg-text);
      font: inherit;
      font-size: 12px;
      line-height: 1.2;
      padding: 6px 10px;
      cursor: pointer;
    }

    #controls button:hover {
      background: var(--fg-btn-hover);
    }

    #status {
      margin-left: 8px;
      font-size: 12px;
      color: var(--fg-muted);
    }

    .paused #status {
      color: var(--fg-paused);
      font-weight: 700;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }

    #flamegraph {
      display: block;
      width: 100%;
      min-height: calc(100vh - 56px);
      background: transparent;
    }

    .title {
      font-size: 14px;
      font-family: monospace;
    }

    .controls text {
      font-size: 12px;
      font-family: monospace;
      cursor: pointer;
      fill: #444;
    }

    .frame text {
      font-size: 11px;
      font-family: monospace;
      pointer-events: none;
      fill: #111;
    }

    .frame rect {
      stroke: rgba(0, 0, 0, 0.18);
      stroke-width: 0.5;
    }
  </style>
</head>
<body>
  <div id="controls">
    <button id="btn-pause" type="button">Pause</button>
    <button id="btn-search" type="button">Search</button>
    <button id="btn-reset-search" type="button">Reset Search</button>
    <button id="btn-undo-zoom" type="button">Undo Zoom</button>
    <button id="btn-reset-zoom" type="button">Reset Zoom</button>
    <span id="status">LIVE</span>
  </div>

  <svg id="flamegraph" xmlns="http://www.w3.org/2000/svg"></svg>

  <script>
    (function () {
      var fg = {
        paused: false,
        pendingData: null,
        zoomRange: null,
        searchQuery: '',
        eventSource: null,
        svg: document.getElementById('flamegraph'),
        status: document.getElementById('status'),
        cfg: {
          width: 1200,
          frameHeight: 16,
          fontSize: 12,
          minWidthPx: 1.0
        }
      };

      function fgFrameColor(name) {
        var bytes = new TextEncoder().encode(name || "");
        var h = 2166136261 >>> 0;
        for (var i = 0; i < bytes.length; i++) {
          h ^= bytes[i];
          h = Math.imul(h, 16777619) >>> 0;
        }
        var r = 200 + (h % 35);
        var g = 80 + ((h >>> 8) % 120);
        var b = 40 + ((h >>> 16) % 90);
        return "rgb(" + r + "," + g + "," + b + ")";
      }

      function fgMaxDepth(node, depth) {
        if (!node || !Array.isArray(node.c) || node.c.length === 0) {
          return depth;
        }
        var maxDepth = depth;
        for (var i = 0; i < node.c.length; i++) {
          var childDepth = fgMaxDepth(node.c[i], depth + 1);
          if (childDepth > maxDepth) {
            maxDepth = childDepth;
          }
        }
        return maxDepth;
      }

      function fgBuildFrames(node, rootTotal, x, depth, canvasHeight, isRoot, out) {
        if (!node || rootTotal <= 0) {
          return;
        }
        if (!isRoot) {
          var w = fg.cfg.width * (Number(node.t || 0) / Number(rootTotal));
          if (w < fg.cfg.minWidthPx) {
            return;
          }
          var y = canvasHeight - ((depth + 1) * fg.cfg.frameHeight);
          var total = Number(node.t || 0);
          var pct = 100 * total / Number(rootTotal);
          out.push({
            name: node.n || "",
            x: x,
            y: y,
            w: w,
            h: fg.cfg.frameHeight - 1,
            depth: depth,
            total: total,
            pct: pct,
            fill: fgFrameColor(node.n || "")
          });
        }

        var cursor = x;
        var children = Array.isArray(node.c) ? node.c : [];
        for (var i = 0; i < children.length; i++) {
          var child = children[i];
          var childTotal = Number(child.t || 0);
          var childWidth = fg.cfg.width * (childTotal / Number(rootTotal));
          fgBuildFrames(child, rootTotal, cursor, depth + 1, canvasHeight, false, out);
          cursor += childWidth;
        }
      }

      function fgEscape(value) {
        return String(value || '')
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&apos;');
      }

      function fgApplySearch() {
        if (!fg.searchQuery) {
          return;
        }
        var query = fg.searchQuery.toLowerCase();
        var frames = fg.svg.querySelectorAll('.frame');
        for (var i = 0; i < frames.length; i++) {
          var frame = frames[i];
          if (String(frame.getAttribute('data-name') || '').toLowerCase().indexOf(query) < 0) {
            continue;
          }
          var rect = frame.querySelector('rect');
          if (rect) {
            rect.setAttribute('fill', 'rgb(220,30,70)');
          }
        }
      }

      function fgApplyZoom() {
        if (!fg.zoomRange) {
          return;
        }
        var frames = fg.svg.querySelectorAll('.frame');
        for (var i = 0; i < frames.length; i++) {
          var frame = frames[i];
          if (frame.getAttribute('data-name') !== fg.zoomRange.name) {
            continue;
          }
          frame.classList.add('zoom-target');
          break;
        }
      }

      function fgBindFrameEvents() {
        var frames = fg.svg.querySelectorAll('.frame');
        for (var i = 0; i < frames.length; i++) {
          frames[i].addEventListener('mouseenter', function () {
            var name = this.getAttribute('data-name') || '';
            fg.status.textContent = fg.paused ? 'PAUSED | ' + name : 'LIVE | ' + name;
          });
          frames[i].addEventListener('mouseleave', function () {
            fg.status.textContent = fg.paused ? 'PAUSED' : 'LIVE';
          });
          frames[i].addEventListener('click', function () {
            fg.zoomRange = { name: this.getAttribute('data-name') || '' };
            fgApplyZoom();
          });
        }
      }

      function fgRender(treeData) {
        if (!treeData || Number(treeData.t || 0) <= 0) {
          fg.svg.innerHTML = '';
          return;
        }
        var rootTotal = Number(treeData.t || 0);
        var maxDepth = fgMaxDepth(treeData, 0);
        var canvasHeight = (fg.cfg.frameHeight * (maxDepth + 1)) + 80;
        var frames = [];
        fgBuildFrames(treeData, rootTotal, 0, 0, canvasHeight, true, frames);

        var parts = [];
        parts.push('<text class="title" x="10" y="22">I/O Flame Graph (Live)</text>');
        for (var i = 0; i < frames.length; i++) {
          var frame = frames[i];
          var textStyle = frame.w <= (fg.cfg.fontSize * 2) ? ' style="display:none"' : '';
          var title = fgEscape(frame.name + ' (' + frame.total + ', ' + frame.pct.toFixed(2) + '%)');
          parts.push('<g class="frame" data-name="' + fgEscape(frame.name) + '" data-x="' + frame.x.toFixed(3) +
            '" data-w="' + frame.w.toFixed(3) + '" data-depth="' + frame.depth +
            '" data-base-fill="' + frame.fill + '">');
          parts.push('<title>' + title + '</title>');
          parts.push('<rect x="' + frame.x.toFixed(3) + '" y="' + frame.y.toFixed(3) + '" width="' + frame.w.toFixed(3) +
            '" height="' + frame.h.toFixed(3) + '" fill="' + frame.fill + '"></rect>');
          parts.push('<text x="' + (frame.x + 3).toFixed(3) + '" y="' + (frame.y + fg.cfg.fontSize).toFixed(3) + '"' +
            textStyle + '>' + fgEscape(frame.name) + '</text>');
          parts.push('</g>');
        }

        fg.svg.setAttribute('viewBox', '0 0 ' + fg.cfg.width + ' ' + canvasHeight);
        fg.svg.setAttribute('preserveAspectRatio', 'xMinYMin meet');
        fg.svg.innerHTML = parts.join('');
        fgBindFrameEvents();
      }

      function fgProcessUpdate(jsonStr) {
        var treeData;
        try {
          treeData = JSON.parse(jsonStr);
        } catch (err) {
          fg.status.textContent = 'LIVE | parse error';
          return;
        }
        fgRender(treeData);
        fgApplyZoom();
        fgApplySearch();
      }

      function fgConnect() {
        fg.eventSource = new EventSource('/events');
        fg.eventSource.onmessage = function (e) {
          if (fg.paused) {
            fg.pendingData = e.data;
            return;
          }
          requestAnimationFrame(function () {
            fgProcessUpdate(e.data);
          });
        };
        fg.eventSource.onerror = function () {
          fg.status.textContent = fg.paused ? 'PAUSED' : 'LIVE | stream error';
        };
      }

      var pauseBtn = document.getElementById("btn-pause");
      var searchBtn = document.getElementById("btn-search");
      var resetSearchBtn = document.getElementById("btn-reset-search");
      pauseBtn.addEventListener("click", function () {
        fg.paused = !fg.paused;
        document.body.classList.toggle("paused", fg.paused);
        pauseBtn.textContent = fg.paused ? "Resume" : "Pause";
        fg.status.textContent = fg.paused ? "PAUSED" : "LIVE";
        if (!fg.paused && fg.pendingData) {
          var pending = fg.pendingData;
          fg.pendingData = null;
          requestAnimationFrame(function () {
            fgProcessUpdate(pending);
          });
        }
      });
      searchBtn.addEventListener('click', function () {
        var query = window.prompt('Search frame substring:', fg.searchQuery || '');
        if (query === null) {
          return;
        }
        fg.searchQuery = query;
        fgApplySearch();
      });
      resetSearchBtn.addEventListener('click', function () {
        fg.searchQuery = '';
        var rects = fg.svg.querySelectorAll('.frame rect');
        for (var i = 0; i < rects.length; i++) {
          var baseFill = rects[i].parentElement.getAttribute('data-base-fill');
          if (baseFill) {
            rects[i].setAttribute('fill', baseFill);
          }
        }
      });

      fgConnect();

      window.fgFrameColor = fgFrameColor;
      window.fgBuildFrames = fgBuildFrames;
      window.fgMaxDepth = fgMaxDepth;
      window.fgRender = fgRender;
      window.fgProcessUpdate = fgProcessUpdate;
      window.liveFlamegraphState = fg;
    })();
  </script>
</body>
</html>
`
