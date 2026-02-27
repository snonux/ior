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
      height: calc(100vh - 56px);
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
    <button id="btn-reset-baseline" type="button">Reset Baseline</button>
    <span id="status">LIVE</span>
  </div>

  <svg id="flamegraph" xmlns="http://www.w3.org/2000/svg"></svg>

  <script>
    (function () {
      var fg = {
        paused: false,
        resetting: false,
        lastTreeData: null,
        pendingData: null,
        searchQuery: '',
        zoomStack: [],
        zoomRange: null,
        frames: [],
        rootWidth: 0,
        matchColor: 'rgb(220,30,70)',
        eventSource: null,
        svg: document.getElementById('flamegraph'),
        status: document.getElementById('status'),
        pauseBtn: document.getElementById('btn-pause'),
        searchBtn: document.getElementById('btn-search'),
        resetSearchBtn: document.getElementById('btn-reset-search'),
        undoZoomBtn: document.getElementById('btn-undo-zoom'),
        resetZoomBtn: document.getElementById('btn-reset-zoom'),
        resetBaselineBtn: document.getElementById('btn-reset-baseline'),
        cfg: {
          baseWidth: 1200,
          baseFrameHeight: 16,
          width: 1200,
          frameHeight: 16,
          fontSize: 12,
          minWidthPx: 1.0
        }
      };

      function fgFrameColor(name) {
        var bytes = new TextEncoder().encode(name || '');
        var h = 2166136261 >>> 0;
        for (var i = 0; i < bytes.length; i++) {
          h ^= bytes[i];
          h = Math.imul(h, 16777619) >>> 0;
        }
        var r = 200 + (h % 35);
        var g = 80 + ((h >>> 8) % 120);
        var b = 40 + ((h >>> 16) % 90);
        return 'rgb(' + r + ',' + g + ',' + b + ')';
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

      function fgDefaultCanvasHeight(maxDepth) {
        return (fg.cfg.baseFrameHeight * (maxDepth + 1)) + 80;
      }

      function fgViewportLayout(maxDepth) {
        var rows = Math.max(maxDepth + 1, 1);
        var defaultCanvasHeight = fgDefaultCanvasHeight(maxDepth);
        var viewportWidth = Number(window.innerWidth || 0);
        if (viewportWidth <= 0 && document && document.documentElement) {
          viewportWidth = Number(document.documentElement.clientWidth || 0);
        }
        if (viewportWidth <= 0) {
          viewportWidth = fg.cfg.baseWidth;
        }
        var viewportHeight = Number(window.innerHeight || 0);
        if (viewportHeight <= 0) {
          return {
            width: viewportWidth,
            frameHeight: fg.cfg.baseFrameHeight,
            canvasHeight: defaultCanvasHeight
          };
        }

        var controls = document.getElementById('controls');
        var controlsHeight = 56;
        if (controls && typeof controls.getBoundingClientRect === 'function') {
          controlsHeight = Number(controls.getBoundingClientRect().height || controlsHeight);
        }

        var availableHeight = viewportHeight - controlsHeight;
        if (availableHeight <= 0) {
          return {
            width: viewportWidth,
            frameHeight: fg.cfg.baseFrameHeight,
            canvasHeight: defaultCanvasHeight
          };
        }

        var canvasHeight = Math.max(defaultCanvasHeight, availableHeight);
        var frameHeight = (canvasHeight - 80) / rows;
        if (frameHeight < fg.cfg.baseFrameHeight) {
          frameHeight = fg.cfg.baseFrameHeight;
        }
        return {
          width: viewportWidth,
          frameHeight: frameHeight,
          canvasHeight: canvasHeight
        };
      }

      function fgVisibleChildrenTotal(node) {
        var children = Array.isArray(node && node.c) ? node.c : [];
        var total = 0;
        for (var i = 0; i < children.length; i++) {
          total += Number(children[i].t || 0);
        }
        if (total > 0) {
          return total;
        }
        return Number(node && node.t || 0);
      }

      function fgBuildFrames(node, rootTotal, x, width, depth, canvasHeight, isRoot, out, path) {
        if (!node || rootTotal <= 0 || width <= 0) {
          return;
        }
        var currentPath = path || '';
        if (!isRoot) {
          var w = width;
          if (w < fg.cfg.minWidthPx) {
            return;
          }
          var name = node.n || '';
          currentPath = currentPath ? (currentPath + '\u001f' + name) : name;
          var y = canvasHeight - ((depth + 1) * fg.cfg.frameHeight);
          var total = Number(node.t || 0);
          var pct = 100 * total / Number(rootTotal);
          out.push({
            name: name,
            path: currentPath,
            x: x,
            y: y,
            w: w,
            h: fg.cfg.frameHeight - 1,
            depth: depth,
            total: total,
            pct: pct,
            fill: fgFrameColor(name)
          });
        }
        var cursor = x;
        var children = Array.isArray(node.c) ? node.c : [];
        var childrenTotal = fgVisibleChildrenTotal(node);
        if (childrenTotal <= 0) {
          return;
        }
        for (var i = 0; i < children.length; i++) {
          var child = children[i];
          var childTotal = Number(child.t || 0);
          if (childTotal <= 0) {
            continue;
          }
          var childWidth = width * (childTotal / childrenTotal);
          fgBuildFrames(child, rootTotal, cursor, childWidth, depth + 1, canvasHeight, false, out, currentPath);
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

      function fgSetStatus(suffix) {
        var prefix = fg.paused ? 'PAUSED' : 'LIVE';
        fg.status.textContent = suffix ? (prefix + ' | ' + suffix) : prefix;
      }

      function fgHover(frame) {
        var title = frame.querySelector('title');
        fgSetStatus(title ? title.textContent : '');
      }

      function fgDetectRootWidth() {
        var maxEnd = 0;
        for (var i = 0; i < fg.frames.length; i++) {
          var x = Number(fg.frames[i].dataset.x || '0');
          var w = Number(fg.frames[i].dataset.w || '0');
          if (x + w > maxEnd) {
            maxEnd = x + w;
          }
        }
        return maxEnd;
      }

      function fgSnapshotOriginalGeometry(frame) {
        var rect = frame.querySelector('rect');
        var text = frame.querySelector('text');
        frame.dataset.ox = frame.dataset.x || '0';
        frame.dataset.ow = frame.dataset.w || '0';
        if (rect) {
          rect.dataset.ox = rect.getAttribute('x') || '0';
          rect.dataset.ow = rect.getAttribute('width') || '0';
        }
        if (text) {
          text.dataset.ox = text.getAttribute('x') || '0';
          text.dataset.hidden = text.style.display === 'none' ? '1' : '0';
          text.dataset.full = text.textContent || frame.dataset.name || '';
        }
      }

      function fgOriginalX(frame) {
        return Number(frame.dataset.ox || frame.dataset.x || '0');
      }

      function fgOriginalW(frame) {
        return Number(frame.dataset.ow || frame.dataset.w || '0');
      }

      function fgFitLabel(text, width) {
        var full = text.dataset.full || text.textContent || '';
        var maxChars = Math.floor((width - 6) / 7);
        if (maxChars < 3) {
          text.style.display = 'none';
          text.textContent = full;
          return;
        }
        text.style.display = '';
        if (full.length <= maxChars) {
          text.textContent = full;
          return;
        }
        text.textContent = full.slice(0, maxChars - 1) + '...';
      }

      function fgSetFrameGeometry(frame, x, w) {
        var rect = frame.querySelector('rect');
        var text = frame.querySelector('text');
        if (rect) {
          rect.setAttribute('x', String(x));
          rect.setAttribute('width', String(w));
        }
        if (text) {
          text.setAttribute('x', String(x + 3));
          fgFitLabel(text, w);
        }
      }

      function fgRestoreFrameGeometry(frame) {
        var rect = frame.querySelector('rect');
        var text = frame.querySelector('text');
        if (rect) {
          rect.setAttribute('x', rect.dataset.ox || '0');
          rect.setAttribute('width', rect.dataset.ow || '0');
        }
        if (text) {
          text.setAttribute('x', text.dataset.ox || '0');
          if (text.dataset.hidden === '1') {
            text.style.display = 'none';
            text.textContent = text.dataset.full || '';
          } else {
            fgFitLabel(text, Number(rect ? (rect.dataset.ow || '0') : '0'));
          }
        }
      }

      function fgZoom(frame) {
        var width = fgOriginalW(frame);
        if (width <= 0) {
          return;
        }
        if (fg.zoomRange) {
          fg.zoomStack.push(fg.zoomRange);
        }
        fg.zoomRange = {
          x: fgOriginalX(frame),
          w: width,
          depth: Number(frame.dataset.depth || '0'),
          path: frame.dataset.path || ''
        };
        fgApplyZoom();
      }

      function fgFindFrameByPath(path) {
        for (var i = 0; i < fg.frames.length; i++) {
          if ((fg.frames[i].dataset.path || '') === path) {
            return fg.frames[i];
          }
        }
        return null;
      }

      function fgRefreshZoomRange() {
        if (!fg.zoomRange || !fg.zoomRange.path) {
          return;
        }
        var candidatePath = fg.zoomRange.path;
        var match = null;
        while (candidatePath) {
          match = fgFindFrameByPath(candidatePath);
          if (match) {
            break;
          }
          var cut = candidatePath.lastIndexOf('\u001f');
          if (cut < 0) {
            break;
          }
          candidatePath = candidatePath.slice(0, cut);
        }
        if (!match) {
          return;
        }
        var width = fgOriginalW(match);
        if (width <= 0) {
          return;
        }
        fg.zoomRange.path = match.dataset.path || candidatePath;
        fg.zoomRange.x = fgOriginalX(match);
        fg.zoomRange.w = width;
        fg.zoomRange.depth = Number(match.dataset.depth || String(fg.zoomRange.depth || 0));
      }

      function fgApplyZoom() {
        if (!fg.zoomRange) {
          for (var i = 0; i < fg.frames.length; i++) {
            fgRestoreFrameGeometry(fg.frames[i]);
            fg.frames[i].style.display = '';
          }
          return;
        }
        fgRefreshZoomRange();
        var x = fg.zoomRange.x;
        var end = x + fg.zoomRange.w;
        var width = fg.zoomRange.w;
        var minDepth = fg.zoomRange.depth;
        var scale = fg.rootWidth > 0 ? fg.rootWidth / width : 1;
        var eps = 1e-6;
        for (var i = 0; i < fg.frames.length; i++) {
          var frame = fg.frames[i];
          var ox = fgOriginalX(frame);
          var ow = fgOriginalW(frame);
          var depth = Number(frame.dataset.depth || '0');
          var inRange = (ox >= x - eps) && (ox + ow <= end + eps);
          var isAncestor = depth < minDepth && ox <= x + eps && ox + ow >= end - eps;
          if (isAncestor || (depth >= minDepth && inRange)) {
            if (isAncestor) {
              fgSetFrameGeometry(frame, 0, fg.rootWidth);
            } else {
              fgSetFrameGeometry(frame, (ox - x) * scale, ow * scale);
            }
            frame.style.display = '';
          } else {
            frame.style.display = 'none';
          }
        }
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
        fgApplyZoom();
      }

      function fgResetSearch() {
        for (var i = 0; i < fg.frames.length; i++) {
          var rect = fg.frames[i].querySelector('rect');
          if (!rect) {
            continue;
          }
          rect.setAttribute('fill', fg.frames[i].dataset.baseFill || '');
        }
      }

      function fgApplySearch() {
        fgResetSearch();
        if (!fg.searchQuery) {
          return;
        }
        var query = fg.searchQuery.toLowerCase();
        for (var i = 0; i < fg.frames.length; i++) {
          var name = (fg.frames[i].dataset.name || '').toLowerCase();
          if (name.indexOf(query) < 0) {
            continue;
          }
          var rect = fg.frames[i].querySelector('rect');
          if (rect) {
            rect.setAttribute('fill', fg.matchColor);
          }
        }
      }

      function fgSearch() {
        var query = window.prompt('Search frame substring:', fg.searchQuery || '');
        if (query === null) {
          return;
        }
        fg.searchQuery = query.trim();
        fgApplySearch();
      }

      function fgTogglePause() {
        fg.paused = !fg.paused;
        document.body.classList.toggle('paused', fg.paused);
        fg.pauseBtn.textContent = fg.paused ? 'Resume' : 'Pause';
        fgSetStatus('');
        if (!fg.paused && fg.pendingData) {
          var pending = fg.pendingData;
          fg.pendingData = null;
          requestAnimationFrame(function () {
            fgProcessUpdate(pending);
          });
        }
      }

      function fgClearLocalState() {
        fg.pendingData = null;
        fg.searchQuery = '';
        fg.zoomStack = [];
        fg.zoomRange = null;
      }

      function fgResetBaseline() {
        if (fg.resetting) {
          return;
        }
        fg.resetting = true;
        fgSetStatus('resetting baseline...');
        fetch('/reset', { method: 'POST' })
          .then(function (resp) {
            if (!resp.ok) {
              throw new Error('reset failed');
            }
            return resp.text();
          })
          .then(function (payload) {
            fgClearLocalState();
            fgProcessUpdate(payload);
            fgSetStatus('baseline reset');
          })
          .catch(function () {
            fgSetStatus('reset failed');
          })
          .then(function () {
            fg.resetting = false;
          });
      }

      function fgBindFrameEvents() {
        for (var i = 0; i < fg.frames.length; i++) {
          fg.frames[i].addEventListener('mouseenter', function () { fgHover(this); });
          fg.frames[i].addEventListener('mouseleave', function () { fgSetStatus(''); });
          fg.frames[i].addEventListener('click', function (ev) {
            if (ev.detail > 1) {
              return;
            }
            ev.stopPropagation();
            fgZoom(ev.currentTarget);
          });
          fg.frames[i].addEventListener('dblclick', function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            fgResetZoom();
          });
        }
      }

      function fgRender(treeData) {
        var maxDepth = fgMaxDepth(treeData, 0);
        var layout = fgViewportLayout(maxDepth);
        fg.cfg.width = layout.width;
        fg.cfg.frameHeight = layout.frameHeight;

        if (!treeData || Number(treeData.t || 0) <= 0) {
          fg.svg.style.height = String(layout.canvasHeight) + 'px';
          fg.svg.setAttribute('viewBox', '0 0 ' + fg.cfg.width + ' ' + layout.canvasHeight);
          fg.svg.setAttribute('preserveAspectRatio', 'xMinYMin meet');
          fg.frames = [];
          fg.svg.innerHTML = '';
          fgSetStatus('');
          return;
        }

        var rootTotal = fgVisibleChildrenTotal(treeData);
        if (rootTotal <= 0) {
          rootTotal = Number(treeData.t || 0);
        }
        var canvasHeight = layout.canvasHeight;
        var frames = [];
        fgBuildFrames(treeData, rootTotal, 0, fg.cfg.width, 0, canvasHeight, true, frames, '');

        var parts = [];
        parts.push('<text class="title" x="10" y="22">I/O Flame Graph (Live)</text>');
        for (var i = 0; i < frames.length; i++) {
          var frame = frames[i];
          var textStyle = frame.w <= (fg.cfg.fontSize * 2) ? ' style="display:none"' : '';
          var title = fgEscape(frame.name + ' (' + frame.total + ', ' + frame.pct.toFixed(2) + '%)');
          parts.push('<g class="frame" data-name="' + fgEscape(frame.name) + '" data-path="' + fgEscape(frame.path) +
            '" data-x="' + frame.x.toFixed(3) + '" data-w="' + frame.w.toFixed(3) +
            '" data-depth="' + frame.depth + '" data-base-fill="' + frame.fill + '">');
          parts.push('<title>' + title + '</title>');
          parts.push('<rect x="' + frame.x.toFixed(3) + '" y="' + frame.y.toFixed(3) + '" width="' + frame.w.toFixed(3) +
            '" height="' + frame.h.toFixed(3) + '" fill="' + frame.fill + '"></rect>');
          parts.push('<text x="' + (frame.x + 3).toFixed(3) + '" y="' + (frame.y + fg.cfg.fontSize).toFixed(3) + '"' +
            textStyle + '>' + fgEscape(frame.name) + '</text>');
          parts.push('</g>');
        }

        fg.svg.setAttribute('viewBox', '0 0 ' + fg.cfg.width + ' ' + canvasHeight);
        fg.svg.setAttribute('preserveAspectRatio', 'xMinYMin meet');
        fg.svg.style.height = String(canvasHeight) + 'px';
        fg.svg.innerHTML = parts.join('');
        fg.frames = Array.prototype.slice.call(fg.svg.querySelectorAll('g.frame'));
        fg.rootWidth = fgDetectRootWidth();
        for (var j = 0; j < fg.frames.length; j++) {
          fgSnapshotOriginalGeometry(fg.frames[j]);
        }
        fgBindFrameEvents();
      }

      function fgProcessUpdate(jsonStr) {
        var treeData;
        try {
          treeData = JSON.parse(jsonStr);
        } catch (err) {
          fgSetStatus('parse error');
          return;
        }
        fg.lastTreeData = treeData;
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
          fgSetStatus('stream error');
        };
      }

      function fgHandleResize() {
        if (!fg.lastTreeData) {
          return;
        }
        requestAnimationFrame(function () {
          fgRender(fg.lastTreeData);
          fgApplyZoom();
          fgApplySearch();
        });
      }

      function fgIsTextEntryTarget(target) {
        if (!target) {
          return false;
        }
        if (target.isContentEditable) {
          return true;
        }
        var tag = (target.tagName || '').toUpperCase();
        return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
      }

      function fgHandleKeydown(ev) {
        if (fgIsTextEntryTarget(ev.target)) {
          return;
        }
        if (ev.key === ' ' || ev.code === 'Space') {
          ev.preventDefault();
          fgTogglePause();
          return;
        }
        if (ev.key === '/') {
          ev.preventDefault();
          fgSearch();
          return;
        }
        if (ev.key === 'r') {
          ev.preventDefault();
          fgResetBaseline();
          return;
        }
        if (ev.key === 'Escape') {
          ev.preventDefault();
          fgResetZoom();
          fgResetSearch();
        }
      }

      fg.pauseBtn.addEventListener('click', fgTogglePause);
      fg.searchBtn.addEventListener('click', fgSearch);
      fg.resetSearchBtn.addEventListener('click', fgResetSearch);
      fg.undoZoomBtn.addEventListener('click', fgUndoZoom);
      fg.resetZoomBtn.addEventListener('click', fgResetZoom);
      fg.resetBaselineBtn.addEventListener('click', fgResetBaseline);
      document.addEventListener('keydown', fgHandleKeydown);
      window.addEventListener('resize', fgHandleResize);

      fgSetStatus('');
      fgConnect();

      window.fgFrameColor = fgFrameColor;
      window.fgBuildFrames = fgBuildFrames;
      window.fgMaxDepth = fgMaxDepth;
      window.fgRender = fgRender;
      window.fgProcessUpdate = fgProcessUpdate;
      window.fgZoom = fgZoom;
      window.fgApplyZoom = fgApplyZoom;
      window.fgUndoZoom = fgUndoZoom;
      window.fgResetZoom = fgResetZoom;
      window.fgSearch = fgSearch;
      window.fgResetSearch = fgResetSearch;
      window.fgTogglePause = fgTogglePause;
      window.fgResetBaseline = fgResetBaseline;
      window.liveFlamegraphState = fg;
    })();
  </script>
</body>
</html>
`
