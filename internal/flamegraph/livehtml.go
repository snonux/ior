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
      var paused = false;
      var pauseBtn = document.getElementById("btn-pause");
      var status = document.getElementById("status");
      pauseBtn.addEventListener("click", function () {
        paused = !paused;
        document.body.classList.toggle("paused", paused);
        pauseBtn.textContent = paused ? "Resume" : "Pause";
        status.textContent = paused ? "PAUSED" : "LIVE";
      });
    })();
  </script>
</body>
</html>
`
