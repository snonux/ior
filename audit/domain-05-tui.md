# Domain 5 — TUI Dashboard & User Interaction (Audit Report)

> Historical audit evidence for the commit named below. Use [README.md](../README.md) and [AGENTS.md](../AGENTS.md) for current behavior.

**Project**: ior (I/O Riot NG) at `/home/paul/git/ior`
**Audit basis**: `PLAN-PROJECT-AUDIT.md` (repo root), section "## Domain 5 — TUI Dashboard & User Interaction", items 5.1–5.6 (21 checklist bullets).
**Commit audited**: working tree at `5f91899` ("audit(domain-04)…", HEAD) plus the known uncommitted deletions of `docs/syscall-tracing-plan.md` / `docs/clickhouse-streaming-plan.md` (pre-existing, not restored per audit constraints; already recorded in domain-01..04 reports).
**Plan drift known in advance**: the plan (and `AGENTS.md`) describe **8 tabs including a Non-IO tab (shortcut `8`)**. Commit `5736381` removed the Non-IO tab (tabs are now **1–7**, with family data surfaced as a **Family column** in the Syscalls tab); commits `a1a1b518` (`[`/`]` family-scope cycling) and `2897495` (filter-scoped Syscalls rows via `visibleSyscallRows`) changed the filtering interaction model. This audit verifies the **current** behavior and flags every plan-vs-code mismatch explicitly (drift items **D1–D5** below).

**Auditor constraints**: no root (`sudo -n true` fails), no interactive tty — every bullet that requires driving the live TUI against BPF (`sudo ./ior`, live PID-picker runs, manual flame/stream observation) is marked **BLOCKED-needs-root / BLOCKED-needs-tty** and is instead mapped to the **in-process TUI integration suite** (`internal/tui_integration_test.go`, 62 teatest tests that drive the *production* `tui.Model` through real key presses against a VT emulator — same model wiring `--testflames`/`--testliveflames` use, no root, no eBPF) plus unit tests and code review. No `mage build`; no source modifications; no `ask` CLI.

**Verification commands run** (all read-only; the only file created is the helper `audit/check/tuihelp/main.go` in the permitted `audit/check/` area — it constructs the production model in-process and prints check results, writing nothing):

```
$ go test -count=1 -timeout=30m ./internal/tui/...
  ok ior/internal/tui 0.598s          ok ior/internal/tui/common    0.057s
  ok ior/internal/tui/dashboard 0.288s ok ior/internal/tui/eventstream 37.034s
  ok ior/internal/tui/export 0.016s    ok ior/internal/tui/flamegraph 5.408s
  ?   ior/internal/tui/messages [no test files]
  ok ior/internal/tui/pidpicker 0.043s ok ior/internal/tui/probes 0.027s
  ok ior/internal/tui/tracefilter 0.031s
$ go test -race -count=1 ./internal/tui/...        → ok all 10 pkgs (eventstream 229.6s under -race), race-clean
$ go test -count=1 ./integrationtests/...          → ok (every BPF test t.Skip's: "requires root for BPF")
$ # root `internal` package (owns tui_integration_test.go) — CGO env replicated from Magefile.go goEnv():
$ LIBBPFGO=… CGO_CFLAGS=… CGO_LDFLAGS=… GOARCH=amd64 GOOS=linux \
    go test -count=1 -v -run 'TestTUIIntegration_' ./internal/
  → 62/62 PASS, 0 FAIL, 0 SKIP (ok ior/internal 12.386s)
$ go run ./audit/check/tuihelp        → 3/3 checks OK (see 5.2b / 5.4d evidence)
$ go vet ./internal/tui/...           → clean
```

The orchestrator's `mage test` was green for every package except the known `TestSyscallTracingPlanBytesClassificationStaysInSync` failure (uncommitted `docs/syscall-tracing-plan.md` deletion — not a TUI finding; not fixed per constraints).

---

## 5.1 PID Picker

**Plan item**: "Launch `sudo ./ior` and verify the initial screen shows a searchable process list. Test filtering by typing process names; confirm that the list narrows in real time. Test arrow-key navigation and Enter selection; confirm the dashboard starts tracing the selected PID. Verify that the PID picker respects the configured `PidFilter` when provided via CLI."

### 5.1a — Initial screen shows a searchable process list — **PASS (live launch BLOCKED-needs-root → mapped)**

Code path: with no `-pid`, `newModelWithRuntimeConfig` starts on `ScreenPIDPicker` (`internal/tui/tui.go:402-446`, `screen: ScreenPIDPicker` at 440); the picker's `Init()` starts `scanCmd()` → `ScanProcesses()` which reads `/proc` (`internal/tui/pidpicker/proclist.go:29-56`), and the view renders a "Filter: " textinput plus the list and an always-present "All PIDs" pseudo-row (`internal/tui/pidpicker/model.go:229-262`). Mapped evidence: `TestTUIIntegration_PidPicker_FilterSelectAllToDashboard` (`internal/tui_integration_test.go:1757-1773`) drives the real model and asserts the picker chrome renders ("Select PID", "Filter: ", "> All PIDs"); unit tests `TestScanProcessesFrom`, `TestApplyFilterByPIDCommAndCmdline`. The literal `sudo ./ior` launch is BLOCKED-needs-root (root-gated by `tuiModeHandler.run`, `internal/ior_mode_registry.go`).

### 5.1b — Typing narrows the list in real time — **PASS**

Every non-navigation keystroke flows through `textinput.Update` + `applyFilter()` (`internal/tui/pidpicker/model.go:140-146, 240-260`); `matchesQuery` (`model.go:262-270`) substring-matches on PID digits, `comm`, and `cmdline` (case-insensitive). Locked by `TestApplyFilterByPIDCommAndCmdline` (`internal/tui/pidpicker/model_test.go:12-36`) and end-to-end by the integration test typing "zzz" (`internal/tui_integration_test.go:1767-1770`: real rows narrow away while "All PIDs" stays). Typing while blurred auto-focuses the input (`model.go:171-176`).

### 5.1c — Arrow-key navigation + Enter selection starts tracing the selected PID — **PASS (live attach BLOCKED-needs-root → mapped)**

Up/Down move `selectedIndex` and blur the input (`internal/tui/pidpicker/model.go:161-171`); `renderRows` keeps the selection scrolled into view (`model.go:276-296`, `TestRenderRowsKeepsSelectionVisible`). Enter → `emitSelection()` emits `PidSelectedMsg` (`model.go:173-201`, unit-locked by `TestEnterEmitsAllPIDsAndSelectedPID`, `TestEnterEmitsAllTIDsAndSelectedTIDInTIDMode`); `Model.handlePidSelected` (`internal/tui/tui.go:907-921`) stops any prior trace, resets the stream buffer, sets the PID filter, switches to the dashboard and starts `beginTraceCmd()` with `attaching=true` and the "Attaching tracepoints..." spinner. Mapped end-to-end evidence: `TestTUIIntegration_PidPicker_FilterSelectAllToDashboard` (Enter → dashboard "view:root") and `TestTUIIntegration_PidPicker_ReselectEscReturns` / `TestTUIIntegration_TidPicker_*` (reselect flow); the *actual BPF attach* of a selected real PID is BLOCKED-needs-root (production wiring verified in code: `tuiModeHandler.run` → `tui.RunWithTraceStarterConfig` → `tuiTraceStarterFromRunTrace`, `internal/ior.go:282-339`).

### 5.1d — Picker respects the configured `PidFilter` from CLI — **PASS**

With `-pid N` the picker is bypassed entirely: `RunWithTraceStarterConfig` passes `cfg.PidFilter` as the initial PID (`internal/tui/tui.go:282-289`), `resolveStartupPIDFilters` (`tui.go:452-459`) forces `tid=-1` when an initial PID is given, and `newModelWithRuntimeConfig` (`tui.go:441-448`) starts directly on `ScreenDashboard` with `attaching=true` — the trace starts immediately for the configured PID without the picker. Locked by `TestInitialPIDSkipsPickerAndStartsTracing` (`internal/tui/tui_test.go:113-123`). Note (design, not defect): "respects" means *skips the picker*; the picker never renders a pre-filtered list.

**Item 5.1 verdict: PASS (4/4 bullets; 5.1a/5.1c live portions mapped from the root-gated in-process suite).**

---

## 5.2 Tab Navigation & Rendering

**Plan item**: "For each tab (1–8), verify: correct shortcut key activates it, `tab`/`shift+tab` and `h`/`l` / `left`/`right` arrows cycle tabs, tab content refreshes without crashing, numeric keys (`1`–`8`) jump directly. Test that `H` toggles the help panel and that help text reflects the current mode (e.g., export disabled when `-tuiExport=false`). Verify that the Non-IO tab (shortcut `8`) shows per-family aggregate rows and that its content matches the `Snapshot.Families` data."

### 5.2a — Shortcut keys, cycle keys, refresh, numeric jumps — **PASS (with drift D1/D2)**

Current behavior (verified):
- **7 tabs, keys 1–7**: the tab registry (`internal/tui/dashboard/tabs.go:9-33` `TabOverview…TabFlame`; `tabregistry.go:64-198` descriptors with `ShortcutKey: k.One…k.Seven`) yields exactly Flame(1), Overview(2), Syscalls(3), Files(4), Processes(5), Latency+Gaps(6), Stream(7). The key map has no `Eight` binding (`internal/tui/common/keys.go:57-66`); numeric dispatch is registry-driven (`tabForShortcutKey`, `tabregistry.go:225-240`). End-to-end: `TestTUIIntegration_TabNav_NumberKeys` walks 2→3→4→5→6→7→1 asserting populated content per tab (`internal/tui_integration_test.go:375-397`); `TestTUIIntegration_AllTabs_RenderPopulatedAndKeepChrome` (1241-1265) asserts each tab renders seeded data **plus the persistent chrome** (tab bar + status line).
- **tab / shift+tab cycle**: `handleShortcutKey` (`internal/tui/dashboard/model.go:674-681`) with `nextTab`/`prevTab` wrapping (`tabs.go:37-56`); `TestTUIIntegration_TabNav_TabAndShiftTab` (399-411) drives Overview→Syscalls→Overview; `TestTabNavigationWraps` (`internal/tui/dashboard/tabs_test.go:10`).
- **Content refreshes without crashing**: the whole 62-test integration suite (including tab switches interleaved with ticks, resize `TestTUIIntegration_Resize_NarrowThenWide`, help toggles, modal open/close) passes, the unit suites for all 10 `internal/tui/*` packages are green, and `-race` is clean.
- **Drift D1 (plan)**: "tabs 1–8 / Non-IO tab 8" no longer exists — see 5.2c.
- **Drift D2 (plan + AGENTS.md:77)**: "`h`/`l` / `left`/`right` arrows cycle tabs" is **not** current behavior. `h/l/left/right` are table **column** navigation keys (`tabScroll*` → `common.HandleTableNavigationKey`, `tabregistry.go:210-251`; help text "left/right table col", `internal/tui/common/keys.go:133-136`), flame-graph navigation keys, or stream paused-view column keys — they never change the active tab. Tab switching is `tab`/`shift+tab` + `1..7` only. Current behavior is self-consistent and unit/integration-locked (`TestTUIIntegration_Syscalls_ColumnNav`); the plan/AGENTS.md claim is stale (the `h/l` table-col help lines predate the plan).

### 5.2b — `H` toggles help; help text reflects the export mode — **PASS (with findings F2/F3/F4)**

- `H` toggles the **global help overlay**: the top-level model intercepts every "H" when not attaching/erroring (`internal/tui/tui.go:667-681`, `isHelpOverlayOpenKey`), renders `renderGlobalHelpOverlay(m.helpSections())`, and closes on `H`/`Esc`/`q`/`?` (`tui.go:689-696`). Integration-locked: `TestTUIIntegration_HelpOverlay_Toggle` (`internal/tui_integration_test.go:413-421`: H → "Help"+"Dashboard Tabs", Esc → back).
- Help reflects `-tuiExport=false`: the disabled binding (`keys.Export = key.NewBinding()`, `tui.go:405-409`) drops the "e stream export" hint from the overlay (`internal/tui/help.go:51-58`, conditional append) and from the binding lists (`internal/tui/common/keys.go:119-127` `globalStatusBindings` skips help-less bindings; same gate in `DashboardFullHelp`). Verified by running the production model in-process (`go run ./audit/check/tuihelp`): with export enabled the overlay contains "e stream export"; with `TUIExportEnable=false` it does not. The `e` key itself is gated at `handleDashboardShortcutKeys` (`tui.go:747-749`) and double-guarded in `runExportCmd` (`tui.go:1255-1263`).
- **Findings**: (F3) the only test claiming to lock hint-hiding, `TestStatusBarHidesExportBindingWhenExportDisabled` (`internal/tui/tui_test.go:2013-2024`), is **vacuous** — it asserts absence of "e stream export" from the *hint-mode* view where that token never renders in either configuration (proven by the helper, which renders both configs); the real gating lives in the overlay path, which has no test. (F4) the dashboard model's own `showHelp` expanded help bar (`internal/tui/dashboard/model.go:646-657`) is unreachable via keyboard in the composed TUI because the top-level "H" intercept always wins (acknowledged in `TestTUIIntegration_Stream_PausedFooterShowsSelection`'s comment: "the global H overlay shadows the dashboard H"); it is only exercised as an isolated dashboard unit (`TestHelpToggleWithH`, `internal/tui/dashboard/model_test.go:1561-1579`).

### 5.2c — Non-IO tab (shortcut 8) shows per-family aggregate rows — **N-A (removed by design; drift D1; current equivalent PASS)**

**Drift D1**: commit `5736381` ("feat(dashboard): drop Non-IO tab; add Family column to Syscalls tab") deleted `TabNonIO`, the `nonio.go` renderer, the "8" key binding, and all non-IO model state. The plan's tab-8 verification is therefore **N-A against current code**. The current-behavior equivalent — per-syscall family visibility — is fully implemented and tested:
- The Syscalls tab has a **Family column** (index 1) in both layouts (`internal/tui/dashboard/syscalls.go:45-80`; rendered from `s.TraceID.Family()` at 246-277), sortable (`syscallSortKeyFamily`, `syscalls.go:24-27, 116-121`), and `Enter` on that column pushes a `family~<F>` filter (`internal/tui/dashboard/model.go:407-428`).
- Global `[`/`]` family-scope cycling (commit `a1a1b518`): `internal/tui/familycycle.go:51-61` + `tui.go:767-773`, replace-not-push via `replaceGlobalFilter` (`tui.go:1070-1078`); locked by `TestTUIIntegration_FamilyCycleHotkeys` (wrap-around, stack label must not grow) and `TestTUIIntegration_FamilyCycleScopesSyscallsTab` (rows actually scoped: Misc/AIO → "Syscalls: no data", Polling → only `epoll_wait`), plus `familycycle_test.go` rank math.
- `Snapshot.Families` still exists and is still computed by the stats engine (`internal/statsengine/snapshot.go:231`, `engine.go:325`, covered in domain-03) but now has **no TUI consumer** — the only per-family surface is the Family column. Leftover note for maintainers: `AGENTS.md:78` still documents the removed tab.

**Item 5.2 verdict: PASS for 5.2a/5.2b (with drift D1/D2 and findings F2/F3/F4), N-A for 5.2c (plan describes removed functionality; current family-scoping behavior verified PASS).**

---

## 5.3 Flamegraph Tab

**Plan item**: "Start a trace and switch to tab `1`; confirm the flamegraph renders bars with recognizable labels. Run a continuously varying workload and confirm bars grow/shift in real time (not just static once). Test with `-tui-fast-refresh=0` and confirm the flamegraph still updates at the standard tick rate."

### 5.3a — Tab 1 renders bars with recognizable labels — **PASS (live trace BLOCKED-needs-root → mapped)**

Tab 1 (Flame) is the dashboard's default active tab (`internal/tui/dashboard/model.go:143-145`, `NewModelWithConfig` → `activeTab: TabFlame`). The in-process suite drives the production model seeded with synthetic stacks (comms `api`/`worker`/`ingest`/`batch`) and asserts recognizable labels: `TestTUIIntegration_Launch_ShowsDashboardChrome` ("view:root", "Selected: root", "press H for help"), `TestTUIIntegration_Flame_NavigateFrames` ("Selected: api" → "batch"), `TestTUIIntegration_Flame_ZoomInOut` ("view:root/api"), plus search/pause/order/metric/sibling tests — 16 flame interaction tests, all PASS. Live BPF tracing is BLOCKED-needs-root; the flame model itself (`internal/tui/flamegraph/`) is green under unit tests and `-race`.

### 5.3b — Bars grow/shift in real time under a varying workload — **PASS (mapped)**

`TestTUIIntegration_Live_FlamegraphUpdatesOverTime` (`internal/tui_integration_test.go:1932-1938`) runs `--testliveflames` (the same live-refresh machinery the CLI uses: `tuiTestLiveFlamesStarter` reshapes the synthetic trie every `LiveInterval` in a background goroutine) and requires **≥2 distinct `total(events)=N` values** within the wait window — proving continuous re-render, not a static first frame. `TestTUIIntegration_Live_PauseFreezesUpdates` proves the freeze/pause counterpart (totals constant while paused). Cadence: the flame tab runs a high-frequency tick (`flameTickMsg`) that re-arms itself and refreshes from the live trie in the background (`internal/tui/dashboard/model.go:255-273, 1569-1578`). A real BPF-fed workload is BLOCKED-needs-root; the synthetic live mode exercises the identical TUI refresh path.

### 5.3c — `-tui-fast-refresh=0`: flamegraph still updates — **PASS (code-verified; docs drift D3)**

Wiring: `RunWithTraceStarterConfig` applies `cfg.TUIFastRefreshInterval` via `SetFastRefreshInterval` (`internal/tui/tui.go:282-289`; default 250 ms, `internal/flags/flags.go:111,215`). `SetFastRefreshInterval(0)` resets to zero (`internal/tui/dashboard/model.go:1053-1063`), and `flameTickCmd`/`streamTickCmd` then fall back to the package constants `flameRefreshMs`/`streamRefreshMs` = **200 ms** (`model.go:1569-1578, 1592-1600`) — i.e. with the flag at `0` the flame tab **still updates** (and `handleFlameTick` unconditionally re-arms, `model.go:255-263`, so the tick chain cannot die), so the plan's observable claim holds. **Drift D3**: `AGENTS.md` says `0` "falls back to the standard dashboard cadence" — inaccurate; the fallback is the 200 ms package constant, not the 1 s dashboard `refreshTick` (`defaultRefreshMs`, `model.go:31`). The CLI help ("0 = disable high-frequency refresh", `flags.go:215-216`) is likewise imprecise. No test pins the flag-at-0 cadence (noted as a coverage gap); the fallback constants are covered by the tab InitCmd wiring in the integration suite.

**Item 5.3 verdict: PASS (3/3; live-trace portions mapped to the in-process flames/liveflames suites; drift D3 on the AGENTS.md fast-refresh wording).**

---

## 5.4 Stream Tab & Export

**Plan item**: "Switch to the Stream tab and confirm live rows appear with correct fields. Press `e` to open the export modal; confirm it proposes a filename `ior-stream-<timestamp>.csv`. Complete the export and verify the written file contains the same rows visible in the stream snapshot (respecting any active filters). Verify that when `-tuiExport=false`, the `e` key hint is hidden and the export modal does not open."

### 5.4a — Stream tab renders live rows with correct fields — **PASS (mapped)**

`TestTUIIntegration_Stream_RowsRender` clears the seeded `pid=1` filter and asserts live chrome ("buffer:", "Filter: all") plus seeded rows ("api", "/srv"); `TestTUIIntegration_Stream_RendersLiveChrome` asserts the header columns ("Comm", "Syscall"); `TestTUIIntegration_Stream_PauseSelectsAndNavigates` asserts row data ("18.4us", "Sel 1/", "Col 1/10"). The on-disk field set is defined in `internal/tui/eventstream/export.go:172-186`: `seq,time_ns,gap_ns,latency_ns,comm,pid,tid,syscall,fd,ret,bytes,file,error,family,requested_sleep_ns` — locked by `TestWriteStreamCSVAppendsFamilyColumn` (incl. `family` and `requested_sleep_ns` values). All 14 stream interaction tests PASS.

### 5.4b — `e` export modal and the `ior-stream-<timestamp>.csv` filename — **PASS (drift D4 on "proposes a filename")**

`e` opens the top-level export modal (`tui.go:747-749`, gated by `m.exportEnabled`) — an **options** modal ("Export Stream CSV" → "CSV stream rows"/"Cancel", `internal/tui/export/model.go:29-32, 100-115`); it does **not** display a filename. On Enter it emits `RequestMsg` → `runExportCmd` → `dashboard.ExportStreamCSV()` (`internal/tui/dashboard/model.go:1071-1073`) → `streamModel.ExportSnapshotToCSV("")` → `exportSnapshotToCSV` fills the empty name with `defaultStreamExportFilename()` = `fmt.Sprintf("ior-stream-%s.csv", time.Now().Format("20060102-150405"))` (`internal/tui/eventstream/export.go:112-121`), written into the default `exportDir "."` (cwd). **Drift D4**: the plan's "confirm it proposes a filename" matches the *stream* `X` ("export as") modal, which does pre-fill that default name (`eventstream/model.go:285`), not the `e` modal. The net observable artifact — a file named `ior-stream-YYYYMMDD-HHMMSS.csv` — is exactly what the plan expects and is locked end-to-end: `TestTUIIntegration_Export_SubmitWritesCSV` (`internal/tui_integration_test.go:675-762`) presses `e` → Enter, waits for "Exported: …ior-stream-", polls the isolated temp dir for `ior-stream-*.csv`, and reads the file back. User-supplied names are sanitized (`.csv` suffix appended, directory components stripped — `ensureCSVFilename`, `export.go:226-247`, `TestEnsureCSVFilenamePathTraversal`).

### 5.4c — Exported file contains the same rows as the filtered stream snapshot — **PASS (with nuance)**

`ExportSnapshotToCSV` snapshots the live **source** ring buffer and applies the current filter row-by-row (`export.go:116-134`, `filter.Matches(&ev)`), so the export respects the active global filter (which the top-level model syncs into the stream model on every change, `internal/tui/dashboard/model.go:1094-1097` `SetGlobalFilter` → `streamModel.SetFilter`). Locked by `TestRunExportCmdCSVWritesFilteredStreamSnapshot` (`internal/tui/tui_test.go:1308-1367`: 3 pushed rows, `comm~firefox` filter → only firefox rows exported) and by `TestTUIIntegration_Export_SubmitWritesCSV` (the seeded rows only enter the export after the pid filter is cleared — filter-respecting by construction). Nuance (by design, documented in code): the `e` path exports a **fresh** source snapshot ("exports a fresh filtered snapshot … without mutating the model's paused/live view state", `export.go:248-252`); the paused on-screen frame is exported verbatim by the stream `x` key instead (`exportFilteredToCSV`, defined `internal/tui/eventstream/export.go:254-256`, invoked from the paused `x` key at `eventstream/model.go:272`). So "same rows visible in the stream snapshot" holds in the filtered-snapshot sense; a paused stream is a frozen view while `e` re-snapshots the buffer.

### 5.4d — `-tuiExport=false`: `e` hint hidden, modal does not open — **PASS (for the plan's scope; finding F1 on stream x/X/E)**

- Hint hidden: disabled key binding (`tui.go:405-409`) + conditional help (`help.go:51-58`, `common/keys.go:119-127`) — verified in-process by `go run ./audit/check/tuihelp` ("overlay hides 'e stream export' when -tuiExport=false (and shows it when enabled)").
- Modal does not open: `handleDashboardShortcutKeys` gates on `m.exportEnabled` (`tui.go:747-749`); locked by `TestExportKeyIgnoredWhenExportDisabled` (`internal/tui/tui_test.go:1265-1277`); `runExportCmd` also refuses when disabled ("tui export is disabled by -tuiExport=false", `tui.go:1255-1263`).
- **Finding F1**: the flag does **not** disable the stream tab's own CSV export shortcuts. While paused on the Stream tab, `x` (export now), `X` (export as), and `E` (open last) still write `ior-stream-<timestamp>.csv` files (`internal/tui/eventstream/model.go:264-301`, `exportDir` default `.`) and their help hints ("stream: x/X export  E open", `help.go:84`; `dashboardStatusBindings`, `keys.go:130-133`) are always rendered — nothing in the eventstream model knows about `TUIExportEnable`. Given the flag help "Enable TUI CSV snapshot export files" (`flags.go:217`), a user running `-tuiExport=false` to prevent TUI CSV writes can still produce them via `x`/`X`. See Findings for severity/repro.

**Item 5.4 verdict: PASS (4/4 within the plan's stated scope; drift D4 on "proposes a filename"; finding F1 that x/X/E escape the -tuiExport=false gate; vacuous-test F3 noted under 5.2b).**

---

## 5.5 Runtime Filter Stack

**Plan item**: "Inside the TUI, apply filters (PID, TID, path, comm) one at a time and in combination. Confirm that the dashboard updates immediately without restarting the BPF trace. Verify that the filter stack is persisted across trace restarts (if applicable) and that the BPF probes are not re-attached. Check that the stream export respects the currently active filter stack."

### 5.5a — Apply PID, TID, path, comm filters individually and combined — **PASS (mapped)**

- Filter modal (`f`): fields Syscall/Comm/File/PID/TID/FD/Latency/Gap/Bytes/Ret/Errors (`internal/tui/tracefilter`); combined edits apply on Esc as one global filter. `TestTUIIntegration_FilterModal_EditApplyClear` (`internal/tui_integration_test.go:1096-1135`) applies `syscall~read` **combined with the startup `pid=1`** → status line "filter: syscall~read pid=1" + "stack: syscall~read", then clears everything → "filter: all"; `TestTUIIntegration_FilterModal_UndoFilter` pops with `F`.
- Enter-on-cell pushes dimension-specific predicates: stream `comm~api` (`TestTUIIntegration_Stream_EnterPushFilterThenUndo`), Syscalls `syscall~write` / Family-column `family~FS` (`TestTUIIntegration_Syscalls_EnterPushesFilter`, `…EnterFamilyColumnPushesFilter`), Files `file~<path>`, Processes `pid=<n>`/`comm~<n>` (`internal/tui/dashboard/model.go:357-405, 632-650`; unit tests `TestFilesTabEnterEmitsGlobalFilterRequest`, `TestProcessesTabEnterCommColumnEmitsCommFilterRequest`). TID filters via the TID picker (`t` → `TidSelectedMsg` → `setProcessFilters`, `tui.go:925-945`; `TestTidSelectedTransitionsToDashboardAndSetsTIDFilter`).
- Combinations are composable because each push **clones** the current filter and overwrites one dimension (`filterStack.push`, `internal/tui/filterstack.go:40-62`); labels for every dimension are generated by `globalFilterActionLabel` (`filterstack.go:131-160`, covering syscall/family/comm/file/pid/tid/fd/latency/gap/bytes/ret), and history is capped at 50 levels with oldest-eviction (`filterstack.go:15-18, 57-61`).
- **Drift D2-adjacent note**: the plan says "PID, TID, path, comm" — all four are supported (plus syscall/family/fd/latency/gap/bytes/ret/errors), so the plan's list is a subset, not a mismatch.

### 5.5b — Dashboard updates immediately without restarting the BPF trace — **PASS (seam-mapped)**

Filter changes route through `applyGlobalFilter`/`replaceGlobalFilter`/`undoGlobalFilter` → `reapplyActiveFilter` (`internal/tui/tui.go:1060-1113`), which **first tries the in-place live swap**: `runtimeBindings.applyLiveFilter` invokes the setter registered by the trace starter (`tui.go:186-198`). That setter is `el.SetFilter` (`internal/ior.go:285`), an `atomic.Pointer[globalfilter.Filter]` store (`internal/eventloop.go:92-95`) — no `tracer.stop()`, no re-attach, no "Attaching tracepoints" overlay; only the dashboard aggregates are cleared (`PrepareForTraceRestart`) and the live trie is re-bound (`tui.go:1088-1096`, with an explanatory comment about the flame tab). The restart fallback runs only when no trace is live (e.g. first invocation or test doubles). Seam-locked by `TestTuiTraceStarterAppliesLiveFilterSwapInPlace` (`internal/ior_mode_test.go:828-887`): after the trace is running, invoking the registered `SetLiveFilterSetter` callback changes which events the eventloop's `printCb` admits **without any restart of the trace pipeline**. Immediate stream re-filtering is locked by `TestSetFilterReappliesCurrentBufferedRows` (`internal/tui/eventstream/model_test.go:225-241`). Coverage gap (noted, not a defect): no test registers a live setter on the *composed TUI model* (the `--testflames` starter doesn't install one, so integration tests exercise the restart fallback branch; the live-swap branch is covered at the seam test + code-review level).

### 5.5c — Filter stack persisted across restarts; BPF probes not re-attached — **PASS**

The `filterStack` (active filter + up to 50 undo levels + label stack) is TUI-owned state that survives `tracer.stop()`/`beginTraceCmd()` cycles — the restart fallback in `reapplyActiveFilter`/`undoGlobalFilter` stops and restarts the trace but keeps `m.filters` intact, and PID/TID changes rebind process constraints across the **whole history** so undo cannot restore a stale PID (`internal/tui/filterstack.go:96-105`, `rebindProcessFilters`). Locked by `TestGlobalFilterApplyPreservesBufferedStreamRowsAcrossRestart` (`internal/tui/tui_test.go:602-651`: filter apply → restart → historical rows survive and re-filter), `TestGlobalFilterApplyAdvancesRuntimeFilterEpochAndKeepsRecorder` (653-684: epoch advances, recorder survives restart), `TestGlobalFilterApplyKeepsActiveRecordingAcrossRestart` (907-941), and `TestTuiTraceStarterFromRunTracePersistsRecorderAcrossRestarts` (`internal/ior_mode_test.go:746-825`). "BPF probes not re-attached": true for the live-swap path (no restart occurs at all — see 5.5b); when the fallback restart *does* run (no live trace), re-attachment is by design. Live BPF-level confirmation is BLOCKED-needs-root; the no-restart property is enforced structurally (the live-swap branch contains no `tracer.stop()` call).

### 5.5d — Stream export respects the active filter stack — **PASS**

`ExportStreamCSV` → `ExportSnapshotToCSV` filters the source snapshot with the stream model's filter, which the top-level model keeps synchronized with the global filter on every filter change (`SetGlobalFilter` → `streamModel.SetFilter`, `internal/tui/dashboard/model.go:1094-1097`; `SetFilterStack` also forwards the label stack for display, `model.go:1099-1103`). Locked by `TestRunExportCmdCSVWritesFilteredStreamSnapshot` (only `comm~firefox` rows exported out of three pushed rows) and `TestTUIIntegration_Export_SubmitWritesCSV` (seeded rows appear in the export only after the `pid=1` filter is cleared — the same filter the stream view uses).

**Item 5.5 verdict: PASS (4/4; live-trace portions mapped; one coverage-gap note on the composed-model live-swap branch).**

---

## 5.6 Recording Modal (Parquet)

**Plan item**: "Review `internal/tui/recordingmodal.go` — note: this is the **Parquet recording** modal (opened by pressing `R`), **not** the `.ior.zst` flamegraph recorder… Verify that the Parquet recording start/stop cycle (keys `R` → enter filename → `R` again to stop) creates a `.parquet` file with correct schema and row data. Confirm that recording does not block the event loop or UI refresh (the `parquet.Recorder` uses a bounded queue and background flush goroutine)."

### 5.6a — `recordingmodal.go` is the Parquet `R` modal — **PASS**

Confirmed: `recordingModal` (`internal/tui/recordingmodal.go:12-122`) is titled "Start Parquet Recording", bound to key `R` (`internal/tui/common/keys.go:80`; `handleRecordKey`, `tui.go:792-803`). `R` toggles: if a recording is active, `R` stops it; otherwise it opens the modal pre-filled with `defaultParquetRecordingFilename()` = `ior-recording-<YYYYMMDD-HHMMSS>.parquet` (`internal/tui/tracelifecycle.go:160-162`, with `R`-stop/`R`-start toggling in `tui.go:792-803`). The `.ior.zst` collapsed-stack recorder is the headless `-flamegraph` path only (verified in domain-04; no zst writer exists anywhere under `internal/tui/`). The modal rejects blank filenames ("filename is required", `recordingmodal.go:83-87`; `TestRecordModalRejectsBlankFilename`), and `SetError` re-opens the modal with the recorder's error on failed start (`tui.go:846-855`).

### 5.6b — `R` → filename → `R` stop creates a valid `.parquet` with correct schema and row data — **PASS (mapped)**

End-to-end UI cycle: `TestTUIIntegration_Recording_SubmitWritesParquet` (`internal/tui_integration_test.go:1028-1093`) drives `R` → modal with pre-filled `ior-recording-` name → Enter (start; dashboard chrome shows "rec: …recording-<ts>.parquet") → `R` again ("rec: off") → polls the isolated temp dir for `ior-recording-*.parquet` and asserts the `PAR1` magic at **both** ends (complete footer written by the graceful stop). `TestTUIIntegration_Recording_ModalOpenClose` covers Esc-cancel. Row data/schema: in `--testflames` no live event loop feeds the recorder (the row sink is the production `printCb` at `internal/ior.go:258-272`), so the integration file is row-empty — the plan's row-data claim is covered by (a) `TestTuiTraceStarterFromRunTracePersistsRecorderAcrossRestarts` (`internal/ior_mode_test.go:746-825`), which pushes two events through the **production** `printCb`/`Recorder.Record` path and reads back `seq` and `FilterEpoch` (0 then 1) from the written file, and (b) the parquet writer/recorder unit suite + domain-04's independent `audit/check/parquetwrite` → pyarrow verification of the on-disk schema (incl. `requested_sleep_ns`). A real BPF-fed recording is BLOCKED-needs-root.

### 5.6c — Recording does not block the event loop or UI refresh — **PASS**

`parquet.Recorder` design (`internal/parquet/recorder.go`): `Start` opens the writer and launches the session consumer as a **background goroutine** (`go r.runSession(session, writer, cfg)`, `recorder.go:109-131`); rows are queued on a **bounded channel** (default `QueueCapacity` 4096, `recorder.go:12`) and `enqueue` is non-blocking (`select`/`default`, `recorder.go:326-345`) — on overflow the session stops accepting with `ErrRecorderQueueFull` (batching: 256 rows/`BatchSize`, 250 ms flush ticker, `recorder.go:183-222`). The event loop's `printCb` calls `Recorder.Record` synchronously but never blocks, and a recorder failure surfaces exactly once as a stream warning row (`internal/ior.go:265-271`, `recorderWarningOnce`). UI keeps refreshing while recording: the integration test asserts the "rec:" status renders on the live dashboard chrome (snapshot ticks keep flowing), `SetRecordingStatus` is re-synced on every start/stop (`recorderStart`/`recorderStop` call the `syncFn` that re-syncs the status bar, `tracelifecycle.go:111-137`), and recording survives filter restarts (`TestGlobalFilterApplyKeepsActiveRecordingAcrossRestart`). Concurrency safety: the full `internal/tui/...` suite is green under `-race` (all 10 packages).

**Item 5.6 verdict: PASS (3/3; row-data portion mapped to the production-seam test + parquet unit suite since live BPF feeding is root-gated).**

---

## Findings

No High-severity defects were found in Domain 5. Confirmed issues, in severity order:

### F1 — `-tuiExport=false` does not disable the stream tab's `x`/`X`/`E` CSV export shortcuts — **Severity: Medium (behavioral/expectation gap)**

- **Where**: `internal/tui/eventstream/model.go:264-301` (`handleStreamExportKey` — `x` writes `ior-stream-<timestamp>.csv` to the cwd when paused, `X` opens the export-as modal, `E` re-opens the last export); help always advertises them (`internal/tui/help.go:84` "stream: x/X export  E open"; `internal/tui/common/keys.go:130-133`). Nothing in the eventstream model knows `TUIExportEnable`.
- **Repro** (no root needed to demonstrate the write path; live TUI needs root to trace, `--testflames` shows the same keys working): run the TUI with `-tuiExport=false`, switch to the Stream tab (`7`), pause (`space`), press `x` → a CSV appears in the current directory despite the flag help "Enable TUI CSV snapshot export files" (`internal/flags/flags.go:217`).
- **Suggested fix**: thread the export-enabled flag into `eventstream.Model` (e.g. `SetExportEnabled(bool)` set from `newDashboardWithRuntime`/`SetGlobalFilter`-style sync) and no-op `x`/`X`/`E` plus hide their hints when disabled — mirroring the existing `keys.Export` gating. (Not fixed per audit constraints.)

### F2 — Help overlay advertises a nonexistent 8th tab — **Severity: Low (stale user-facing help text)**

- **Where**: `internal/tui/help.go:72` — "tab/shift+tab tabs  **1..8 jump tab**  r reset baseline  R parquet rec", although tabs are 1–7 since commit `5736381` (the "8"/Non-IO tab was removed and `common.KeyMap.Eight` deleted).
- **Repro**: any TUI session → press `H` → read the "Dashboard Tabs" section; pressing `8` does nothing (no binding matches; `tabForShortcutKey` iterates only the 7 registered tabs).
- **Suggested fix**: change the literal to "1..7 jump tab". Verified live via `go run ./audit/check/tuihelp` ("drift confirmed: help overlay still says '1..8 jump tab'").

### F3 — `TestStatusBarHidesExportBindingWhenExportDisabled` is vacuous — **Severity: Low (test-quality)**

- **Where**: `internal/tui/tui_test.go:2013-2024`. It asserts that the model's default `View()` lacks "e stream export" when `TUIExportEnable=false` — but the default view renders the *hint* line ("press H for help | filter: …"), which never contains binding lists in **either** configuration (proven by `audit/check/tuihelp`, which renders both configs and finds the token absent in both). The genuinely gated surface (the `H` overlay, `help.go:51-58`; and the dashboard expanded help bar's `k.Export`) has **no** test.
- **Suggested fix**: assert on `renderGlobalHelpOverlay(width, height, m.helpSections())` output (present with export enabled, absent with disabled), or on the dashboard help bar with `showHelp` forced on.

### F4 — Dashboard expanded help bar is unreachable via keyboard in the composed TUI (dead UI path) — **Severity: Low (design wart / dead code)**

- **Where**: the top-level model intercepts every "H" press (`internal/tui/tui.go:667-681`) and renders the global overlay, so the dashboard model's own `showHelp` toggle (`internal/tui/dashboard/model.go:646-657`, rendering the two-line binding bar incl. the gated `k.Export` via `globalStatusBindings`, `keys.go:119-127`) can never fire in production; only the isolated dashboard unit test `TestHelpToggleWithH` (`internal/tui/dashboard/model_test.go:1561-1579`) reaches it. The shadowing is acknowledged in a test comment (`internal/tui_integration_test.go:886-888`: "the global 'H' overlay shadows the dashboard 'H' so the help bar is never enabled"). The status-bar help bindings (including the export-binding gating the plan's 5.2b asks about) are therefore dead UI.
- **Suggested fix**: pick one help mechanism — either route "H" to the dashboard when on `ScreenDashboard` (making `globalStatusBindings` reachable and F3's original intent meaningful), or delete the dashboard help-bar path and keep the global overlay.

### Plan-vs-code drift items (flagged, per the audit instructions; code behavior is self-consistent in every case)

- **D1 — Non-IO tab removed**: the plan (and `AGENTS.md:78`) describe 8 tabs incl. a Non-IO tab (shortcut `8`) backed by `Snapshot.Families`. Current code has 7 tabs; family data is surfaced as the Syscalls tab's Family column (sortable; `Enter` pushes `family~<F>` filters) plus the global `[`/`]` family-scope cycle (commits `5736381`, `a1a1b518`, `2897495`). `statsengine.Snapshot.Families` is still produced but has **no remaining TUI consumer** — candidate dead data for a follow-up cleanup decision (keep or remove).
- **D2 — `h`/`l` / `left`/`right` do not cycle tabs**: plan 5.2 and `AGENTS.md:77` claim they do; in current code they are table-column navigation keys (and flame navigation), with tab switching only via `tab`/`shift+tab` and `1..7`. Docs are stale, not the code.
- **D3 — `-tui-fast-refresh=0` semantics**: `AGENTS.md` says `0` "falls back to the standard dashboard cadence"; code falls back to the 200 ms package constants (`internal/tui/dashboard/model.go:1569-1600`), so high-frequency refresh never actually stops. The flag help ("0 = disable high-frequency refresh") is equally imprecise.
- **D4 — "e … proposes a filename"**: the top-level `e` modal is an options picker with no filename; the default `ior-stream-<timestamp>.csv` name is generated at submit time. The filename-proposing modal is the stream `X` ("export as") modal. The resulting artifact name matches the plan.
- **D5 — AGENTS.md stale TUI section**: `AGENTS.md:77-78` still document "numeric keys 1..8", the Non-IO tab, and Non-IO filtering "applied in `internal/tui/dashboard`" (that code no longer exists). Everything else in AGENTS.md's TUI behavior list (export modal naming, `-tuiExport` gating of `e`, fast-refresh flag default 250 ms, tab/shift+tab navigation) was verified accurate against the code.

### Coverage gaps (not defects)

1. No test pins the `-tui-fast-refresh=0` cadence fallback (5.3c) or any custom fast-refresh value end-to-end.
2. No composed-TUI-level test registers a live filter setter, so `reapplyActiveFilter`'s in-place branch (`tui.go:1082-1096`, incl. the `SetLiveTrie` re-bind) is covered only at the seam level (`TestTuiTraceStarterAppliesLiveFilterSwapInPlace`) and by code review; the integration suite exercises the restart fallback.
3. The help-overlay content (export hint gating) has no in-repo test — verified this session only via the `audit/check/tuihelp` helper (F3).
4. All live-BPF-verification bullets remain root-gated: the `integrationtests/` package skips wholesale without root ("requires root for BPF"), so TUI-vs-kernel end-to-end (picker → real attach → dashboard) is covered by the in-process suite + code review only.

---

## Domain Summary

Domain 5 (TUI Dashboard & User Interaction) is in **strong shape**: all 21 checklist bullets resolve to **20 PASS and 1 N-A** (the N-A being the plan's Non-IO-tab bullet, removed by design in commit `5736381` — its replacement behavior, the Syscalls Family column plus `[`/`]` family cycling and filter-scoped rows, is fully implemented and tested), with **0 FAIL**. Where the plan describes behavior that no longer exists (8 tabs, `h`/`l` tab cycling, filename-proposing `e` modal, fast-refresh=0 fallback cadence), the current code is internally consistent, tested, and better documented in-repo than in the plan — those mismatches are recorded as drift items D1–D5 rather than code defects. The verification is unusually well-supported for a no-root, no-tty audit: the 62-test in-process TUI integration suite drives the production `tui.Model` through real key presses against a VT emulator (covering launch chrome, all 7 tabs, tab cycling, help, PID/TID pickers, filter modal + undo, family cycling, stream pause/search/export, CSV export submit writing a real file, and the Parquet recording modal writing a real `PAR1`-framed file), all 10 `internal/tui/*` packages are green (including `-race`), and the live-filter-swap and recorder seams are locked by production-path tests. The confirmed defects are modest: one Medium finding (`-tuiExport=false` fails to gate the stream `x`/`X`/`E` export shortcuts, F1) and three Low findings (stale "1..8" help text F2; a vacuous export-hint test F3; an unreachable dashboard help bar F4), plus stale `AGENTS.md`/plan documentation (D1–D5) that should be refreshed to describe the 7-tab dashboard.

**Verdict counts: 20 PASS · 0 FAIL · 1 N-A** (of the 20 PASS, 7 bullet-subchecks requiring a live root-gated trace or interactive tty were BLOCKED and satisfied through the mapped in-process suite and code review, as instructed). **Findings: 4 confirmed (1 Medium, 3 Low) + 5 plan/doc drift items + 4 coverage gaps.**