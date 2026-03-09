# TUI Dashboard Table Sorting Plan

## Overview

Add column-driven sorting to the dashboard table views for:

- `3:Syscalls`
- `4:Files`
- `5:Processes`

This is a **table-view-only** feature. Bubble, treemap, and icicle modes keep
their existing ordering rules.

The task wording says "sort by any row", but the current dashboard already
tracks both a selected row and a selected column. This plan therefore treats
`s` as **sort by the currently selected column/cell**.

Pressing `s`:

1. on a new selected column enables that column's sort order
2. again on the same selected column clears the custom sort and restores the
   tab's current default ordering

## Current Behavior

The dashboard already has the key pieces needed for this feature:

- `internal/tui/dashboard/model.go`
  - stores row selection and selected column for Syscalls, Files, and Processes
  - routes table navigation with `left/right` and `h/l`
- `internal/tui/dashboard/syscalls.go`
  - renders the syscall table from `snap.Syscalls()`
- `internal/tui/dashboard/files.go`
  - renders both the file table and the grouped-directory table
- `internal/tui/dashboard/processes.go`
  - renders the process table

The current default ordering comes from the snapshot producers:

- Syscalls: `Count desc`, then `Name asc`
- Files: `Accesses desc`, then `Path asc`
- Grouped directories: `Accesses desc`, then `Directory asc`
- Processes: `Syscalls desc`, then `Bytes desc`, then `PID asc`

That ordering should remain the baseline whenever no custom sort is active.

## Design Goals

- `s` sorts by the selected column in table mode.
- `s` on the same selected column toggles back to the default ranking.
- `Enter` continues to act on the row currently visible on screen after sorting.
- Sorting stays in the dashboard layer; `statsengine` snapshot semantics do not
  change.
- Selection remains anchored to the same logical entity when sorting changes.
- Width changes do not corrupt sort state for the Syscalls tab.

## UX Rules

- `s` is active only for sortable dashboard tables:
  - Syscalls table mode
  - Files table mode
  - Files directory-grouped table mode
  - Processes table mode
- `s` does nothing in:
  - Overview
  - Latency+Gaps
  - Stream
  - Flame
  - bubble/treemap/icicle modes
- Table footer hints should add `s:sort`.
- The footer should also show the active sort, for example:
  - `sort: default`
  - `sort: p95 desc`
  - `sort: Path asc`
- Expanded help should mention `s` so the feature is discoverable.

## State Model

Add dashboard-local sort state per table shape.

Example shape:

```go
type tableSortState[K comparable] struct {
    active bool
    key    K
}
```

Recommended fields on `dashboard.Model`:

- `syscallsSort`
- `filesSort`
- `filesDirSort`
- `processesSort`

`Files` needs **two** sort states because the tab has two different table
schemas:

- file rows
- grouped directory rows

Those states should persist independently when `d` toggles between files and
directories.

## Logical Sort Keys

Do **not** store the raw selected column index as the sort identifier.

The Syscalls table changes shape by width:

- narrow layout: `Syscall Count Rate/s Avg p95 p99 Bytes Errors`
- wide layout: `Syscall Count Rate/s Avg Min Max p50 p95 p99 Bytes Errors`

If sort state stored only a column index, resizing from narrow to wide would
turn "sort by p95" into "sort by Min". The sort state must therefore use a
stable logical key enum, and map the current visible column index to that enum
at keypress time.

Recommended enums:

- `syscallSortKey`
- `fileSortKey`
- `fileDirSortKey`
- `processSortKey`

## Column Ordering Rules

Use a fixed natural direction per logical column. This avoids inventing a
three-state cycle and matches the task requirement of "sort" plus "toggle back".

### Syscalls

- `Syscall`: `Name asc`
- `Count`: `Count desc`
- `Rate/s`: `RatePerSec desc`
- `Avg`: `LatencyMeanNs desc`
- `Min`: `LatencyMinNs desc`
- `Max`: `LatencyMaxNs desc`
- `p50`: `LatencyP50Ns desc`
- `p95`: `LatencyP95Ns desc`
- `p99`: `LatencyP99Ns desc`
- `Bytes`: `Bytes desc`
- `Errors`: `Errors desc`

### Files

- `Accesses`: `Accesses desc`
- `Read`: `BytesRead desc`
- `Write`: `BytesWritten desc`
- `Avg Latency`: `AvgLatencyNs desc`
- `Max Latency`: `MaxLatencyNs desc`
- `Path`: `Path asc`

### Grouped Directories

- `Accesses`: `Accesses desc`
- `Read`: `BytesRead desc`
- `Write`: `BytesWritten desc`
- `Avg Latency`: `AvgLatencyNs desc`
- `Max Latency`: `MaxLatencyNs desc`
- `Files`: `FileCount desc`
- `Directory`: `Dir asc`

### Processes

- `PID`: `PID asc`
- `Comm`: `Comm asc`
- `Syscalls`: `Syscalls desc`
- `Rate/s`: `RatePerSec desc`
- `Total Bytes`: `Bytes desc`
- `Avg Latency`: `AvgLatencyNs desc`

## Comparator Rules

For deterministic output, custom comparators should fall back to the existing
default ranking for that row type.

Examples:

- `p95 desc`, then syscall default order
- `Path asc`, then file default order
- `Comm asc`, then process default order

This keeps ties stable and makes the "toggle back to default" behavior
predictable.

## Selection Anchoring

Changing sort order must not leave the cursor on the same numeric row index if
that index now points to a different entity.

Before toggling sort:

1. capture the currently selected logical entity key
2. recompute the sorted rows
3. restore the selected row to the same entity in the new order
4. if the entity no longer exists, clamp as today

Recommended identity keys:

- Syscalls: `Name`
- Files: `Path`
- Grouped directories: `Dir`
- Processes: `PID`

This same anchor logic should run on refresh ticks while custom sorting is
active so the selected item does not drift unpredictably as live stats change.

## Implementation Shape

Keep the sorting logic in `internal/tui/dashboard`, not in `internal/statsengine`.

Reason:

- snapshot order is part of the existing aggregate ranking behavior
- only the table presentation needs alternate ordering
- bubble/treemap/icicle already have their own ordering rules

Recommended implementation split:

- `internal/tui/common/keys.go`
  - add a `Sort` binding for `s`
  - include it in dashboard help output
- `internal/tui/dashboard/model.go`
  - add per-table sort state
  - handle `s`
  - ignore `s` outside sortable table modes
  - preserve selection anchors when sort changes
  - make `selectedSyscallFilter`, `selectedFileFilter`, and
    `selectedProcessSnapshot` read from the same sorted rows used by rendering
- `internal/tui/dashboard/syscalls.go`
  - add syscall sort key mapping from visible column index
  - add sorted syscall row helper
  - expose active sort label for footer hints
- `internal/tui/dashboard/files.go`
  - add file and directory sort key helpers
  - keep file and grouped-directory comparators separate
- `internal/tui/dashboard/processes.go`
  - add process sort key helpers and sorted row helper
- `internal/tui/dashboard/table.go`
  - extend footer hints/status rendering as needed for the active sort label

## Rendering/Data Consistency

The most important implementation rule is:

**the rendered rows and the row-selection actions must use the exact same sorted
slice**

Without this, the UI can show one row while `Enter` filters a different row.

The safest approach is to centralize each table's sorted typed rows in helper
functions and use those helpers in both:

- render paths
- selected-row action paths

## Files Tab Details

The Files tab needs one extra rule beyond Syscalls and Processes:

- in plain file mode, sorting operates on `[]statsengine.FileSnapshot`
- in directory-grouped mode, sorting operates on `[]DirSnapshot`

The two modes should not share a single sort key because their columns differ.
Switching with `d` should preserve:

- last file-table custom sort
- last directory-table custom sort

## Interaction With Existing Features

- `Enter`
  - still filters the currently selected visible row
- `d`
  - only changes Files table shape; custom sort state persists per mode
- `v`
  - custom sort state persists, but only applies when returning to table mode
- `b`
  - unaffected; bubble/treemap ordering remains metric-driven
- terminal resize
  - sort state persists because it stores logical keys, not raw indices
- trace restart / filter apply
  - sort state should remain as view state

## Testing Plan

Add focused tests in `internal/tui/dashboard` and `internal/tui/common`.

### Model behavior

- `s` on Syscalls enables a column sort.
- `s` on the same Syscalls column restores default sorting.
- `s` on Processes does nothing in non-table modes.
- `s` on Files uses file-mode sort state when `filesDirGrouped == false`.
- `s` on Files uses directory-mode sort state when `filesDirGrouped == true`.
- changing sort preserves the selected entity instead of only the row index.

### Width-sensitive syscall behavior

- sorting by `p95` in narrow mode survives a resize into wide mode
- sorting by `Syscall` or `Count` maps correctly in both layouts

### Selection action consistency

- `selectedSyscallFilter()` uses sorted syscall rows
- `selectedFileFilter()` uses sorted file or directory rows
- `selectedProcessSnapshot()` uses sorted process rows in table mode

### Help/footer rendering

- expanded help includes `s`
- table footer includes `s:sort`
- active sort label is visible in the table footer

### Negative cases

- `s` does nothing on Overview / Stream / Flame / Latency+Gaps
- `s` does nothing for bubble / treemap / icicle views

## Recommended Delivery Order

1. add key binding and sort state plumbing in `dashboard.Model`
2. implement sorted typed-row helpers per tab
3. switch render paths and selected-row actions to the shared helpers
4. add footer/help output
5. add regression tests for sort toggling, width changes, and selected-row
   action consistency

## Non-Goals

- no change to snapshot generation order in `statsengine`
- no sortable Overview or Latency+Gaps tables
- no ascending/descending toggle cycle beyond "custom sort" vs "default"
- no behavior change for bubble/treemap/icicle ordering
