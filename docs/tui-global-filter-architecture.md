# TUI Global Filter Architecture

## Overview

Add one global filter flow for the TUI that is accessible from any dashboard
screen/tab and applies consistently across:

- Flame
- Overview
- Syscalls
- Files
- Processes
- Latency+Gaps
- Stream

The filter UI should reuse the current stream filter concepts, but the filter
state must move to the top-level TUI model so there is a single source of truth.

## Goals

- One shared filter modal opened from anywhere in the dashboard.
- One shared filter state owned by the top-level TUI model.
- Aggregate dashboards must only reflect matching live events.
- The stream tab must preserve its existing ring buffer across filter changes.
- Existing stream rows must be re-filtered locally after a filter change.
- String filters must remain substring-based. File path matching is explicitly a
  partial substring match, not exact-only.

## Supported Filter Fields

The global filter supports the fields currently exposed by the stream filter
workflow, plus the existing runtime PID/TID controls:

- `syscall`
- `comm`
- `file/path`
- `pid`
- `tid`
- `fd`
- `latency`
- `gap`
- `bytes`
- `retval`
- `errors only`

## Matching Semantics

- String fields use case-insensitive substring matching.
- `file/path` uses the same case-insensitive substring matching as the other
  string fields.
- Numeric fields use the existing comparison operators (`=`, `!=`, `>`, `>=`,
  `<`, `<=`).
- `errors only` keeps only events with negative return values / error-marked
  events.

## Architecture

```
BPF events -> eventLoop / print callback
                |
                +-> global runtime matcher
                        |
                        +-> statsengine.Ingest()   (filtered live aggregates)
                        +-> liveTrie.Ingest()      (filtered flamegraph)
                        +-> eventstream.Push()     (filtered new stream rows)

TUI state
  top-level model
    |
    +-> owns shared global filter state
    +-> owns global filter modal lifecycle
    +-> restarts tracing when filter changes
    +-> preserves current screen/tab
    +-> asks Stream to re-filter buffered rows in place
```

## Runtime Behavior

Applying a new global filter does all of the following:

1. Preserve the current screen/tab.
2. Stop the active trace runtime.
3. Reset aggregate dashboard state and flamegraph baseline.
4. Restart tracing with the new global filter.
5. Keep the stream ring buffer contents intact.
6. Re-filter existing buffered stream rows locally so the stream updates
   immediately.

This means aggregate tabs only show post-change matching data, while Stream can
still show matching historical rows from before the restart.

## Ownership and Data Flow

### Top-level TUI model

The top-level TUI model owns:

- active global filter state
- global filter modal visibility
- filter apply/cancel/clear behavior
- trace restart lifecycle
- publication of filter state to child models that need local re-filtering

### Stream model

The stream model no longer owns the primary filter system. It must:

- accept the shared global filter
- re-filter its retained `allEvents` slice on demand
- preserve the ring buffer across filter changes
- keep regex search as a separate feature
- drop the stream-local add/undo filter stack

### Runtime / trace startup

The TUI trace context currently carries only PID/TID. It must be expanded to
carry the full global filter payload. The trace startup path then uses that
payload to construct a runtime matcher before forwarding events into:

- stats engine
- flamegraph live trie
- new stream events

## Key Implementation Areas

- `internal/tui/tui.go`
  - own shared filter state
  - open modal globally
  - restart trace on apply
  - preserve current screen/tab
- `internal/tui/dashboard/model.go`
  - route global shortcut access cleanly across tabs
  - expose active filter summary in dashboard rendering/help
- `internal/tui/eventstream/*`
  - refactor modal for reuse
  - keep stream history
  - re-filter buffered rows in place
  - remove stream-local filter stack behavior
- `internal/ior.go`
  - plumb full filter payload through trace startup
  - apply runtime matcher before aggregate/flame/live stream ingestion

## UX Rules

- `f` opens the global filter modal from any dashboard tab.
- `Enter` in the modal applies the filter.
- `Esc` closes the modal without applying.
- clear action resets to the unfiltered state.
- active filter summary is visible in dashboard status/help areas.
- stream regex search (`/`, `?`, `n`, `N`) remains separate from filtering.

## Testing Requirements

- context round-trip of the full global filter payload
- runtime matcher coverage for all supported fields
- stream ring buffer retention across filter changes
- local re-filtering of buffered stream rows
- file path substring matching coverage
- aggregate dashboards only reflecting matching live events after restart
- help/status rendering updates for the shared filter workflow
