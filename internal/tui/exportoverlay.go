package tui

import (
	tuiexport "ior/internal/tui/export"

	"charm.land/lipgloss/v2"
)

// overlayExportModal draws the export modal's box over base (the dashboard or
// PID picker view) in a width x height frame and pads it to the viewport.
//
// It used to stack the modal's full-screen view above the whole base
// ("modal\nbase"), about twice the terminal's height on every tab, and
// placeToViewport does not clip (lipgloss.Place only pads), so the terminal
// scrolled and the status line went off screen (task ns2). Composing the box
// over the base on a width x height canvas bounds the frame by construction:
// the canvas cuts base lines wider than the terminal (the table views' known
// wide lines included) and drops rows past its height, and it splits wide
// runes and SGR runs at the box's edges cleanly.
func overlayExportModal(exporter tuiexport.Model, base string, width, height int) string {
	box, top := placeOverlayBox(exporter.Box, min(lipgloss.Height(base), height), width, height)
	canvas := lipgloss.NewCanvas(width, height)
	canvas.Compose(lipgloss.NewCompositor(
		lipgloss.NewLayer(base),
		lipgloss.NewLayer(box).X(max((width-lipgloss.Width(box))/2, 0)).Y(top).Z(1),
	))
	return placeToViewport(width, height, canvas.Render())
}

// overlayRegion is a run of frame rows a modal box may be centred in.
type overlayRegion struct {
	top, rows int
}

// placeOverlayBox renders a modal box (render: a width x height area to the
// box) for a base drawn on the first baseRows rows of a frame height rows
// tall, and returns it with the frame row it starts at.
//
// The base's first line is the tab bar and its last the status line, which
// is above the frame's last row when the tab draws fewer rows than it has
// (a table or the Latency tab without data draws three). So the box goes
// where it covers neither: between them (over the tab's body) or in the
// blank rows below the base, the larger region first, the roomiest layout
// that region fits. Only when neither region fits the most compact box is
// it fitted to the whole frame as though the base filled it (fitOverlayBox),
// covering the frame's first row and then its last only as far as it must.
func placeOverlayBox(render func(width, height int) string, baseRows, width, height int) (string, int) {
	regions := []overlayRegion{{top: 1, rows: baseRows - 2}, {top: baseRows, rows: height - baseRows}}
	if regions[1].rows > regions[0].rows {
		regions[0], regions[1] = regions[1], regions[0]
	}
	for _, region := range regions {
		if region.rows <= 0 {
			continue
		}
		if box := render(width, region.rows); lipgloss.Height(box) <= region.rows {
			return box, region.top + (region.rows-lipgloss.Height(box))/2
		}
	}
	box := fitOverlayBox(render, width, height)
	return box, overlayTop(lipgloss.Height(box), height)
}

// fitOverlayBox renders a modal box for a frame height rows tall whose base
// fills it, leaving the first row (the tab bar) and the last (the status
// line) uncovered where it can: it asks for a box of height-2 rows, then
// height-1 (the status line outranks the tab bar, as in the dashboard's own
// row budget, splitFrameRows), then all rows. A frame shorter than the most
// compact box gets that box, which the caller's canvas clips.
func fitOverlayBox(render func(width, height int) string, width, height int) string {
	var box string
	for reserved := 2; reserved >= 0; reserved-- {
		avail := height - reserved
		if avail <= 0 {
			continue
		}
		box = render(width, avail)
		if lipgloss.Height(box) <= avail {
			return box
		}
	}
	return box
}

// overlayTop is the frame row a box boxHeight rows tall that fitOverlayBox
// fitted to a frame height rows tall starts at: ending just above the last
// row, so it covers the first row (the tab bar) before the last (the status
// line), and at the top when it is taller than height-1 rows. (A box of at
// most height-2 rows only gets here over a base shorter than the frame,
// whose own status line is higher up and covered either way.)
func overlayTop(boxHeight, height int) int {
	return max(height-1-boxHeight, 0)
}
