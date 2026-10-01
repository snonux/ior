package common

// MessagePanelChrome is the columns PanelStyle adds around its text: a border
// cell and a padding cell on each side.
const MessagePanelChrome = 4

// RenderMessagePanel boxes a one-line placeholder message ("terminal too
// narrow", "waiting for data", ...) in PanelStyle, cut so the panel is at most
// width cells wide. Such messages are typically shown precisely when the
// terminal is small, and a line wider than the terminal would soft-wrap into
// extra rows the dashboard has not budgeted. Below the panel's own chrome plus
// one cell the bare message is cut instead (one row, no border); width <= 0
// means unbounded. The boxed panel is three rows, the bare message one.
func RenderMessagePanel(msg string, width int) string {
	if width <= 0 {
		return Current().PanelStyle.Render(msg)
	}
	if width <= MessagePanelChrome {
		return TruncateRight(msg, width, Ellipsis)
	}
	return Current().PanelStyle.Render(TruncateRight(msg, width-MessagePanelChrome, Ellipsis))
}
