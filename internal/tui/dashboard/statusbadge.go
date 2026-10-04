package dashboard

import (
	"fmt"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

// statusSeparator joins the segments of the status row.
const statusSeparator = " | "

// statusTail is the live half of the status row: the optional warning badge
// and the status summary (filter notice, filter, stack, recording,
// auto-reset; Model.filterSummary).
//
// badges lists the badge's renderings from the longest to the shortest; the
// row uses the first one that fits and drops the badge when none does. An
// empty list means no badge.
type statusTail struct {
	badges  []string
	summary string
}

// statusRow is one fitted status row: the static help text, the chosen badge
// rendering and the summary, each already cut to its share of the width. An
// empty segment is left out together with its separator.
type statusRow struct {
	help    string
	badge   string
	summary string
}

// fitStatusRow fits the help text base and tail into one row of at most
// width cells (no limit when width <= 0).
//
// Priority, highest first: the summary, then the warning badge, then the
// help text. The summary is where the dashboard reports state the user
// cannot get anywhere else - the active filter, a filter that was refused,
// the recording status - so it is only ever cut to the width. (Truncating
// the joined row from the right, as the status row once did, dropped
// precisely that half, which is how a refused filter could go unnoticed on
// a narrow terminal.) The badge is live state too, but only a pointer to
// rows the Stream tab shows in full, so it yields to the summary: it takes
// its longest rendering that fits beside the summary and is dropped before
// the summary loses a cell. The help text is reference text the help
// overlay repeats, so it gets what is left (and disappears below one cell).
func fitStatusRow(base string, tail statusTail, width int) statusRow {
	if tail.summary == "" && len(tail.badges) == 0 {
		return statusRow{help: base}
	}
	if width <= 0 {
		row := statusRow{help: base, summary: tail.summary}
		if len(tail.badges) > 0 {
			row.badge = tail.badges[0]
		}
		return row
	}
	var row statusRow
	used := 0
	if tail.summary != "" {
		row.summary = truncatePlain(tail.summary, width)
		used = common.DisplayWidth(row.summary)
	}
	row.badge = pickStatusBadge(tail.badges, width-used, row.summary != "")
	if row.badge != "" {
		used += common.DisplayWidth(row.badge)
		if row.summary != "" {
			used += common.DisplayWidth(statusSeparator)
		}
	}
	if room := width - used - common.DisplayWidth(statusSeparator); room >= 1 {
		row.help = truncatePlain(base, room)
	}
	return row
}

// pickStatusBadge returns the first (longest) badge rendering that fits into
// room cells, counting the separator to the summary when one follows, or ""
// when none fits.
func pickStatusBadge(badges []string, room int, beforeSummary bool) string {
	for _, badge := range badges {
		need := common.DisplayWidth(badge)
		if beforeSummary {
			need += common.DisplayWidth(statusSeparator)
		}
		if need <= room {
			return badge
		}
	}
	return ""
}

// plain joins the row's segments without any styling.
func (r statusRow) plain() string {
	return r.join(r.badge, r.tail())
}

// render joins the row's segments with the badge in the theme's warning
// style (ErrorStyle, the style the Stream tab draws warning rows with).
// When resume is set, the text after the badge is rendered in the help bar's
// muted foreground: the badge's style ends in a full SGR reset, which would
// otherwise also drop the colour HelpBarStyle set for the whole row.
func (r statusRow) render(resume bool) string {
	if r.badge == "" {
		return r.plain()
	}
	theme := common.Current()
	tail := r.tail()
	if resume && tail != "" {
		tail = lipgloss.NewStyle().Foreground(theme.Muted).Render(tail)
	}
	return r.join(theme.ErrorStyle.Render(r.badge), tail)
}

// tail returns the text after the badge: the separator and the summary, or
// the summary alone when there is no badge.
func (r statusRow) tail() string {
	if r.summary == "" {
		return ""
	}
	if r.badge == "" {
		return r.summary
	}
	return statusSeparator + r.summary
}

// join puts the help text in front of badge and tail, with a separator only
// when there is something after the help text.
func (r statusRow) join(badge, tail string) string {
	rest := badge + tail
	switch {
	case rest == "":
		return r.help
	case r.help == "":
		return rest
	default:
		return r.help + statusSeparator + rest
	}
}

// warningBadges returns the status-row renderings of the warning badge for
// count warning rows, longest first ("warnings: 3 (7:Stream)", "warn: 3 (7)",
// "!3"), or nil when there are none. The tab number is looked up in the
// registry, so it follows the Stream tab if the tab order ever changes.
func warningBadges(count int) []string {
	if count <= 0 {
		return nil
	}
	number := tabIndex(TabStream, orderedTabs()) + 1
	return []string{
		fmt.Sprintf("warnings: %d (%d:%s)", count, number, TabStream),
		fmt.Sprintf("warn: %d (%d)", count, number),
		fmt.Sprintf("!%d", count),
	}
}

// statusTail builds the live half of the status row. The warning badge
// points a user on any other tab at the warning rows (wrong -tid, zero
// probes attached, libbpf warnings) that appear nowhere but the Stream tab -
// on the default Flame tab such a run otherwise just looks empty. It is left
// out while the Stream tab is active, because its only job is to say which
// tab holds the rows, and that is the current tab. The rows are in the Stream
// tab's buffer then (warning rows bypass every stream filter) but not
// necessarily on screen: a paused stream shows a frozen snapshot without
// warnings pushed since the pause, and in follow mode a startup warning
// scrolls off screen once a screenful of rows follows it (it stays in the
// buffer, and counted, until the ring evicts it). Unpausing (space) brings
// in the newer rows and g jumps to the oldest; a badge on this tab would only
// repeat "go to this tab", and it would take room from the filter summary on
// the tab whose filter stack the user is working with.
func (m *Model) statusTail() statusTail {
	tail := statusTail{summary: m.filterSummary()}
	if m.activeTab != TabStream {
		tail.badges = warningBadges(m.streamModel.WarningCount())
	} else if message := m.streamModel.UndrawnStatusMessage(); message != "" {
		tail.badges = streamMessageBadges(message)
	}
	return tail
}

// streamMessageBadges returns the renderings of a stream status message that
// had no row of its own in the panel (eventstream.UndrawnStatusMessage), longest
// first: whole, then cut to 24 and to 12 cells. fitStatusRow takes the longest
// that fits beside the filter summary and drops the badge, never the summary,
// when none does (task 403).
func streamMessageBadges(message string) []string {
	return []string{
		message,
		common.TruncateRight(message, 24, "…"),
		common.TruncateRight(message, 12, "…"),
	}
}
