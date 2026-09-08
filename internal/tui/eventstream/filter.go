package eventstream

import (
	"ior/internal/globalfilter"
	"ior/internal/globalfilter/parser"
)

// The filter types are aliases of the globalfilter contract: the stream tab
// builds, holds and applies the same Filter the event loop and the dashboard
// ingest stage use, so the aliases exist purely to keep this package's
// signatures free of an extra import.

// CompareOp is the comparison a NumericFilter applies.
type CompareOp = globalfilter.CompareOp

// NumericFilter constrains one numeric dimension.
type NumericFilter = globalfilter.NumericFilter

// StringFilter constrains one string dimension by (optionally anchored)
// substring.
type StringFilter = globalfilter.StringFilter

// Filter is the active global event filter.
type Filter = globalfilter.Filter

// The comparison operators, re-exported for the modal's field construction.
const (
	// OpEq selects values equal to the reference.
	OpEq = globalfilter.OpEq
	// OpNeq selects values different from the reference.
	OpNeq = globalfilter.OpNeq
	// OpGt selects values strictly greater than the reference.
	OpGt = globalfilter.OpGt
	// OpGte selects values greater than or equal to the reference.
	OpGte = globalfilter.OpGte
	// OpLt selects values strictly less than the reference.
	OpLt = globalfilter.OpLt
	// OpLte selects values less than or equal to the reference.
	OpLte = globalfilter.OpLte
)

// ParseDurationNs delegates to parser.ParseDurationNs, re-exporting the
// duration parsing helper for eventstream callers.
func ParseDurationNs(input string) (int64, error) {
	return parser.ParseDurationNs(input)
}
