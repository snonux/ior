package eventstream

import (
	"ior/internal/globalfilter"
	"ior/internal/globalfilter/parser"
)

type CompareOp = globalfilter.CompareOp
type NumericFilter = globalfilter.NumericFilter
type StringFilter = globalfilter.StringFilter
type Filter = globalfilter.Filter

const (
	OpEq  = globalfilter.OpEq
	OpNeq = globalfilter.OpNeq
	OpGt  = globalfilter.OpGt
	OpGte = globalfilter.OpGte
	OpLt  = globalfilter.OpLt
	OpLte = globalfilter.OpLte
)

// ParseDurationNs delegates to parser.ParseDurationNs, re-exporting the
// duration parsing helper for eventstream callers.
func ParseDurationNs(input string) (int64, error) {
	return parser.ParseDurationNs(input)
}
