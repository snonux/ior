package eventstream

import "ior/internal/globalfilter"

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

func ParseDurationNs(input string) (int64, error) {
	return globalfilter.ParseDurationNs(input)
}
