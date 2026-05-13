package flags

import "ior/internal/globalfilter"

// BuildTraceFilter constructs a globalfilter.Filter from the CLI-level filter
// fields stored in cfg. If a GlobalFilter is already active it is returned
// as-is (cloned), because the structured filter supersedes all individual CLI
// flags. Otherwise the per-field flags (CommFilter, PathFilter, PidFilter,
// TidFilter) are merged into a new filter.
//
// This function is the single authoritative place for turning a flags.Config
// into the globalfilter.Filter used by event ingestion. It replaces the
// former Config.TraceFilter() method so that filter-building logic lives in a
// dedicated function rather than on the configuration struct itself.
func BuildTraceFilter(cfg Config) globalfilter.Filter {
	filter := cfg.GlobalFilter.Clone()
	if filter.IsActive() {
		return filter
	}
	if cfg.CommFilter != "" {
		filter.Comm = &globalfilter.StringFilter{Pattern: cfg.CommFilter}
	}
	if cfg.PathFilter != "" {
		filter.File = &globalfilter.StringFilter{Pattern: cfg.PathFilter}
	}
	if cfg.PidFilter > 0 {
		filter.PID = globalfilter.NewEqFilter(int64(cfg.PidFilter))
	}
	if cfg.TidFilter > 0 {
		filter.TID = globalfilter.NewEqFilter(int64(cfg.TidFilter))
	}
	return filter
}
