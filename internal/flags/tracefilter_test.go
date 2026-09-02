package flags

import (
	"testing"

	"ior/internal/globalfilter"
)

// TestBuildTraceFilterEmptyConfigIsInactive locks the no-filter default: an
// untouched config must produce an inactive filter so every pair is ingested.
func TestBuildTraceFilterEmptyConfigIsInactive(t *testing.T) {
	filter := BuildTraceFilter(Config{})
	if filter.IsActive() {
		t.Fatalf("empty config produced an active filter: %+v", filter)
	}
}

// TestBuildTraceFilterMapsIndividualFlags covers the CLI-flag glue that has no
// other test (audit domain-06 F3): each flag alone, all flags combined, and
// the -1 "no filter" sentinels.
func TestBuildTraceFilterMapsIndividualFlags(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "comm only",
			cfg:  Config{CommFilter: "nginx"},
		},
		{
			name: "path only",
			cfg:  Config{PathFilter: "/var/log"},
		},
		{
			name: "pid only",
			cfg:  Config{PidFilter: 1234},
		},
		{
			name: "tid only",
			cfg:  Config{TidFilter: 5678},
		},
		{
			name: "all combined",
			cfg: Config{
				CommFilter: "nginx",
				PathFilter: "/var/log",
				PidFilter:  1234,
				TidFilter:  5678,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter := BuildTraceFilter(tc.cfg)
			if !filter.IsActive() {
				t.Fatalf("filter is inactive, want active")
			}
			if tc.cfg.CommFilter == "" {
				if filter.Comm != nil {
					t.Fatalf("Comm filter = %+v, want nil", filter.Comm)
				}
			} else if filter.Comm == nil || filter.Comm.Pattern != tc.cfg.CommFilter {
				t.Fatalf("Comm filter = %+v, want pattern %q", filter.Comm, tc.cfg.CommFilter)
			}
			if tc.cfg.PathFilter == "" {
				if filter.File != nil {
					t.Fatalf("File filter = %+v, want nil", filter.File)
				}
			} else if filter.File == nil || filter.File.Pattern != tc.cfg.PathFilter {
				t.Fatalf("File filter = %+v, want pattern %q", filter.File, tc.cfg.PathFilter)
			}
			if tc.cfg.PidFilter > 0 {
				value, ok := filter.PID.EqValue()
				if !ok || value != int64(tc.cfg.PidFilter) {
					t.Fatalf("PID filter = (%d, %v), want (%d, true)", value, ok, tc.cfg.PidFilter)
				}
			} else if filter.PID != nil {
				t.Fatalf("PID filter = %+v, want nil", filter.PID)
			}
			if tc.cfg.TidFilter > 0 {
				value, ok := filter.TID.EqValue()
				if !ok || value != int64(tc.cfg.TidFilter) {
					t.Fatalf("TID filter = (%d, %v), want (%d, true)", value, ok, tc.cfg.TidFilter)
				}
			} else if filter.TID != nil {
				t.Fatalf("TID filter = %+v, want nil", filter.TID)
			}
		})
	}
}

// TestBuildTraceFilterSentinelsStayInactive locks that the -1 "no filter"
// sentinels never activate a dimension.
func TestBuildTraceFilterSentinelsStayInactive(t *testing.T) {
	filter := BuildTraceFilter(Config{PidFilter: -1, TidFilter: -1})
	if filter.IsActive() {
		t.Fatalf("-1 sentinels produced an active filter: %+v", filter)
	}
}

// TestBuildTraceFilterGlobalFilterTakesPrecedence locks the documented
// precedence: an active structured GlobalFilter supersedes every individual
// CLI filter flag, and is returned cloned (so callers cannot mutate it).
func TestBuildTraceFilterGlobalFilterTakesPrecedence(t *testing.T) {
	global := globalfilter.Filter{
		Comm: &globalfilter.StringFilter{Pattern: "structured"},
	}
	cfg := Config{
		GlobalFilter: global,
		CommFilter:   "cli-flag-ignored",
		PathFilter:   "/also/ignored",
		PidFilter:    1234,
		TidFilter:    5678,
	}

	filter := BuildTraceFilter(cfg)
	if filter.Comm == nil || filter.Comm.Pattern != "structured" {
		t.Fatalf("Comm filter = %+v, want the structured pattern", filter.Comm)
	}
	if filter.File != nil {
		t.Fatalf("File filter = %+v, want nil (CLI flags must be ignored)", filter.File)
	}
	if filter.PID != nil || filter.TID != nil {
		t.Fatalf("PID/TID filters = %v/%v, want nil (CLI flags must be ignored)", filter.PID, filter.TID)
	}

	// The returned filter is a clone: mutating it must not leak into cfg.
	filter.Comm.Pattern = "mutated"
	if cfg.GlobalFilter.Comm.Pattern != "structured" {
		t.Fatalf("BuildTraceFilter leaked the caller's GlobalFilter: %q", cfg.GlobalFilter.Comm.Pattern)
	}
}
