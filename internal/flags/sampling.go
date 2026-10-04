package flags

import (
	"fmt"
	"strconv"
	"strings"

	"ior/internal/csvlist"
	"ior/internal/types"
)

var defaultAggregateOnlySyscalls = []string{
	"futex",
	"futex_wait",
	"futex_wake",
	"futex_requeue",
	"futex_waitv",
	"clock_gettime",
}

func cloneFamilySamplingRates(in map[types.SyscallFamily]uint32) map[types.SyscallFamily]uint32 {
	out := make(map[types.SyscallFamily]uint32, len(in))
	for family, rate := range in {
		out[family] = rate
	}
	return out
}

func cloneSyscallSamplingRates(in map[string]uint32) map[string]uint32 {
	out := make(map[string]uint32, len(in))
	for syscall, rate := range in {
		out[syscall] = rate
	}
	return out
}

func defaultSyscallSamplingRates() map[string]uint32 {
	out := make(map[string]uint32, len(defaultAggregateOnlySyscalls))
	for _, syscall := range defaultAggregateOnlySyscalls {
		out[syscall] = 0
	}
	return out
}

// resolveDefaultSyscallSamplingRates returns the built-in per-syscall defaults
// for the given output mode. They are deliberately kept apart from the user's
// explicit -syscall-sampling-syscalls entries (Config.SyscallSamplingRates):
// merging them into one map would make an implicit default indistinguishable
// from an explicit choice and let it beat an explicit -syscall-sampling-families
// rate. The consumer applies the precedence built-in default < family rate <
// explicit syscall rate.
//
// The defaults are aggregate-only (rate 0). In raw output modes (-plain,
// -flamegraph, headless -parquet) there is no aggregate sink, so rate 0 would
// suppress every ring-buffer event and silently erase these syscalls from the
// output; there the defaults are promoted to rate 1 (emit every event). The
// promotion applies to built-in defaults only: explicit user rates, including
// an explicit 0, never pass through here.
func resolveDefaultSyscallSamplingRates(rawOutput bool) map[string]uint32 {
	out := defaultSyscallSamplingRates()
	if !rawOutput {
		return out
	}
	for syscall, rate := range out {
		if rate == 0 {
			out[syscall] = 1
		}
	}
	return out
}

func parseFamilySamplingRates(raw string) (map[types.SyscallFamily]uint32, error) {
	entries, err := parseSamplingEntries(raw)
	if err != nil {
		return nil, err
	}
	out := make(map[types.SyscallFamily]uint32, len(entries))
	for key, rate := range entries {
		family, ok := types.ParseSyscallFamily(key)
		if !ok {
			return nil, fmt.Errorf("invalid syscall family in sampling map: %q", key)
		}
		out[family] = rate
	}
	return out, nil
}

func parseSyscallSamplingRates(raw string) (map[string]uint32, error) {
	entries, err := parseSamplingEntries(raw)
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint32, len(entries))
	for syscall, rate := range entries {
		syscall = strings.ToLower(strings.TrimSpace(syscall))
		if syscall == "" {
			return nil, fmt.Errorf("invalid syscall sampling key %q", syscall)
		}
		if _, ok := types.EnterTraceIDByName(syscall); !ok {
			return nil, fmt.Errorf("invalid syscall in sampling map: %q", syscall)
		}
		out[syscall] = rate
	}
	return out, nil
}

func parseSamplingEntries(raw string) (map[string]uint32, error) {
	out := make(map[string]uint32)
	for _, part := range csvlist.Split(raw) {
		key, valueRaw, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("invalid sampling entry %q: expected name=rate", part)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("invalid sampling entry %q: empty name", part)
		}
		rate, err := strconv.ParseUint(strings.TrimSpace(valueRaw), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid sampling rate for %q: %w", key, err)
		}
		out[key] = uint32(rate)
	}
	return out, nil
}
