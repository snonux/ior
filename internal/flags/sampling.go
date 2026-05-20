package flags

import (
	"fmt"
	"strconv"
	"strings"

	"ior/internal/types"
)

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
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out, nil
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
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
