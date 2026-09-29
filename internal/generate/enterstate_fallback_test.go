package generate

import (
	"strings"
	"testing"
)

// The enter-state fallbacks in internal/c/filter.c ("Enter state and its two
// fallbacks") keep syscall_aggregate_map and the ring-buffer stream an exact
// partition of the invocations even when syscall_enter_state_map has no entry
// for a sys_exit: a failed enter-state write is counted untimed at sys_enter
// (unless the rate is 1, where the pair is emitted), and a stateless or
// mismatched sys_exit is emitted only at rate 1 and never counted. BPF
// behaviour cannot be exercised from a unit test, so the contract is asserted
// over the source, and each check is shown to reject the shape it guards
// against.

const (
	sigSyscallEnter  = "static __always_inline int ior_on_syscall_enter(__u32 tid, __u32 enter_trace_id, __u64 now)"
	sigSyscallExit   = "static __always_inline int ior_on_syscall_exit(__u32 tid, __u32 enter_trace_id, __s64 ret, __u64 now)"
	sigStateLost     = "static __always_inline int ior_on_enter_state_lost(__u32 enter_trace_id, __u32 rate)"
	sigStatelessExit = "static __always_inline int ior_stateless_exit_emits(__u32 enter_trace_id)"
	sigUntimedCount  = "static __always_inline void ior_count_untimed_syscall(__u32 enter_trace_id)"
	sigTimedAggreg   = "static __always_inline void ior_update_syscall_aggregate(__u32 enter_trace_id, __u64 duration_ns, __s64 ret)"
)

// normalizeC collapses all whitespace so the checks below do not depend on
// indentation or line breaks.
func normalizeC(source string) string {
	return strings.Join(strings.Fields(source), " ")
}

// enterStateFallbackViolations returns one message per broken rule, or none
// when filter.c honours the enter-state fallback contract.
func enterStateFallbackViolations(source string) []string {
	source = stripCComments(source)
	var problems []string
	body := func(signature string) string {
		b, ok := cFunctionBody(source, signature)
		if !ok {
			problems = append(problems, "missing "+signature)
		}
		return normalizeC(b)
	}
	require := func(text, needle, why string) {
		if !strings.Contains(text, needle) {
			problems = append(problems, why)
		}
	}

	enter := body(sigSyscallEnter)
	require(enter, "if (bpf_map_update_elem(&syscall_enter_state_map, &tid, &state, BPF_ANY)) return ior_on_enter_state_lost(enter_trace_id, rate);",
		"ior_on_syscall_enter must divert a failed enter-state write to ior_on_enter_state_lost")

	lost := body(sigStateLost)
	require(lost, "if (rate == 1) return 1; ior_count_untimed_syscall(enter_trace_id); return 0;",
		"ior_on_enter_state_lost must emit at rate 1 and otherwise count untimed and suppress")

	stateless := body(sigStatelessExit)
	if stateless != "return ior_sampling_rate(enter_trace_id) == 1;" {
		problems = append(problems, "ior_stateless_exit_emits must emit exactly at rate 1")
	}

	exit := body(sigSyscallExit)
	require(exit, "if (!state) return ior_stateless_exit_emits(enter_trace_id);",
		"a stateless sys_exit must follow the rate, not emit unconditionally")
	require(exit, "if (state->enter_trace_id != enter_trace_id) { bpf_map_delete_elem(&syscall_enter_state_map, &tid); return ior_stateless_exit_emits(enter_trace_id); }",
		"a mismatched enter state must be dropped and the exit treated as stateless")
	if strings.Contains(exit, "return 1;") {
		problems = append(problems, "ior_on_syscall_exit must not emit unconditionally anywhere")
	}

	untimed := body(sigUntimedCount)
	for _, field := range []string{"duration", "errors", "histogram"} {
		if strings.Contains(untimed, field) {
			problems = append(problems, "ior_count_untimed_syscall must only move count, it touches "+field)
		}
	}

	timed := body(sigTimedAggreg)
	require(timed, "if (!ior_aggregate_has_timed_samples(existing) || duration_ns < existing->min_duration_ns)",
		"the first timed sample must seed min_duration_ns even after untimed counts")
	return problems
}

func TestEnterStateFallbacksKeepThePartitionExact(t *testing.T) {
	filterC, err := readCSource("filter.c")
	if err != nil {
		t.Fatalf("read filter.c: %v", err)
	}
	for _, problem := range enterStateFallbackViolations(filterC) {
		t.Error(problem)
	}
}

// TestEnterStateFallbackViolationsRejectsRegressions feeds the checker the
// pre-fix shapes (and a few other plausible regressions) so it cannot pass
// vacuously.
func TestEnterStateFallbackViolationsRejectsRegressions(t *testing.T) {
	filterC, err := readCSource("filter.c")
	if err != nil {
		t.Fatalf("read filter.c: %v", err)
	}
	mutations := map[string][2]string{
		"enter ignores the update result": {
			"if (bpf_map_update_elem(&syscall_enter_state_map, &tid, &state, BPF_ANY))\n        return ior_on_enter_state_lost(enter_trace_id, rate);",
			"bpf_map_update_elem(&syscall_enter_state_map, &tid, &state, BPF_ANY);",
		},
		"stateless exit always emits": {
			"if (!state)\n        return ior_stateless_exit_emits(enter_trace_id);",
			"if (!state)\n        return 1;",
		},
		"lost state emits at every rate": {
			"if (rate == 1)\n        return 1;\n    ior_count_untimed_syscall(",
			"if (rate != 0)\n        return 1;\n    ior_count_untimed_syscall(",
		},
		"stateless exit emits for sampled rates": {
			"return ior_sampling_rate(enter_trace_id) == 1;",
			"return ior_sampling_rate(enter_trace_id) != 0;",
		},
		"untimed count touches the histogram": {
			"        existing->count += 1;\n        return;\n",
			"        existing->count += 1;\n        existing->duration_histogram[0] += 1;\n        return;\n",
		},
		"min seeded by count == 1": {
			"if (!ior_aggregate_has_timed_samples(existing) || duration_ns < existing->min_duration_ns)",
			"if (existing->count == 0 || duration_ns < existing->min_duration_ns)",
		},
	}
	for name, m := range mutations {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(filterC, m[0]) {
				t.Fatalf("mutation anchor %q not found in filter.c", m[0])
			}
			mutated := strings.Replace(filterC, m[0], m[1], 1)
			if len(enterStateFallbackViolations(mutated)) == 0 {
				t.Fatal("checker accepted the regression")
			}
		})
	}
}
