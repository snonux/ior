package generate

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Syscall groups enter+exit formats by syscall name.
type Syscall struct {
	Name  string
	Enter *Format
	Exit  *Format
}

// GeneratedTracepoint holds a classified format ready for code generation.
type GeneratedTracepoint struct {
	Format         *Format
	Classification ClassificationResult
}

// GenerateTracepointsC produces the full generated_tracepoints.c content from
// concatenated sysfs format data parsed into formats.
func GenerateTracepointsC(formats []Format) string {
	syscalls := groupBySyscall(formats)
	var b strings.Builder

	b.WriteString("// Code generated - don't change manually!\n\n")

	var accepted []GeneratedTracepoint
	for _, sc := range syscalls {
		tracepoints, reason := classifySyscall(sc)
		if reason != "" {
			fmt.Fprintf(&b, "/// %s\n", reason)
			continue
		}
		accepted = append(accepted, tracepoints...)
	}

	slices.SortFunc(accepted, func(a, b GeneratedTracepoint) int {
		return cmp.Compare(b.Format.ID, a.Format.ID)
	})

	b.WriteString("\n")
	for _, tp := range accepted {
		fmt.Fprintf(&b, "#define %s %d\n", strings.ToUpper(tp.Format.Name), tp.Format.ID)
	}
	b.WriteString("\n")

	for _, tp := range accepted {
		b.WriteString(generateBPFHandler(tp))
		b.WriteString("\n")
	}

	return b.String()
}

func groupBySyscall(formats []Format) []Syscall {
	m := make(map[string]*Syscall)
	var order []string

	for i := range formats {
		f := &formats[i]
		parts := strings.SplitN(f.Name, "_", 3)
		if len(parts) < 3 {
			continue
		}
		enterExit := parts[1]
		what := parts[2]

		sc, ok := m[what]
		if !ok {
			sc = &Syscall{Name: what}
			m[what] = sc
			order = append(order, what)
		}
		if enterExit == "enter" {
			sc.Enter = f
		} else {
			sc.Exit = f
		}
	}

	result := make([]Syscall, 0, len(order))
	for _, name := range order {
		result = append(result, *m[name])
	}
	return result
}

func classifySyscall(sc Syscall) ([]GeneratedTracepoint, string) {
	var enterClass, exitClass ClassificationResult
	allCanGenerate := true

	if sc.Enter != nil {
		enterClass = classifyEnterForGeneration(sc.Enter)
		if enterClass.Kind == KindNone {
			allCanGenerate = false
		}
	} else {
		allCanGenerate = false
	}

	if sc.Exit != nil {
		exitClass = ClassifyFormat(sc.Exit)
		if exitClass.Kind == KindNone {
			allCanGenerate = false
		}
	} else {
		allCanGenerate = false
	}

	if !allCanGenerate {
		names := syscallFormatNames(sc)
		return nil, fmt.Sprintf("Skipping %s as incomplete or unclassifiable", strings.Join(names, " "))
	}

	if isEnterRejected(enterClass.Kind) {
		names := syscallFormatNames(sc)
		return nil, fmt.Sprintf("Ignoring %s as enter-rejected", strings.Join(names, " "))
	}

	var result []GeneratedTracepoint
	if sc.Enter != nil {
		result = append(result, GeneratedTracepoint{Format: sc.Enter, Classification: enterClass})
	}
	// Emit the exit handler only for syscalls that can actually return.
	// Noreturn syscalls (exit, exit_group, rt_sigreturn) never return to the
	// syscall site, so their sys_exit tracepoint never fires; emitting a handler
	// would be dead code in the generated BPF program. We still emit their enter
	// handler above.
	if sc.Exit != nil && !isNoreturnSyscall(sc.Name) {
		result = append(result, GeneratedTracepoint{Format: sc.Exit, Classification: exitClass})
	}
	return result, ""
}

func classifyEnterForGeneration(f *Format) ClassificationResult {
	classification := ClassifyFormat(f)
	if classification.Kind != KindNone || len(f.ExternalFields) == 0 {
		return classification
	}
	return ClassificationResult{Kind: KindNull}
}

// isEnterRejected reports whether kind must not appear on a syscall-enter
// tracepoint. The answer comes from the kindRegistry so no switch statement
// needs updating when a new TracepointKind is added.
func isEnterRejected(kind TracepointKind) bool {
	return !lookupKind(kind).enterAccepted
}

// noreturnSyscalls lists syscalls that never return to the syscall site.
// Their sys_exit tracepoint can never fire, so the generator suppresses the
// matching exit handler (see classifySyscall) to avoid dead code in the
// generated BPF program, and the enter handler uses the noreturn enter hook
// that skips the (otherwise un-reclaimable) syscall_enter_state_map write.
//
//   - exit / exit_group terminate the thread/process; control never returns.
//   - rt_sigreturn restores the pre-signal execution context off the signal
//     stack frame and resumes the interrupted instruction. It does NOT return
//     to the instruction after the rt_sigreturn syscall, so the kernel never
//     fires sys_exit_rt_sigreturn. Verified empirically against
//     /sys/kernel/tracing: sys_enter_rt_sigreturn fires once per signal-handler
//     return while sys_exit_rt_sigreturn never does. The man page (sigreturn(2))
//     states plainly that "sigreturn() never returns". rt_sigreturn is emitted
//     by the signal trampoline, not called directly by applications.
var noreturnSyscalls = map[string]bool{
	"exit":         true,
	"exit_group":   true,
	"rt_sigreturn": true,
}

// isNoreturnSyscall reports whether the named syscall never returns and thus
// must not have an exit handler emitted.
func isNoreturnSyscall(name string) bool {
	return noreturnSyscalls[name]
}

func syscallFormatNames(sc Syscall) []string {
	var names []string
	if sc.Enter != nil {
		names = append(names, sc.Enter.Name)
	}
	if sc.Exit != nil {
		names = append(names, sc.Exit.Name)
	}
	slices.Sort(names)
	return names
}
