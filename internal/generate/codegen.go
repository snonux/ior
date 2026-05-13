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
		enterClass = ClassifyFormat(sc.Enter)
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
		return nil, fmt.Sprintf("Ignoring %s as possibly not file I/O related", strings.Join(names, " "))
	}

	if isEnterRejected(enterClass.Kind) {
		names := syscallFormatNames(sc)
		return nil, fmt.Sprintf("Ignoring %s as enter-rejected", strings.Join(names, " "))
	}

	var result []GeneratedTracepoint
	if sc.Enter != nil {
		result = append(result, GeneratedTracepoint{Format: sc.Enter, Classification: enterClass})
	}
	if sc.Exit != nil {
		result = append(result, GeneratedTracepoint{Format: sc.Exit, Classification: exitClass})
	}
	return result, ""
}

// isEnterRejected reports whether kind must not appear on a syscall-enter
// tracepoint. The answer comes from the kindRegistry so no switch statement
// needs updating when a new TracepointKind is added.
func isEnterRejected(kind TracepointKind) bool {
	return !lookupKind(kind).enterAccepted
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
