package internal

import (
	"go/ast"
	"testing"
)

// capabilityCall returns the one call trace setup makes of the event-loop
// method that hands a BPF-setup capability to the loop (trustRenameRecords,
// foldProvenRestarts, trustExecRecords, trustFileIdents), for the caller to
// check its arguments. Structural, like the other setup tests: the setup
// cannot run unprivileged.
//
// The calls live in applyProbeCapabilities, so the facts the tests used to
// read off runTraceSetup itself are pinned through it, none weaker:
//
//   - runTraceSetup calls applyProbeCapabilities exactly once, as a statement
//     of its own body (no branch can skip it), with its loop and its infra,
//     after buildEventLoop - the factory wires the drop counter that
//     trustRenameRecords and foldProvenRestarts read - and before
//     signalTraceStarted, after which the loop may already consume records;
//   - runTraceSetup does not call the method itself as well, so "once" is
//     once in the whole setup;
//   - applyProbeCapabilities names its parameters el and infra (so an
//     argument rendered as infra.x is a field of the infra runTraceSetup
//     passed) and calls the method exactly once, on el, as a statement of its
//     own body.
func capabilityCall(t *testing.T, method string) *ast.CallExpr {
	t.Helper()
	setup, _ := parseInternalFunction(t, "ior.go", "runTraceSetup")
	applies := callsNamed(setup, "applyProbeCapabilities")
	if len(applies) != 1 || !isBodyStatement(setup, applies[0]) {
		t.Fatalf("runTraceSetup must call applyProbeCapabilities exactly once, unconditionally (found %d calls)", len(applies))
	}
	assertCallArguments(t, applies[0], []string{"el", "infra"})
	build := firstCallPosition(setup, "buildEventLoop")
	signal := firstCallPosition(setup, "signalTraceStarted")
	if !build.IsValid() || !signal.IsValid() || applies[0].Pos() < build || applies[0].Pos() > signal {
		t.Fatal("applyProbeCapabilities must run after buildEventLoop and before signalTraceStarted")
	}
	if direct := callsNamed(setup, method); len(direct) != 0 {
		t.Fatalf("runTraceSetup calls %s itself %d times besides applyProbeCapabilities", method, len(direct))
	}

	helper, _ := parseInternalFunction(t, "ior.go", "applyProbeCapabilities")
	if names := parameterNames(helper); len(names) != 2 || names[0] != "el" || names[1] != "infra" {
		t.Fatalf("applyProbeCapabilities parameters = %v, want el, infra", names)
	}
	calls := callsNamed(helper, method)
	if len(calls) != 1 || !isBodyStatement(helper, calls[0]) {
		t.Fatalf("applyProbeCapabilities must call %s exactly once, unconditionally (found %d calls)", method, len(calls))
	}
	if receiver := receiverName(calls[0]); receiver != "el" {
		t.Fatalf("applyProbeCapabilities calls %s on %q, want on el", method, receiver)
	}
	return calls[0]
}

// receiverName returns the identifier a method call is made on, or "" when
// call is not a method call on a plain identifier.
func receiverName(call *ast.CallExpr) string {
	selector, isMethod := call.Fun.(*ast.SelectorExpr)
	if !isMethod {
		return ""
	}
	receiver, isIdent := selector.X.(*ast.Ident)
	if !isIdent {
		return ""
	}
	return receiver.Name
}

// isBodyStatement reports whether call is, by itself, one of the statements
// of decl's body: not nested in a branch, a loop, a closure or another call.
func isBodyStatement(decl *ast.FuncDecl, call *ast.CallExpr) bool {
	for _, statement := range decl.Body.List {
		if expr, isExpr := statement.(*ast.ExprStmt); isExpr && expr.X == call {
			return true
		}
	}
	return false
}

// parameterNames returns the names of decl's parameters in order.
func parameterNames(decl *ast.FuncDecl) []string {
	var names []string
	for _, field := range decl.Type.Params.List {
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
	}
	return names
}
