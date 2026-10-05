package flags

import (
	"errors"
	"flag"
	"strconv"
	"strings"
	"testing"
)

func TestParseRejectsUnexpectedPositionalArguments(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		operand string
	}{
		{"before_filter", []string{"-plain", "typo", "-pid", "1234"}, "typo"},
		{"split_boolean", []string{"-plain", "false", "-pid", "1234"}, "false"},
		{"after_separator", []string{"--", "-pid", "1234"}, "-pid"},
		{"filename", []string{"trace.ior.zst"}, "trace.ior.zst"},
		{"after_filter", []string{"-pid", "1234", "typo"}, "typo"},
		{"empty_operand", []string{""}, ""},
		{"single_dash", []string{"-"}, "-"},
		{"escaped_operand", []string{"bad\n\x1b[2J\"argument"}, "bad\n\x1b[2J\"argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseArgs(tc.args)
			if err == nil {
				t.Fatalf("accepted %q", tc.args)
			}
			for _, want := range []string{"unexpected positional argument " + strconv.Quote(tc.operand), "tracing accepts flags only", "-h"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want %q", err, want)
				}
			}
			if strings.ContainsAny(err.Error(), "\n\x1b") {
				t.Errorf("error contains unescaped terminal controls: %q", err)
			}
		})
	}
}

func TestParseAcceptsFlagsWithoutOperands(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		pid   int
		plain bool
		comm  string
	}{
		{"defaults", nil, -1, false, ""},
		{"empty_separator", []string{"--"}, -1, false, ""},
		{"boolean_then_filter", []string{"-plain", "-pid", "1234"}, 1234, true, ""},
		{"explicit_boolean", []string{"-plain=false", "-pid", "1234"}, 1234, false, ""},
		{"separator_after_flags", []string{"-plain", "-pid=1234", "--"}, 1234, true, ""},
		{"string_value", []string{"-comm", "worker", "-pid", "1234"}, 1234, false, "worker"},
		{"dash_string_value", []string{"-comm", "--", "-pid", "1234"}, 1234, false, "--"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseArgs(tc.args)
			if err != nil {
				t.Fatalf("ParseArgs(%q): %v", tc.args, err)
			}
			if cfg.PidFilter != tc.pid || cfg.PlainMode != tc.plain || cfg.CommFilter != tc.comm {
				t.Errorf("pid/plain/comm = %d/%v/%q, want %d/%v/%q", cfg.PidFilter, cfg.PlainMode, cfg.CommFilter, tc.pid, tc.plain, tc.comm)
			}
		})
	}
}

func TestParseHelpPrecedesOperandValidation(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"-h", "operand"}} {
		if _, err := ParseArgs(args); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("ParseArgs(%q) error = %v, want flag.ErrHelp", args, err)
		}
	}
}
