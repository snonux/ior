package parser_test

import (
	"testing"

	"ior/internal/globalfilter/parser"
)

func TestParseDurationNsAcceptsValidInputs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{in: "1ms", want: 1_000_000},
		{in: "10us", want: 10_000},
		{in: "500ns", want: 500},
		{in: "42", want: 42},
		{in: "-10", want: -10},
		{in: "1s", want: 1_000_000_000},
	} {
		got, err := parser.ParseDurationNs(tc.in)
		if err != nil {
			t.Fatalf("ParseDurationNs(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseDurationNs(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseDurationNsRejectsInvalidInputs(t *testing.T) {
	for _, bad := range []string{"garbage", "", "abc", "1xx"} {
		if _, err := parser.ParseDurationNs(bad); err == nil {
			t.Fatalf("ParseDurationNs(%q) expected error, got nil", bad)
		}
	}
}
