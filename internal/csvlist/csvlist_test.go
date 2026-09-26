package csvlist

import (
	"slices"
	"testing"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty", raw: "", want: nil},
		{name: "whitespace only", raw: " \t\n ", want: nil},
		{name: "comma only", raw: ",", want: nil},
		{name: "commas and blanks only", raw: " , ,\t,", want: nil},
		{name: "single entry", raw: "read", want: []string{"read"}},
		{name: "single padded entry", raw: "  read\t", want: []string{"read"}},
		{name: "trailing comma", raw: "read,", want: []string{"read"}},
		{name: "leading comma", raw: ",read", want: []string{"read"}},
		{name: "doubled comma", raw: "read,,write", want: []string{"read", "write"}},
		{name: "space after comma", raw: "read, write", want: []string{"read", "write"}},
		{name: "interior whitespace kept", raw: " a b , c ", want: []string{"a b", "c"}},
		{name: "order preserved", raw: "c,a,b", want: []string{"c", "a", "b"}},
		{name: "duplicates kept", raw: "a,a", want: []string{"a", "a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Split(tt.raw)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("Split(%q) = %q, want %q", tt.raw, got, tt.want)
			}
			if tt.want == nil && got != nil {
				t.Fatalf("Split(%q) = %#v, want nil", tt.raw, got)
			}
		})
	}
}
