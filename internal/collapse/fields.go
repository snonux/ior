package collapse

import "slices"

var validFields = []string{
	"path",
	"comm",
	"tracepoint",
	"pid",
	"tid",
	"flags",
}

var validCountFields = []string{
	"count",
	"duration",
	"durationToPrev",
	"bytes",
}

// ValidFields returns a copy of supported collapse fields.
func ValidFields() []string {
	return slices.Clone(validFields)
}

// ValidCountFields returns a copy of supported collapse count fields.
func ValidCountFields() []string {
	return slices.Clone(validCountFields)
}

// DefaultFields returns the default frame fields, in stack order. It is the
// single source of truth shared by the -flame-fields flag, the live trie,
// and the `ior collapsed` converter so all flame views derive identical
// stacks by default.
func DefaultFields() []string {
	return []string{"comm", "tracepoint", "path"}
}

// DefaultCountField returns the default metric used as the sample weight.
func DefaultCountField() string {
	return "count"
}

// IsValidField reports whether a collapse field is supported.
func IsValidField(field string) bool {
	return slices.Contains(validFields, field)
}

// IsValidCountField reports whether a collapse count field is supported.
func IsValidCountField(field string) bool {
	return slices.Contains(validCountFields, field)
}
