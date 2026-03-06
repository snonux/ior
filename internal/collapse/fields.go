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

// IsValidField reports whether a collapse field is supported.
func IsValidField(field string) bool {
	return slices.Contains(validFields, field)
}

// IsValidCountField reports whether a collapse count field is supported.
func IsValidCountField(field string) bool {
	return slices.Contains(validCountFields, field)
}
