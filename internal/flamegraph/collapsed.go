package flamegraph

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"ior/internal/collapse"
)

// CollapsedOptions controls how an .ior.zst recording is derived into
// flamegraph.pl-ready collapsed stacks.
type CollapsedOptions struct {
	// Fields names the record fields used as frames, in stack order
	// (any of collapse.ValidFields). Empty means collapse.DefaultFields.
	Fields []string
	// CountField is the counter metric used as the sample weight
	// (any of collapse.ValidCountFields). Empty means "count".
	CountField string
}

func (o CollapsedOptions) normalize() (CollapsedOptions, error) {
	fields := o.Fields
	if len(fields) == 0 {
		fields = collapse.DefaultFields()
	}
	fields, err := normalizeLiveTrieFields(fields)
	if err != nil {
		return CollapsedOptions{}, fmt.Errorf("invalid collapsed fields: %w", err)
	}

	countField := strings.TrimSpace(o.CountField)
	if countField == "" {
		countField = collapse.DefaultCountField()
	}
	if !collapse.IsValidCountField(countField) {
		return CollapsedOptions{}, fmt.Errorf("invalid count field %q", countField)
	}
	return CollapsedOptions{Fields: fields, CountField: countField}, nil
}

// WriteCollapsedStacks reads an .ior.zst recording and writes collapsed-stack
// lines ("frame;frame;... weight") to w, ready for flamegraph.pl:
//
//	ior collapsed trace.ior.zst | flamegraph.pl > trace.svg
//
// The .ior.zst artifact is a zstd-compressed gob record map, not collapsed
// text; this function is the documented bridge to external FlameGraph
// tooling. Frames mirror the in-TUI flamegraph exactly (same record fields
// and the same per-field splitting), records mapping to identical frame
// paths are summed into one sample, and lines are sorted so the output is
// deterministic. Records with a zero sample weight or no derived frames are
// skipped: they would render zero-width in any flamegraph.
func WriteCollapsedStacks(w io.Writer, filename string, opts CollapsedOptions) error {
	opts, err := opts.normalize()
	if err != nil {
		return err
	}

	records, err := LoadFromFile(filename)
	if err != nil {
		return err
	}

	totals := make(map[string]uint64)
	for record := range records {
		value, err := record.Cnt.ValueByName(opts.CountField)
		if err != nil {
			return err
		}
		if value == 0 {
			continue
		}
		frames := buildFrames(record, opts.Fields)
		if len(frames) == 0 {
			continue
		}
		totals[strings.Join(frames, ";")] += value
	}

	paths := make([]string, 0, len(totals))
	for path := range totals {
		paths = append(paths, path)
	}
	slices.Sort(paths)

	for _, path := range paths {
		if _, err := fmt.Fprintf(w, "%s %d\n", path, totals[path]); err != nil {
			return fmt.Errorf("write collapsed stacks: %w", err)
		}
	}
	return nil
}
