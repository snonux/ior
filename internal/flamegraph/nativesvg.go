package flamegraph

import (
	"fmt"
	"io"
	"iter"
	"os"
	"strings"
)

// NativeSVG generates interactive flamegraph SVGs directly from .ior.zst data files.
//
// Flamegraphs are generated natively by ior from .ior.zst data files; no external
// flamegraph tool is required. The CLI typically drives this via the -ior flag,
// which reads trace data, aggregates it into a trie of stack frames (e.g. comm,path,tracepoint)
// and renders a self-contained SVG that can be viewed in a browser.
type NativeSVG struct {
	fields     []string
	countField string
	config     SVGConfig
}

func NewNativeSVG(fields []string, countField string) NativeSVG {
	return NativeSVG{
		fields:     fields,
		countField: countField,
		config:     defaultSVGConfig(),
	}
}

func (n NativeSVG) WriteSVGFromFile(iorDataFile string) (outFile string, err error) {
	outFile = fmt.Sprintf("%s.%s-by-%s.svg",
		strings.TrimSuffix(iorDataFile, ".ior.zst"),
		strings.Join(n.fields, ":"),
		n.countField,
	)
	defer func() {
		if err != nil {
			_ = os.Remove(outFile)
		}
	}()

	iod, err := newIorDataFromFile(iorDataFile)
	if err != nil {
		return outFile, fmt.Errorf("read ior data: %w", err)
	}

	fd, err := os.Create(outFile)
	if err != nil {
		return outFile, fmt.Errorf("create output %s: %w", outFile, err)
	}
	defer fd.Close()

	if err := n.WriteSVGFromIter(iod.iter(), fd); err != nil {
		return outFile, err
	}
	return outFile, nil
}

func (n NativeSVG) WriteSVGFromIter(records iter.Seq[IterRecord], w io.Writer) error {
	tr, err := n.buildTrieFromIter(records)
	if err != nil {
		return err
	}
	return WriteSVG(w, tr, n.config)
}

func (n NativeSVG) buildTrieFromIter(records iter.Seq[IterRecord]) (*trie, error) {
	tr := newTrie()
	var framesBuf []string
	for record := range records {
		frames, err := n.recordFrames(record, framesBuf)
		if err != nil {
			return nil, err
		}
		framesBuf = frames
		tr.add(frames, record.Cnt.ValueByName(n.countField))
	}
	tr.computeTotals()
	return tr, nil
}

func (n NativeSVG) recordFrames(record IterRecord, framesBuf []string) ([]string, error) {
	frames := framesBuf[:0]
	for _, fieldName := range n.fields {
		value, err := record.StringByName(fieldName)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldName, err)
		}
		for _, part := range strings.Split(value, ";") {
			if part != "" {
				frames = append(frames, part)
			}
		}
	}
	return frames, nil
}
