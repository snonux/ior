package flamegraph

// buildFrames returns the stack frames of record for the configured fields,
// in field order. Every field value is split on ';' and empty parts are
// dropped, so a value can contribute several frames or none; unknown fields
// contribute nothing.
//
// This runs once per ingested event, so it avoids the per-field string
// building of IterRecord.StringByName where it can: frames are substrings of
// the record's own strings (insertTriePath clones a name only when it creates
// a node) and the "path" field is split in place by appendPathFrames.
func buildFrames(record IterRecord, fields []string) []string {
	frames := make([]string, 0, len(fields)+4)
	for _, fieldName := range fields {
		if fieldName == "path" {
			frames = appendPathFrames(frames, record.Path)
			continue
		}
		value, err := record.StringByName(fieldName)
		if err != nil {
			continue
		}
		frames = appendSplitFrames(frames, value)
	}
	return frames
}

// appendSplitFrames appends the non-empty ';'-separated parts of value.
func appendSplitFrames(frames []string, value string) []string {
	start := 0
	for i := 0; i < len(value); i++ {
		if value[i] == ';' {
			frames = appendNonEmptyFrame(frames, value[start:i])
			start = i + 1
		}
	}
	return appendNonEmptyFrame(frames, value[start:])
}

// appendPathFrames appends the frames of a file path: one frame per path
// component, each keeping its leading '/' ("/a/b" -> "/a", "/b"), with ';'
// also splitting frames and empty frames dropped. That is exactly what
// splitting StringByName("path") — the path with every "/" replaced by ";/"
// — on ';' yields, without building the intermediate strings.
func appendPathFrames(frames []string, path string) []string {
	start := 0
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '/':
			frames = appendNonEmptyFrame(frames, path[start:i])
			start = i
		case ';':
			frames = appendNonEmptyFrame(frames, path[start:i])
			start = i + 1
		}
	}
	return appendNonEmptyFrame(frames, path[start:])
}

func appendNonEmptyFrame(frames []string, frame string) []string {
	if frame == "" {
		return frames
	}
	return append(frames, frame)
}
