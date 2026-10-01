package flamegraph

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"ior/internal/sampling"
	"ior/internal/types"
)

// Recording stream layout (the payload inside the zstd frame of an .ior.zst):
//
//	recordingMagic                      8 raw bytes
//	gob(recordingHeader)                format version + tracepoint table (+ sampling)
//	gob(map[recordKey]Counter)          the records
//
// recordKey.TraceID is a numeric tracepoint ID, and those IDs are the
// generating host's kernel event IDs: they change whenever the tracepoint set
// does (openat was 784, 788, 791 and 809 in successive releases). Rendering a
// stored ID with the reading binary's table therefore printed wrong syscall
// names without any error. The header fixes that by carrying, for every ID
// that occurs in the records, the tracepoint string ("enter_openat") that the
// writer's table gave it. The reader resolves each string back to *its own*
// ID, so the in-memory representation and every consumer stay unchanged.
//
// The magic prefix (instead of a header struct decoded straight from gob) is
// what tells a headerless legacy recording apart from a new one without
// matching gob's error strings.
var recordingMagic = [8]byte{'I', 'O', 'R', 'R', 'E', 'C', 0, 0}

// Sampling (task qq2): a run that samples writes only a fraction of the
// invocations of the sampled syscalls as records, so the counts of such a
// recording are not the population. The header's Sampling field names those
// syscalls with their rates and the exact totals (sampling.Summary). Because a
// reader that ignores the field would present sampled counts as complete, a
// sampled recording is written as version recordingFormatVersionSampled, which
// a build that predates the field refuses; a recording that sampled nothing
// stays at version 1 and stays readable by every build.

// recordingFormatVersion is the version of a recording that sampled nothing.
// recordingFormatVersionSampled is bumped on any incompatible change to the
// layout above; the reader refuses versions it does not know instead of
// guessing.
const (
	recordingFormatVersion        = 1
	recordingFormatVersionSampled = 2
)

// unknownTracePrefix is what types.TraceId.String yields for an ID missing
// from the writer's table. Such a name cannot be resolved by string, so the
// reader falls back to the ID embedded in it (see resolveTracepoint).
const unknownTracePrefix = "unknown_trace_id_"

// errLegacyRecording marks a recording written before the header existed. Its
// numeric IDs carry no hint of the build that wrote them, so there is no
// reliable way to translate them and it is rejected rather than mis-decoded.
var errLegacyRecording = errors.New("recording has no format header: it was written by an older ior " +
	"whose numeric tracepoint IDs are specific to that build and cannot be decoded reliably; " +
	"re-record it with this version")

// recordingHeader precedes the records in the stream.
type recordingHeader struct {
	Version     uint32
	Tracepoints map[traceIdType]string // writer's ID -> tracepoint string, for IDs used in the records
	// Sampling is the run's sampling outcome; the zero value (no entries) for
	// a recording that sampled nothing, which is also what a version 1 header
	// decodes to.
	Sampling sampling.Summary
}

// newRecordingHeader records the writer's name for every trace ID that occurs
// in records, so the table stays small however large the recording is, and the
// run's sampling outcome. The version is the lowest one that still tells a
// reader the truth (see the Sampling note above).
func newRecordingHeader(records map[recordKey]Counter, samples sampling.Summary) recordingHeader {
	names := make(map[traceIdType]string)
	for key := range records {
		if _, ok := names[key.TraceID]; !ok {
			names[key.TraceID] = key.TraceID.String()
		}
	}
	header := recordingHeader{Version: recordingFormatVersion, Tracepoints: names}
	if samples.Active() {
		header.Version = recordingFormatVersionSampled
		header.Sampling = samples
	}
	return header
}

// encodeRecords writes the full recording stream (magic, header, records) to w.
//
// Memory: the records map is one gob value, and gob encodes a whole value into
// an in-memory buffer (grown by doubling) before it hands it to w in a single
// Write, which the zstd writer in encodeCompressed answers with a destination
// buffer of CompressBound of that size. The serialized form is ~60-120 bytes
// per record depending on path length, and the peak extra heap while saving
// was measured at ~330-520 bytes per record (2^17 and 2^18 keys, task rs2),
// i.e. up to ~2x the recorder's own ~250 bytes per record, transiently. The
// flag help and README state this as "up to ~500 bytes each while the file is
// written". Even at MaxRecordKeysLimit plus headroom the gob message stays
// far below gob's 8 GB message limit on 64-bit builds.
func encodeRecords(w io.Writer, records map[recordKey]Counter, samples sampling.Summary) error {
	if _, err := w.Write(recordingMagic[:]); err != nil {
		return fmt.Errorf("write recording magic: %w", err)
	}
	enc := gob.NewEncoder(w)
	if err := enc.Encode(newRecordingHeader(records, samples)); err != nil {
		return fmt.Errorf("encode recording header: %w", err)
	}
	if err := enc.Encode(records); err != nil {
		return fmt.Errorf("encode records: %w", err)
	}
	return nil
}

// decodeRecords reads a recording stream and returns its records with every
// trace ID translated to this build's table, and the sampling outcome of the
// run that wrote it (the zero Summary for an unsampled recording). A headerless
// legacy stream yields errLegacyRecording; anything that is neither format
// yields a decode error.
func decodeRecords(r io.Reader) (map[recordKey]Counter, sampling.Summary, error) {
	br := bufio.NewReader(r)
	prefix, err := br.Peek(len(recordingMagic))
	if err != nil || !bytes.Equal(prefix, recordingMagic[:]) {
		return nil, sampling.Summary{}, classifyHeaderless(br)
	}
	if _, err := br.Discard(len(recordingMagic)); err != nil {
		return nil, sampling.Summary{}, fmt.Errorf("read recording magic: %w", err)
	}
	dec := gob.NewDecoder(br)
	var header recordingHeader
	if err := dec.Decode(&header); err != nil {
		return nil, sampling.Summary{}, fmt.Errorf("decode recording header: %w", err)
	}
	if header.Version != recordingFormatVersion && header.Version != recordingFormatVersionSampled {
		return nil, sampling.Summary{}, fmt.Errorf("unsupported recording format version %d (this build reads versions %d and %d)",
			header.Version, recordingFormatVersion, recordingFormatVersionSampled)
	}
	var stored map[recordKey]Counter
	if err := dec.Decode(&stored); err != nil {
		return nil, sampling.Summary{}, fmt.Errorf("decode records: %w", err)
	}
	records, err := translateRecords(stored, header.Tracepoints)
	if err != nil {
		return nil, sampling.Summary{}, err
	}
	return records, header.Sampling, nil
}

// classifyHeaderless decides between "old recording" and "not a recording".
// It only trusts the legacy verdict when the whole stream really decodes as
// the pre-header layout, so garbage or truncated input keeps a plain decode
// error instead of a misleading "written by an older ior".
//
// Cost: a genuine legacy stream is decoded in full into a throwaway map, so
// this path uses memory proportional to that recording (once, then garbage).
// That is accepted deliberately. gob cannot check a stream's type without
// reading the value (the whole message is buffered before the destination
// type is compared), and Decode(nil) would skip the allocation but also skip
// the type check, which would let any unrelated gob stream be called "legacy".
// The path only runs for a file that is being rejected anyway.
func classifyHeaderless(r io.Reader) error {
	var legacy map[recordKey]Counter
	if err := gob.NewDecoder(r).Decode(&legacy); err != nil {
		return fmt.Errorf("not a recognised ior recording: %w", err)
	}
	return errLegacyRecording
}

// translateRecords rewrites the trace IDs of stored (the writer's numbering)
// into this build's numbering through the header's tracepoint table.
//
// Memory: the common case is a recording written by a build with the same ID
// table, where every ID maps to itself; stored is then returned untouched, so
// loading costs one map. Only a recording from a differently numbered build
// (the situation the header exists for) builds a second map, transiently
// doubling the peak while stored and the result coexist.
func translateRecords(stored map[recordKey]Counter, table map[traceIdType]string) (map[recordKey]Counter, error) {
	remap, err := buildRemap(stored, table)
	if err != nil {
		return nil, err
	}
	identity := true
	for from, to := range remap {
		if from != to {
			identity = false
			break
		}
	}
	if identity {
		return stored, nil
	}
	out := make(map[recordKey]Counter, len(stored))
	for key, cnt := range stored {
		key.TraceID = remap[key.TraceID]
		// Distinct writer IDs may resolve to one ID here (a header naming two
		// IDs with the same tracepoint); their counts are summed rather than
		// letting one overwrite the other.
		if prev, dup := out[key]; dup {
			cnt = prev.add(cnt)
		}
		out[key] = cnt
	}
	return out, nil
}

// buildRemap resolves every trace ID that occurs in stored to this build's ID.
func buildRemap(stored map[recordKey]Counter, table map[traceIdType]string) (map[traceIdType]traceIdType, error) {
	remap := make(map[traceIdType]traceIdType, len(table))
	for key := range stored {
		if _, done := remap[key.TraceID]; done {
			continue
		}
		id, err := resolveTracepoint(key.TraceID, table)
		if err != nil {
			return nil, err
		}
		remap[key.TraceID] = id
	}
	return remap, nil
}

// resolveTracepoint maps one stored ID to this build's ID via its tracepoint
// name. A name this build does not know (a syscall newer than this binary) is
// an error: guessing an ID would reintroduce the silent mislabelling.
//
// The one carve-out is the writer's own "unknown_trace_id_<n>" placeholder for
// an ID its table lacked. Its embedded number is kept only if this build also
// renders n as that same placeholder, i.e. n is unknown to the reader too, so
// the label is unchanged. If n is a real tracepoint here, keeping it would
// show a different syscall than the writer meant (the mislabel this format
// exists to prevent), so the file is rejected instead.
func resolveTracepoint(stored traceIdType, table map[traceIdType]string) (traceIdType, error) {
	name, ok := table[stored]
	if !ok {
		return 0, fmt.Errorf("corrupt recording: trace ID %d is missing from its tracepoint table", stored)
	}
	if id, ok := types.TraceIDByString(name); ok {
		return id, nil
	}
	if n, ok := strings.CutPrefix(name, unknownTracePrefix); ok {
		if v, err := strconv.ParseUint(n, 10, 32); err == nil {
			if id := traceIdType(v); id.String() == name {
				return id, nil
			}
			return 0, fmt.Errorf("recording has an unnamed tracepoint (%q) whose ID is a known tracepoint (%s) "+
				"in this ior build, so it cannot be labelled reliably; use the ior version that wrote it",
				name, traceIdType(v).String())
		}
	}
	return 0, fmt.Errorf("recording contains tracepoint %q, which this ior build does not know; "+
		"use the ior version that wrote it", name)
}

// WriteRecordingFile writes records to path as a complete .ior.zst recording
// in the current format. The tracer never calls it (it goes through
// serializeToFile, which names and atomically publishes the file); it exists so
// tests and tools in other packages can synthesise recordings without
// duplicating the on-disk layout, which is what let them silently fall out of
// step with the format before it had a header.
func WriteRecordingFile(path string, records []IterRecord) (retErr error) {
	iod := newIorData()
	for _, r := range records {
		iod.add(r.Path, r.TraceID, r.Comm, r.Pid, r.Tid, r.Flags, r.Cnt)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close %s: %w", path, err))
		}
	}()
	return iod.encodeCompressed(f, path)
}
