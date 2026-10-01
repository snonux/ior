package flamegraph

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
)

// Streaming the records message (task tz2).
//
// A reader decodes the records with a single gob Decode of a
// map[recordKey]Counter, so the stream has to carry them as one gob message.
// gob.Encoder.Encode builds a message completely in memory (a buffer grown by
// append, ~5x the message in allocations) and hands it over in one Write, to
// which the zstd writer answers with a CompressBound-sized destination buffer.
// For a large recording that was the save-time memory peak.
//
// writeRecordsMessage writes the same message without ever holding it. In the
// gob wire format (see "Encoding details" in the encoding/gob documentation)
// a top-level map value is
//
//	message  = uint(len(payload)) payload
//	payload  = int(typeID) 0x00 uint(count) pairs
//	pairs    = (key elem)*
//
// where 0x00 is the field delta of the singleton field gob wraps every
// non-struct value in, and every key and elem is encoded on its own, without
// reference to its neighbours. The pair bytes come from gob itself: up to
// recordsBatchSize records at a time are encoded as a small map by a batch
// encoder, and each batch message is stripped of its framing (type
// definitions, length, type ID, singleton delta, count). The concatenated
// pairs of all batches are exactly what one Encode of the whole map writes,
// up to map iteration order, which gob leaves random anyway. The type
// definitions and the type ID that frame the records message come from the
// stream's own encoder (probe), so they are the ones a plain Encode would
// have written. Because the length comes first, a sizing pass encodes every
// batch once just to add up the pair bytes, and the writing pass encodes them
// again. Memory stays at one batch; the price is encoding the records twice.

// recordsBatchSize is the number of records encoded per batch. With the
// typical 60-120 encoded bytes per record a batch is ~60-120 KB, so it is
// also the size of every write the zstd writer sees; a pathological batch of
// PATH_MAX paths stays at ~4 MB.
var recordsBatchSize = 1024

// gobMaxMessage mirrors encoding/gob's tooBig (8 GB on 64-bit, 1 GB on
// 32-bit builds): gob refuses to encode or decode a message of this length or
// longer, so writeRecordsMessage refuses it as well, with the same effect as
// the stock encoder.
const gobMaxMessage = (1 << 30) << (^uint(0) >> 62)

// errRecordsChanged reports a records map that changed between the sizing
// and the writing pass; the length prefix would no longer match the message.
var errRecordsChanged = errors.New("records changed while being written")

// switchWriter is the writer of the stream's gob.Encoder. Pointing it at the
// stream or at a scratch buffer lets the same encoder write the header (to
// the stream) and the probe (to scratch), so the probe sees exactly the type
// definitions the stream still lacks.
type switchWriter struct{ w io.Writer }

func (s *switchWriter) Write(p []byte) (int, error) { return s.w.Write(p) }

// recordsStreamer holds the per-message state of writeRecordsMessage.
type recordsStreamer struct {
	enc    *gob.Encoder // the stream's encoder
	sw     *switchWriter
	prefix []byte // int(typeID) 0x00 of the stream's records message

	// The batches go through an encoder of their own, as a map of pointers:
	// gob flattens pointers, so the pairs are the same bytes as for
	// map[recordKey]Counter, but reflect hands out a pointer-shaped map key
	// or value without the heap copy it makes of a recordKey or Counter.
	// That keeps encoding free of per-record garbage. keys and cnts back the
	// pointers and, like batch and scratch, are reused from batch to batch.
	batchEnc *gob.Encoder
	scratch  bytes.Buffer // one encoded batch message
	batch    map[*recordKey]*Counter
	keys     []recordKey
	cnts     []Counter
}

func newRecordsStreamer(enc *gob.Encoder, sw *switchWriter) *recordsStreamer {
	s := &recordsStreamer{
		enc:   enc,
		sw:    sw,
		batch: make(map[*recordKey]*Counter, recordsBatchSize),
		keys:  make([]recordKey, 0, recordsBatchSize),
		cnts:  make([]Counter, 0, recordsBatchSize),
	}
	s.batchEnc = gob.NewEncoder(&s.scratch)
	return s
}

// writeRecordsMessage writes records to w as the one gob message that
// enc.Encode(records) would write (see the note above), including any type
// definitions enc has not sent yet. enc must write through sw, which currently
// points at w; it points at w again when this returns.
func writeRecordsMessage(w io.Writer, enc *gob.Encoder, sw *switchWriter, records map[recordKey]Counter) error {
	s := newRecordsStreamer(enc, sw)
	defer func() { sw.w = w }()
	typeDefs, err := s.probe()
	if err != nil {
		return err
	}
	if _, err := w.Write(typeDefs); err != nil {
		return err
	}
	var pairBytes int
	if err := s.forEachBatch(records, func(pairs []byte) error {
		pairBytes += len(pairs)
		return nil
	}); err != nil {
		return err
	}
	if err := s.writeHead(w, len(records), pairBytes); err != nil {
		return err
	}
	return s.writePairs(w, records, pairBytes)
}

// probe encodes an empty records map. Everything before its value message is
// the type definitions this encoder still owes the stream (returned verbatim),
// and the value message, int(typeID) 0x00 0x00 (count 0), yields the prefix of
// every records message. The format checks guard against a gob whose wire
// format is not the documented one, which would otherwise corrupt the file.
func (s *recordsStreamer) probe() ([]byte, error) {
	s.scratch.Reset()
	s.sw.w = &s.scratch
	if err := s.enc.Encode(map[recordKey]Counter{}); err != nil {
		return nil, err
	}
	msgs := s.scratch.Bytes()
	for len(msgs) > 0 {
		payload, rest, err := splitGobMessage(msgs)
		if err != nil {
			return nil, err
		}
		id, idLen, err := readGobInt(payload)
		if err != nil {
			return nil, err
		}
		if id < 0 { // a type definition: keep scanning
			msgs = rest
			continue
		}
		if len(rest) != 0 || !bytes.Equal(payload[idLen:], []byte{0, 0}) {
			return nil, errors.New("unexpected gob encoding of an empty records map")
		}
		s.prefix = append([]byte(nil), payload[:idLen+1]...)
		typeDefs := s.scratch.Bytes()[:s.scratch.Len()-len(msgs)]
		return append([]byte(nil), typeDefs...), nil
	}
	return nil, errors.New("gob wrote no value message for an empty records map")
}

// forEachBatch encodes records in batches of recordsBatchSize and calls fn
// with the pair bytes of each batch. The slice passed to fn is only valid
// until fn returns.
func (s *recordsStreamer) forEachBatch(records map[recordKey]Counter, fn func(pairs []byte) error) error {
	s.resetBatch()
	for key, cnt := range records {
		s.keys = append(s.keys, key)
		s.cnts = append(s.cnts, cnt)
		if len(s.keys) < recordsBatchSize {
			continue
		}
		if err := s.flushBatch(fn); err != nil {
			return err
		}
	}
	if len(s.keys) == 0 {
		return nil
	}
	return s.flushBatch(fn)
}

// resetBatch empties the batch, keeping its storage.
func (s *recordsStreamer) resetBatch() {
	clear(s.batch)
	s.keys, s.cnts = s.keys[:0], s.cnts[:0]
}

// flushBatch encodes the current batch, hands its pairs to fn and empties
// the batch.
func (s *recordsStreamer) flushBatch(fn func(pairs []byte) error) error {
	for i := range s.keys {
		s.batch[&s.keys[i]] = &s.cnts[i]
	}
	s.scratch.Reset()
	if err := s.batchEnc.Encode(s.batch); err != nil {
		return err
	}
	pairs, err := batchPairs(s.scratch.Bytes(), len(s.keys))
	if err != nil {
		return err
	}
	s.resetBatch()
	return fn(pairs)
}

// batchPairs strips the framing off an encoded batch of count records: the
// type definitions the batch encoder sends with its first batch, then the
// value message's length, int(typeID), singleton delta 0x00 and count. The
// checks guard against a gob whose wire format is not the documented one,
// which would otherwise corrupt the file.
func batchPairs(msgs []byte, count int) ([]byte, error) {
	for {
		payload, rest, err := splitGobMessage(msgs)
		if err != nil {
			return nil, err
		}
		id, idLen, err := readGobInt(payload)
		if err != nil {
			return nil, err
		}
		if id < 0 { // a type definition (first batch only)
			msgs = rest
			continue
		}
		if len(rest) != 0 || len(payload) == idLen || payload[idLen] != 0 {
			return nil, errors.New("unexpected gob encoding of a records batch")
		}
		got, countLen, err := readGobUint(payload[idLen+1:])
		if err != nil {
			return nil, err
		}
		if got != uint64(count) {
			return nil, fmt.Errorf("gob encoded a records batch of %d as %d records", count, got)
		}
		return payload[idLen+1+countLen:], nil
	}
}

// writeHead writes the start of the records message: its length, the prefix
// and the record count. pairBytes is the size of all pairs that follow.
func (s *recordsStreamer) writeHead(w io.Writer, count, pairBytes int) error {
	countBytes := appendGobUint(nil, uint64(count))
	payloadLen := len(s.prefix) + len(countBytes) + pairBytes
	if payloadLen >= gobMaxMessage {
		return errors.New("gob: encoder: message too big")
	}
	head := appendGobUint(nil, uint64(payloadLen))
	head = append(head, s.prefix...)
	head = append(head, countBytes...)
	_, err := w.Write(head)
	return err
}

// writePairs is the writing pass: it encodes the records again and writes
// their pairs to w, one batch per Write. Writing a different number of bytes
// than the sizing pass counted would leave a corrupt message, so that is an
// error (the caller discards the file).
func (s *recordsStreamer) writePairs(w io.Writer, records map[recordKey]Counter, want int) error {
	written := 0
	err := s.forEachBatch(records, func(pairs []byte) error {
		if written += len(pairs); written > want {
			return errRecordsChanged
		}
		_, err := w.Write(pairs)
		return err
	})
	if err == nil && written != want {
		err = errRecordsChanged
	}
	return err
}
