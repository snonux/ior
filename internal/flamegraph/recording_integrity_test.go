package flamegraph

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ior/internal/sampling"

	"github.com/DataDog/zstd"
	zstddecode "github.com/klauspost/compress/zstd"
)

func TestLoadFromFileValidatesCompleteRecording(t *testing.T) {
	for name, iod := range integrityFixtures() {
		t.Run(name, func(t *testing.T) {
			assertIntegrityLoaded(t, compressedRecording(t, iod), iod)
		})
	}
}

func TestLoadFromFileRejectsTruncatedZstdEnd(t *testing.T) {
	for name, iod := range integrityFixtures() {
		compressed := compressedRecording(t, iod)
		for cut := 1; cut <= 4; cut++ {
			t.Run(fmt.Sprintf("%s/cut%d", name, cut), func(t *testing.T) {
				assertIntegrityRejected(t, compressed[:len(compressed)-cut])
			})
		}
	}
}

func TestLoadFromFileRejectsCorruptZstdTail(t *testing.T) {
	for name, iod := range integrityFixtures() {
		t.Run(name, func(t *testing.T) {
			compressed := compressedRecording(t, iod)
			assertIntegrityRejected(t, append(compressed, []byte("corrupt zstd tail")...))
		})
	}
}

// Flush makes every gob byte readable before Close writes the frame's last
// block. A loader must validate that last block even after gob Decode succeeds.
func TestLoadFromFileRejectsMissingFlushedZstdEnd(t *testing.T) {
	for name, iod := range integrityFixtures() {
		t.Run(name, func(t *testing.T) {
			var compressed bytes.Buffer
			writer := zstd.NewWriter(&compressed)
			closed := false
			defer func() {
				if !closed {
					_ = writer.Close()
				}
			}()
			if err := encodeRecords(writer, iod.records, iod.sampling); err != nil {
				t.Fatal(err)
			}
			if err := writer.Flush(); err != nil {
				t.Fatal(err)
			}
			unfinished := append([]byte(nil), compressed.Bytes()...)
			err := writer.Close()
			closed = true
			if err != nil {
				t.Fatal(err)
			}
			assertIntegrityLoaded(t, compressed.Bytes(), iod)
			assertIntegrityRejected(t, unfinished)
		})
	}
}

// The small fixtures fit in bufio's read-ahead, so checking the underlying
// decompressor instead of the reader given to gob would miss these tails.
func TestLoadFromFileRejectsExtraPayload(t *testing.T) {
	for name, iod := range integrityFixtures() {
		raw, err := iod.serialize()
		if err != nil {
			t.Fatal(err)
		}
		compressed := compressedRecording(t, iod)
		for tailName, data := range map[string][]byte{
			"raw byte":             compressIntegrityPayload(t, append(append([]byte(nil), raw...), 0)),
			"extra gob map":        compressIntegrityPayload(t, recordingWithExtraGob(t, iod)),
			"second raw recording": compressIntegrityPayload(t, append(append([]byte(nil), raw...), raw...)),
			"concatenated frames":  append(append([]byte(nil), compressed...), compressed...),
			"partial frame header": append(append([]byte(nil), compressed...), 0x28, 0xb5, 0x2f),
		} {
			t.Run(name+"/"+tailName, func(t *testing.T) { assertIntegrityRejected(t, data) })
		}
	}
}

func TestLoadFromFileValidatesZstdChecksum(t *testing.T) {
	iod := iorData{records: fixtureRecords(3), sampling: sampledSummary()}
	raw, err := iod.serialize()
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := zstddecode.NewWriter(nil, zstddecode.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = encoder.Close() }()
	compressed := encoder.EncodeAll(raw, nil)
	assertIntegrityLoaded(t, compressed, iod)
	compressed[len(compressed)-1] ^= 0xff
	assertIntegrityRejected(t, compressed)
}

func TestDeserializeRejectsTrailingDataWithoutChangingState(t *testing.T) {
	iod := iorData{records: fixtureRecords(3), sampling: sampledSummary()}
	raw, err := iod.serialize()
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"extra gob map":    recordingWithExtraGob(t, iod),
		"second recording": append(raw, raw...),
	} {
		t.Run(name, func(t *testing.T) {
			previous := previousIntegrityData()
			loaded := previousIntegrityData()
			if err := loaded.deserialize(bytes.NewBuffer(raw)); err == nil {
				t.Fatal("accepted trailing uncompressed data")
			}
			if !reflect.DeepEqual(loaded, previous) {
				t.Fatal("failed deserialize changed previously loaded state")
			}
		})
	}
}
func integrityFixtures() map[string]iorData {
	return map[string]iorData{
		"empty":   newIorData(),
		"records": {records: fixtureRecords(3)},
		"sampled": {records: fixtureRecords(3), sampling: sampledSummary()},
		"nil map": {},
	}
}

func compressedRecording(t *testing.T, iod iorData) []byte {
	t.Helper()
	var compressed bytes.Buffer
	if err := iod.encodeCompressed(&compressed, "fixture"); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func writeIntegrityRecording(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.ior.zst")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// An error must neither replace a previously loaded recording nor expose a
// partial iterator or sampling summary to public callers.
func assertIntegrityRejected(t *testing.T, data []byte) {
	t.Helper()
	path := writeIntegrityRecording(t, data)
	previous := previousIntegrityData()
	iod := previousIntegrityData()
	if err := iod.loadFromFile(path); err == nil {
		t.Fatal("accepted invalid recording")
	} else if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not name %s", err, path)
	}
	if !reflect.DeepEqual(iod, previous) {
		t.Fatal("failed load changed existing records, sampling or recording limits")
	}
	if records, samples, err := LoadRecording(path); err == nil || records != nil || samples.Active() {
		t.Fatalf("LoadRecording returned records=%v samples=%+v err=%v", records != nil, samples, err)
	}
}

func assertIntegrityLoaded(t *testing.T, data []byte, want iorData) {
	t.Helper()
	path := writeIntegrityRecording(t, data)
	iod, err := newIorDataFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(iod.records, want.records) || !reflect.DeepEqual(iod.sampling, want.sampling) {
		t.Fatalf("loaded recording differs: got %+v, want %+v", iod, want)
	}
}

func previousIntegrityData() iorData {
	return iorData{
		records:  fixtureRecords(2),
		sampling: sampling.New([]sampling.Entry{{Syscall: "write", Rate: 4}}, "unavailable"),
		maxKeys:  17,
		folds:    foldCounts{pidless: 2, other: 3},
	}
}

func compressIntegrityPayload(t *testing.T, raw []byte) []byte {
	t.Helper()
	compressed, err := zstd.Compress(nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	return compressed
}

func recordingWithExtraGob(t *testing.T, iod iorData) []byte {
	t.Helper()
	var raw bytes.Buffer
	raw.Write(recordingMagic[:])
	enc := gob.NewEncoder(&raw)
	for _, value := range []any{newRecordingHeader(iod.records, iod.sampling), iod.records, iod.records} {
		if err := enc.Encode(value); err != nil {
			t.Fatal(err)
		}
	}
	return raw.Bytes()
}
