package parquet

import (
	"path/filepath"
	"testing"
)

var benchmarkRecordSink Record

func BenchmarkWriterThroughput(b *testing.B) {
	rows := benchmarkRecords(256)
	dir := b.TempDir()
	writer, err := NewWriter(filepath.Join(dir, "writer-throughput.parquet"), WriterConfig{}, FileMetadata{Mode: "bench"})
	if err != nil {
		b.Fatalf("NewWriter() error = %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := writer.WriteRows(rows); err != nil {
			b.Fatalf("WriteRows() error = %v", err)
		}
		benchmarkRecordSink = rows[i%len(rows)]
	}

	b.StopTimer()
	if err := writer.Close(); err != nil {
		b.Fatalf("Close() error = %v", err)
	}
}

func BenchmarkRecorderQueueHandoff(b *testing.B) {
	row := testStreamRow(1, "read", false)
	session := newRecordingSession(1)
	recorder := &Recorder{
		active: session,
		status: Status{Active: true},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		row.Seq = uint64(i + 1)
		if err := recorder.Record(row, 0); err != nil {
			b.Fatalf("Record() error = %v", err)
		}
		select {
		case <-session.queue:
		default:
			b.Fatal("expected queued record request")
		}
	}

	b.StopTimer()
	session.stop(nil)
	recorder.finishSession(session, nil)
}

func benchmarkRecords(n int) []Record {
	rows := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		row := testStreamRow(uint64(i+1), "read", i%7 == 0)
		rows = append(rows, RecordFromStream(row, uint64(i%4)))
	}
	return rows
}
