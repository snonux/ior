package internal

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"ior/internal/benchutil"
	"ior/internal/event"
	"ior/internal/flamegraph"
	"ior/internal/parquet"
	"ior/internal/statsengine"
	"ior/internal/streamrow"
)

const (
	benchPipelineBaseTid = 2000
	benchPipelineSize    = 10_000
	benchParquetSize     = 2_000
)

func BenchmarkPipelineReadHeavy(b *testing.B) {
	benchmarkPipelineMix(b, benchutil.ReadHeavy, benchPipelineSize, 10)
}

func BenchmarkPipelineWriteHeavy(b *testing.B) {
	benchmarkPipelineMix(b, benchutil.WriteHeavy, benchPipelineSize, 10)
}

func BenchmarkPipelineMetadataHeavy(b *testing.B) {
	benchmarkPipelineMix(b, benchutil.MetadataHeavy, benchPipelineSize, 10)
}

func BenchmarkPipelineDiverseAllTypes(b *testing.B) {
	benchmarkPipelineMix(b, benchutil.DiverseAllTypes, benchPipelineSize, 10)
}

func BenchmarkPipelineScaling(b *testing.B) {
	for _, events := range []int{100, 1000, 10000, 100000} {
		events := events
		b.Run(fmt.Sprintf("events_%d", events), func(b *testing.B) {
			benchmarkPipelineMix(b, benchutil.DiverseAllTypes, events, 10)
		})
	}
}

func BenchmarkPipelineThreadScaling(b *testing.B) {
	for _, threads := range []int{1, 10, 100, 1000} {
		threads := threads
		b.Run(fmt.Sprintf("threads_%d", threads), func(b *testing.B) {
			benchmarkPipelineMix(b, benchutil.DiverseAllTypes, benchPipelineSize, threads)
		})
	}
}

func BenchmarkPipelineHeadlessParquetCapture(b *testing.B) {
	benchmarkPipelineHeadlessParquet(b, benchutil.DiverseAllTypes, benchParquetSize, 10)
}

func BenchmarkPipelineTUIParquetRecording(b *testing.B) {
	benchmarkPipelineTUIParquet(b, benchutil.DiverseAllTypes, benchParquetSize, 10)
}

func benchmarkPipelineMix(b *testing.B, mix benchutil.EventMix, events, numThreads int) {
	b.Helper()
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	stream, err := mix.GenerateStream(gen, events, numThreads)
	if err != nil {
		b.Fatalf("generate stream: %v", err)
	}
	if len(stream) == 0 {
		b.Fatal("generated empty benchmark stream")
	}

	var totalPairs int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()

		rawCh := make(chan []byte, len(stream))
		for _, raw := range stream {
			rawCh <- raw
		}
		close(rawCh)

		var pairCount int64
		el := mustNewEventLoop(b, eventLoopConfig{})
		preseedBenchComms(el, numThreads)
		el.printCb = func(ep *event.Pair) {
			pairCount++
			ep.Recycle()
		}

		ctx, cancel := context.WithCancel(context.Background())

		b.StartTimer()
		el.run(ctx, rawCh)
		b.StopTimer()

		cancel()
		totalPairs += pairCount
	}

	if b.N > 0 {
		b.ReportMetric(float64(totalPairs)/float64(b.N), "pairs/op")
	}
}

func benchmarkPipelineHeadlessParquet(b *testing.B, mix benchutil.EventMix, events, numThreads int) {
	b.Helper()
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	stream, err := mix.GenerateStream(gen, events, numThreads)
	if err != nil {
		b.Fatalf("generate stream: %v", err)
	}
	if len(stream) == 0 {
		b.Fatal("generated empty benchmark stream")
	}

	dir := b.TempDir()
	var totalPairs int64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()

		rawCh := make(chan []byte, len(stream))
		for _, raw := range stream {
			rawCh <- raw
		}
		close(rawCh)

		el := mustNewEventLoop(b, eventLoopConfig{})
		preseedBenchComms(el, numThreads)

		recorder := parquet.NewRecorder(parquet.RecorderConfig{})
		path := filepath.Join(dir, fmt.Sprintf("headless-%d.parquet", i))
		if err := recorder.Start(path, parquet.StartOptions{
			Metadata: parquet.FileMetadata{Mode: "headless"},
		}); err != nil {
			b.Fatalf("recorder.Start() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		sink := newHeadlessParquetSink(recorder, cancel)
		sink.configure(el)

		b.StartTimer()
		el.run(ctx, rawCh)
		b.StopTimer()

		cancel()
		if err := recorder.Stop(); err != nil {
			b.Fatalf("recorder.Stop() error = %v", err)
		}
		if err := sink.err(); err != nil {
			b.Fatalf("sink.err() = %v", err)
		}
		totalPairs += int64(events)
	}

	if b.N > 0 {
		b.ReportMetric(float64(totalPairs)/float64(b.N), "pairs/op")
	}
}

func benchmarkPipelineTUIParquet(b *testing.B, mix benchutil.EventMix, events, numThreads int) {
	b.Helper()
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	stream, err := mix.GenerateStream(gen, events, numThreads)
	if err != nil {
		b.Fatalf("generate stream: %v", err)
	}
	if len(stream) == 0 {
		b.Fatal("generated empty benchmark stream")
	}

	dir := b.TempDir()
	var totalPairs int64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()

		rawCh := make(chan []byte, len(stream))
		for _, raw := range stream {
			rawCh <- raw
		}
		close(rawCh)

		el := mustNewEventLoop(b, eventLoopConfig{})
		preseedBenchComms(el, numThreads)

		engine := statsengine.NewEngine(statsengine.DefaultTopN)
		streamBuf := streamrow.NewRingBuffer()
		streamSeq := streamrow.NewSequencer(0)
		liveTrie := flamegraph.NewLiveTrie([]string{"comm", "tracepoint", "path"}, "count", "count")

		recorder := parquet.NewRecorder(parquet.RecorderConfig{})
		path := filepath.Join(dir, fmt.Sprintf("tui-%d.parquet", i))
		if err := recorder.Start(path, parquet.StartOptions{
			Metadata: parquet.FileMetadata{Mode: "tui"},
		}); err != nil {
			b.Fatalf("recorder.Start() error = %v", err)
		}

		var recordErr error
		el.printCb = func(ep *event.Pair) {
			row := streamrow.New(streamSeq.Next(), ep)
			engine.Ingest(ep)
			streamBuf.Push(row)
			if recordErr == nil {
				recordErr = recorder.Record(row, 0)
			}
			liveTrie.Ingest(ep)
			ep.Recycle()
		}

		b.StartTimer()
		el.run(context.Background(), rawCh)
		b.StopTimer()

		if recordErr != nil {
			b.Fatalf("recorder.Record() error = %v", recordErr)
		}
		if err := recorder.Stop(); err != nil {
			b.Fatalf("recorder.Stop() error = %v", err)
		}
		totalPairs += int64(events)
		_ = engine
		_ = liveTrie
		_ = streamBuf
	}

	if b.N > 0 {
		b.ReportMetric(float64(totalPairs)/float64(b.N), "pairs/op")
	}
}

func preseedBenchComms(el *eventLoop, numThreads int) {
	threadCount := numThreads
	if threadCount < 1 {
		threadCount = 1
	}
	for i := 0; i < threadCount; i++ {
		el.setCachedComm(benchPipelineBaseTid+uint32(i), "bench")
	}
}
