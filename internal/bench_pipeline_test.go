package internal

import (
	"context"
	"fmt"
	"testing"

	"ior/internal/benchutil"
	"ior/internal/event"
)

const (
	benchPipelineBaseTid = 2000
	benchPipelineSize    = 10_000
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

func benchmarkPipelineMix(b *testing.B, mix benchutil.EventMix, events, numThreads int) {
	b.Helper()
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	stream := mix.GenerateStream(gen, events, numThreads)
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
		el := newEventLoop(eventLoopConfig{})
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

func preseedBenchComms(el *eventLoop, numThreads int) {
	threadCount := numThreads
	if threadCount < 1 {
		threadCount = 1
	}
	for i := 0; i < threadCount; i++ {
		el.setCachedComm(benchPipelineBaseTid+uint32(i), "bench")
	}
}
