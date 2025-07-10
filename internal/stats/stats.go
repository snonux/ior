package stats

import (
	"math"
	"sort"
	"sync"
	"time"
)

// IOStats represents statistical data for I/O operations
type IOStats struct {
	mu sync.RWMutex

	// Basic metrics
	Count        int64
	TotalBytes   int64
	TotalLatency time.Duration

	// Latency statistics
	MinLatency    time.Duration
	MaxLatency    time.Duration
	MeanLatency   time.Duration
	MedianLatency time.Duration
	P95Latency    time.Duration
	P99Latency    time.Duration

	// Throughput statistics
	MinBytes    int64
	MaxBytes    int64
	MeanBytes   float64
	MedianBytes int64
	P95Bytes    int64
	P99Bytes    int64

	// Time series data for trend analysis
	latencyHistory []time.Duration
	bytesHistory   []int64
	timestamps     []time.Time
}

// NewIOStats creates a new IOStats instance
func NewIOStats() *IOStats {
	return &IOStats{
		MinLatency: time.Duration(math.MaxInt64),
		MinBytes:   math.MaxInt64,
	}
}

// AddOperation adds a new I/O operation to the statistics
func (s *IOStats) AddOperation(bytes int64, latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.Count++
	s.TotalBytes += bytes
	s.TotalLatency += latency

	// Update latency statistics
	if latency < s.MinLatency {
		s.MinLatency = latency
	}
	if latency > s.MaxLatency {
		s.MaxLatency = latency
	}

	// Update bytes statistics
	if bytes < s.MinBytes {
		s.MinBytes = bytes
	}
	if bytes > s.MaxBytes {
		s.MaxBytes = bytes
	}

	// Store history
	s.latencyHistory = append(s.latencyHistory, latency)
	s.bytesHistory = append(s.bytesHistory, bytes)
	s.timestamps = append(s.timestamps, now)

	// Calculate percentiles if we have enough data
	if len(s.latencyHistory) > 0 {
		s.calculatePercentiles()
	}
}

// calculatePercentiles calculates various statistical measures
func (s *IOStats) calculatePercentiles() {
	// Sort the data for percentile calculations
	latencies := make([]time.Duration, len(s.latencyHistory))
	copy(latencies, s.latencyHistory)
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	bytes := make([]int64, len(s.bytesHistory))
	copy(bytes, s.bytesHistory)
	sort.Slice(bytes, func(i, j int) bool {
		return bytes[i] < bytes[j]
	})

	// Calculate mean
	var totalLatency time.Duration
	var totalBytes int64
	for i := range latencies {
		totalLatency += latencies[i]
		totalBytes += bytes[i]
	}
	s.MeanLatency = totalLatency / time.Duration(len(latencies))
	s.MeanBytes = float64(totalBytes) / float64(len(bytes))

	// Calculate median and percentiles
	mid := len(latencies) / 2
	s.MedianLatency = latencies[mid]
	s.MedianBytes = bytes[mid]

	p95Index := int(float64(len(latencies)) * 0.95)
	p99Index := int(float64(len(latencies)) * 0.99)
	if p95Index < len(latencies) {
		s.P95Latency = latencies[p95Index]
		s.P95Bytes = bytes[p95Index]
	}
	if p99Index < len(latencies) {
		s.P99Latency = latencies[p99Index]
		s.P99Bytes = bytes[p99Index]
	}
}

// GetStats returns a map of all statistics
func (s *IOStats) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"count":         s.Count,
		"total_bytes":   s.TotalBytes,
		"total_latency": s.TotalLatency,
		"latency": map[string]interface{}{
			"min":    s.MinLatency,
			"max":    s.MaxLatency,
			"mean":   s.MeanLatency,
			"median": s.MedianLatency,
			"p95":    s.P95Latency,
			"p99":    s.P99Latency,
		},
		"bytes": map[string]interface{}{
			"min":    s.MinBytes,
			"max":    s.MaxBytes,
			"mean":   s.MeanBytes,
			"median": s.MedianBytes,
			"p95":    s.P95Bytes,
			"p99":    s.P99Bytes,
		},
	}
}

// GetTimeSeriesData returns the historical data for trend analysis
func (s *IOStats) GetTimeSeriesData() ([]time.Time, []time.Duration, []int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	timestamps := make([]time.Time, len(s.timestamps))
	latencies := make([]time.Duration, len(s.latencyHistory))
	bytes := make([]int64, len(s.bytesHistory))

	copy(timestamps, s.timestamps)
	copy(latencies, s.latencyHistory)
	copy(bytes, s.bytesHistory)

	return timestamps, latencies, bytes
}
