package stats

import (
	"math"
	"time"
)

// PatternAnalysis represents the analysis of I/O patterns
type PatternAnalysis struct {
	// Burst detection
	BurstCount     int
	BurstDuration  time.Duration
	BurstThreshold int64

	// Periodicity detection
	IsPeriodic     bool
	PeriodDuration time.Duration

	// Trend analysis
	TrendSlope     float64
	TrendDirection string // "increasing", "decreasing", "stable"
}

// AnalyzePatterns analyzes the I/O patterns from the statistics
func (s *IOStats) AnalyzePatterns() *PatternAnalysis {
	s.mu.RLock()
	defer s.mu.RUnlock()

	analysis := &PatternAnalysis{
		BurstThreshold: 1000, // Configurable threshold
	}

	// Analyze bursts
	analysis.analyzeBursts(s.bytesHistory, s.timestamps)

	// Analyze periodicity
	analysis.analyzePeriodicity(s.bytesHistory, s.timestamps)

	// Analyze trends
	analysis.analyzeTrend(s.bytesHistory, s.timestamps)

	return analysis
}

func (a *PatternAnalysis) analyzeBursts(bytes []int64, timestamps []time.Time) {
	if len(bytes) < 2 {
		return
	}

	var currentBurstSize int64
	var burstStart time.Time
	inBurst := false

	for i := 0; i < len(bytes); i++ {
		if bytes[i] > a.BurstThreshold {
			if !inBurst {
				burstStart = timestamps[i]
				inBurst = true
			}
			currentBurstSize += bytes[i]
		} else if inBurst {
			a.BurstCount++
			a.BurstDuration += timestamps[i].Sub(burstStart)
			inBurst = false
			currentBurstSize = 0
		}
	}
}

func (a *PatternAnalysis) analyzePeriodicity(bytes []int64, timestamps []time.Time) {
	if len(bytes) < 4 {
		return
	}

	// Simple periodicity detection using autocorrelation
	mean := 0.0
	for _, b := range bytes {
		mean += float64(b)
	}
	mean /= float64(len(bytes))

	var maxCorrelation float64
	var bestPeriod int

	// Check for periods up to half the data length
	for period := 1; period < len(bytes)/2; period++ {
		correlation := 0.0
		count := 0

		for i := 0; i < len(bytes)-period; i++ {
			correlation += (float64(bytes[i]) - mean) * (float64(bytes[i+period]) - mean)
			count++
		}

		if count > 0 {
			correlation /= float64(count)
			if correlation > maxCorrelation {
				maxCorrelation = correlation
				bestPeriod = period
			}
		}
	}

	// If we found a strong correlation, consider it periodic
	if maxCorrelation > 0.7 { // Threshold for periodicity
		a.IsPeriodic = true
		if bestPeriod > 0 && bestPeriod < len(timestamps)-1 {
			a.PeriodDuration = timestamps[bestPeriod].Sub(timestamps[0])
		}
	}
}

func (a *PatternAnalysis) analyzeTrend(bytes []int64, timestamps []time.Time) {
	if len(bytes) < 2 {
		return
	}

	// Simple linear regression
	var sumX, sumY, sumXY, sumX2 float64
	n := float64(len(bytes))

	for i := 0; i < len(bytes); i++ {
		x := float64(timestamps[i].UnixNano())
		y := float64(bytes[i])
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	// Calculate slope
	a.TrendSlope = (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)

	// Determine trend direction
	if math.Abs(a.TrendSlope) < 0.1 {
		a.TrendDirection = "stable"
	} else if a.TrendSlope > 0 {
		a.TrendDirection = "increasing"
	} else {
		a.TrendDirection = "decreasing"
	}
}
