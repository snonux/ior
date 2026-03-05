package dashboard

import "math"

var sparkChars = []rune("▁▂▃▄▅▆▇█")

func renderSparkline(data []float64, width int) string {
	if len(data) == 0 || width <= 0 {
		return ""
	}

	samples := sampleForWidth(data, width)
	min, max := minMax(samples)
	if min == max {
		if min == 0 {
			return repeatRune(' ', width)
		}
		return repeatRune('▁', width)
	}

	row := make([]rune, width)
	scale := 16.0
	denom := max - min
	for i, value := range samples {
		level := int(math.Round((value - min) / denom * scale))
		if level < 0 {
			level = 0
		}
		if level > 16 {
			level = 16
		}

		// Collapse the previous two-row 0..16 scale to a single-row 0..7 scale.
		oneRow := level / 2
		if oneRow < 0 {
			oneRow = 0
		}
		if oneRow > 7 {
			oneRow = 7
		}
		row[i] = sparkChars[oneRow]
	}
	return string(row)
}

func renderLabeledSparkline(label string, data []float64, width int) string {
	spark := renderSparkline(data, width)
	if spark == "" {
		return label
	}
	return label + " " + spark
}

func sampleForWidth(data []float64, width int) []float64 {
	if width <= 0 || len(data) == 0 {
		return nil
	}

	if width < len(data) {
		start := len(data) - width
		return append([]float64(nil), data[start:]...)
	}

	if width == len(data) {
		return append([]float64(nil), data...)
	}

	if len(data) == 1 {
		out := make([]float64, width)
		for i := range out {
			out[i] = data[0]
		}
		return out
	}

	out := make([]float64, width)
	srcLast := len(data) - 1
	dstLast := width - 1
	for i := 0; i < width; i++ {
		// Nearest-neighbor upsampling preserves the original series shape
		// without introducing interpolated spikes between samples.
		srcIdx := int(math.Round(float64(i) * float64(srcLast) / float64(dstLast)))
		if srcIdx < 0 {
			srcIdx = 0
		}
		if srcIdx > srcLast {
			srcIdx = srcLast
		}
		out[i] = data[srcIdx]
	}
	return out
}

func minMax(values []float64) (float64, float64) {
	min := values[0]
	max := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max
}

func repeatRune(r rune, count int) string {
	if count <= 0 {
		return ""
	}
	out := make([]rune, count)
	for i := range out {
		out[i] = r
	}
	return string(out)
}
