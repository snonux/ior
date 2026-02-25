package dashboard

import "math"

var sparkChars = []rune("▁▂▃▄▅▆▇█")

func renderSparkline(data []float64, width int) string {
	if len(data) == 0 || width <= 0 {
		return ""
	}

	samples := sampleForWidth(data, width)
	min, max := minMax(samples)
	line := ""
	if min == max {
		line = repeatRune('▄', len(samples))
		return line + "\n" + line
	}

	out := make([]rune, len(samples))
	scale := float64(len(sparkChars) - 1)
	denom := max - min
	for i, value := range samples {
		idx := int(math.Round((value - min) / denom * scale))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		out[i] = sparkChars[idx]
	}
	line = string(out)
	return line + "\n" + line
}

func sampleForWidth(data []float64, width int) []float64 {
	if width >= len(data) {
		return append([]float64(nil), data...)
	}
	if width == 1 {
		return []float64{data[len(data)-1]}
	}

	last := len(data) - 1
	samples := make([]float64, width)
	for i := 0; i < width; i++ {
		idx := int(math.Round(float64(i) * float64(last) / float64(width-1)))
		samples[i] = data[idx]
	}
	return samples
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
