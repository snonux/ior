package dashboard

import "math"
import "strings"

var sparkRowChars = []rune(" ▁▂▃▄▅▆▇█")

func renderSparkline(data []float64, width int) string {
	if len(data) == 0 || width <= 0 {
		return ""
	}

	samples := sampleForWidth(data, width)
	leftPad := 0
	if len(samples) < width {
		leftPad = width - len(samples)
	}
	min, max := minMax(samples)
	if min == max {
		top := repeatRune(' ', width)
		bottom := repeatRune(' ', leftPad) + repeatRune('█', len(samples))
		return top + "\n" + bottom
	}

	top := make([]rune, width)
	bottom := make([]rune, width)
	for i := 0; i < leftPad; i++ {
		top[i] = ' '
		bottom[i] = ' '
	}
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

		topLevel := level - 8
		if topLevel < 0 {
			topLevel = 0
		}
		bottomLevel := level
		if bottomLevel > 8 {
			bottomLevel = 8
		}

		col := leftPad + i
		top[col] = sparkRowChars[topLevel]
		bottom[col] = sparkRowChars[bottomLevel]
	}
	return string(top) + "\n" + string(bottom)
}

func renderLabeledSparkline(label string, data []float64, width int) string {
	spark := renderSparkline(data, width)
	if spark == "" {
		return label
	}
	lines := strings.Split(spark, "\n")
	if len(lines) == 1 {
		return label + " " + lines[0]
	}
	pad := repeatRune(' ', len([]rune(label))+1)
	return label + " " + lines[0] + "\n" + pad + lines[1]
}

func sampleForWidth(data []float64, width int) []float64 {
	if width >= len(data) {
		return append([]float64(nil), data...)
	}
	start := len(data) - width
	return append([]float64(nil), data[start:]...)
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
