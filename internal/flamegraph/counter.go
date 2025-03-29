package flamegraph

type counter struct {
	count          uint64
	duration       uint64
	durationToPrev uint64
}

func (c counter) add(other counter) counter {
	c.count += other.count
	c.duration += other.duration
	c.durationToPrev += other.durationToPrev
	return c
}
