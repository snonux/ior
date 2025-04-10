package flamegraph

type Counter struct {
	Count          uint64
	Duration       uint64
	DurationToPrev uint64
	Bytes          uint64 // TODO: implement
}

func (c Counter) add(other Counter) Counter {
	c.Count += other.Count
	c.Duration += other.Duration
	c.DurationToPrev += other.DurationToPrev
	c.Bytes += other.Bytes
	return c
}
