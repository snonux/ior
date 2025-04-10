package flamegraph

import (
	"fmt"
)

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

func (c Counter) ValueByName(name string) uint64 {
	// Convert the numbers to strings here
	switch name {
	case "count":
		return c.Count
	case "duration":
		return c.Duration
	case "durationToPrev":
		return c.DurationToPrev
	case "bytes":
		return c.Bytes
	default:
		panic(fmt.Sprintln("No", name, "in count record"))
	}
}
