package globalfilter

import (
	"ior/internal/event"
	"ior/internal/types"
)

func MatchPair(filter Filter, pair *event.Pair) bool {
	return filter.MatchPair(pair)
}

type pairCandidate struct {
	pair *event.Pair
}

func (p pairCandidate) SyscallValue() string {
	if p.pair == nil || p.pair.EnterEv == nil {
		return ""
	}
	return p.pair.EnterEv.GetTraceId().Name()
}

func (p pairCandidate) CommValue() string {
	if p.pair == nil {
		return ""
	}
	return p.pair.Comm
}

func (p pairCandidate) FileValue() string {
	if p.pair == nil || p.pair.File == nil {
		return ""
	}
	return p.pair.File.Name()
}

func (p pairCandidate) PIDValue() uint32 {
	if p.pair == nil || p.pair.EnterEv == nil {
		return 0
	}
	return p.pair.EnterEv.GetPid()
}

func (p pairCandidate) TIDValue() uint32 {
	if p.pair == nil || p.pair.EnterEv == nil {
		return 0
	}
	return p.pair.EnterEv.GetTid()
}

func (p pairCandidate) FDValue() int32 {
	if p.pair == nil {
		return -1
	}
	fd, ok := p.pair.FileDescriptor()
	if !ok {
		return -1
	}
	return fd
}

func (p pairCandidate) LatencyValue() uint64 {
	if p.pair == nil {
		return 0
	}
	return p.pair.Duration
}

func (p pairCandidate) GapValue() uint64 {
	if p.pair == nil {
		return 0
	}
	return p.pair.DurationToPrev
}

func (p pairCandidate) BytesValue() uint64 {
	if p.pair == nil {
		return 0
	}
	return p.pair.Bytes
}

func (p pairCandidate) ReturnValue() int64 {
	if p.pair == nil {
		return 0
	}
	retEvent, ok := p.pair.ExitEv.(*types.RetEvent)
	if !ok {
		return 0
	}
	return retEvent.Ret
}

func (p pairCandidate) ErrorValue() bool {
	return p.ReturnValue() < 0
}
