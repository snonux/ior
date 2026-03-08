package benchutil

import (
	"fmt"
	"math/rand"
	"syscall"

	"ior/internal/types"
)

const (
	defaultMixSeed    int64  = 1
	defaultStreamTime uint64 = 1
	defaultBasePid    uint32 = 1000
	defaultBaseTid    uint32 = 2000
	defaultBaseFd     int32  = 64
)

type MixEvent uint8

const (
	MixRead MixEvent = iota + 1
	MixWrite
	MixOpen
	MixClose
	MixStat
	MixSync
	MixFsync
	MixAccess
	MixMkdir
	MixUnlink
	MixRename
	MixLink
	MixFcntl
	MixDup3
	MixOpenByHandleAt
)

type MixEntry struct {
	Event  MixEvent
	Weight int
}

type EventMix struct {
	Entries []MixEntry
	Seed    int64
}

var ReadHeavy = EventMix{
	Entries: []MixEntry{
		{Event: MixRead, Weight: 30},
		{Event: MixWrite, Weight: 30},
		{Event: MixOpen, Weight: 10},
		{Event: MixClose, Weight: 10},
		{Event: MixStat, Weight: 10},
		{Event: MixSync, Weight: 10},
	},
	Seed: defaultMixSeed,
}

var WriteHeavy = EventMix{
	Entries: []MixEntry{
		{Event: MixWrite, Weight: 40},
		{Event: MixFsync, Weight: 20},
		{Event: MixRead, Weight: 15},
		{Event: MixOpen, Weight: 5},
		{Event: MixClose, Weight: 5},
		{Event: MixStat, Weight: 15},
	},
	Seed: defaultMixSeed,
}

var MetadataHeavy = EventMix{
	Entries: []MixEntry{
		{Event: MixStat, Weight: 15},
		{Event: MixAccess, Weight: 15},
		{Event: MixOpen, Weight: 12},
		{Event: MixClose, Weight: 13},
		{Event: MixMkdir, Weight: 10},
		{Event: MixUnlink, Weight: 10},
		{Event: MixRename, Weight: 8},
		{Event: MixLink, Weight: 7},
		{Event: MixRead, Weight: 5},
		{Event: MixWrite, Weight: 5},
	},
	Seed: defaultMixSeed,
}

var DiverseAllTypes = EventMix{
	Entries: []MixEntry{
		{Event: MixOpen, Weight: 1},
		{Event: MixRead, Weight: 1},
		{Event: MixSync, Weight: 1},
		{Event: MixStat, Weight: 1},
		{Event: MixRename, Weight: 1},
		{Event: MixFcntl, Weight: 1},
		{Event: MixDup3, Weight: 1},
		{Event: MixOpenByHandleAt, Weight: 1},
		{Event: MixClose, Weight: 1},
	},
	Seed: defaultMixSeed,
}

func (m EventMix) GenerateStream(gen EventGenerator, n, numThreads int) ([][]byte, error) {
	if n <= 0 {
		return nil, nil
	}

	threadCount := numThreads
	if threadCount < 1 {
		threadCount = 1
	}

	entries := m.activeEntries()
	totalWeight := sumWeights(entries)
	rng := rand.New(rand.NewSource(m.seed()))

	stream := make([][]byte, 0, n*2)
	nextTime := defaultStreamTime
	for i := 0; i < n; i++ {
		threadIdx := i % threadCount
		pid := defaultBasePid + uint32(threadIdx)
		tid := defaultBaseTid + uint32(threadIdx)
		fd := fdFor(threadIdx, i)
		event := choose(entries, totalWeight, rng)
		enter, exit, err := event.pair(gen, nextTime, pid, tid, fd, i)
		if err != nil {
			return nil, fmt.Errorf("generate event %v pair: %w", event, err)
		}
		stream = append(stream, enter, exit)
		nextTime += gen.pairDelta() + 1
	}

	return stream, nil
}

func choose(entries []MixEntry, totalWeight int, rng *rand.Rand) MixEvent {
	if totalWeight <= 0 {
		return MixRead
	}

	roll := rng.Intn(totalWeight)
	for _, entry := range entries {
		if entry.Weight <= 0 {
			continue
		}
		if roll < entry.Weight {
			return entry.Event
		}
		roll -= entry.Weight
	}
	return entries[len(entries)-1].Event
}

func fdFor(threadIdx, seq int) int32 {
	return defaultBaseFd + int32(threadIdx*100+seq%100)
}

func (m EventMix) activeEntries() []MixEntry {
	active := make([]MixEntry, 0, len(m.Entries))
	for _, entry := range m.Entries {
		if entry.Weight > 0 {
			active = append(active, entry)
		}
	}
	if len(active) == 0 {
		return DiverseAllTypes.Entries
	}
	return active
}

func (m EventMix) seed() int64 {
	if m.Seed == 0 {
		return defaultMixSeed
	}
	return m.Seed
}

func sumWeights(entries []MixEntry) int {
	total := 0
	for _, entry := range entries {
		total += entry.Weight
	}
	return total
}

func (e MixEvent) pair(gen EventGenerator, time uint64, pid, tid uint32, fd int32, seq int) ([]byte, []byte, error) {
	switch e {
	case MixRead:
		return gen.FdPair(time, pid, tid, fd, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 128)
	case MixWrite:
		return gen.FdPair(time, pid, tid, fd, types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE, 256)
	case MixOpen:
		return gen.OpenPair(time, pid, tid)
	case MixClose:
		_, enter, err := gen.EnterFdEvent(time, pid, tid, fd, types.SYS_ENTER_CLOSE)
		if err != nil {
			return nil, nil, err
		}
		_, exit, err := gen.ExitFdEvent(time+gen.pairDelta(), pid, tid, fd, types.SYS_EXIT_CLOSE)
		if err != nil {
			return nil, nil, err
		}
		return enter, exit, nil
	case MixStat:
		path := fmt.Sprintf("/tmp/ior-stat-%d-%d", tid, seq)
		return gen.PathPair(time, pid, tid, path, types.SYS_ENTER_NEWSTAT, types.SYS_EXIT_NEWSTAT, 0)
	case MixSync:
		return gen.NullPair(time, pid, tid, types.SYS_ENTER_SYNC, types.SYS_EXIT_SYNC)
	case MixFsync:
		return gen.FdPair(time, pid, tid, fd, types.SYS_ENTER_FSYNC, types.SYS_EXIT_FSYNC, 0)
	case MixAccess:
		path := fmt.Sprintf("/tmp/ior-access-%d-%d", tid, seq)
		return gen.PathPair(time, pid, tid, path, types.SYS_ENTER_ACCESS, types.SYS_EXIT_ACCESS, 0)
	case MixMkdir:
		path := fmt.Sprintf("/tmp/ior-mkdir-%d-%d", tid, seq)
		return gen.PathPair(time, pid, tid, path, types.SYS_ENTER_MKDIR, types.SYS_EXIT_MKDIR, 0)
	case MixUnlink:
		path := fmt.Sprintf("/tmp/ior-unlink-%d-%d", tid, seq)
		return gen.PathPair(time, pid, tid, path, types.SYS_ENTER_UNLINK, types.SYS_EXIT_UNLINK, 0)
	case MixRename:
		oldname := fmt.Sprintf("/tmp/ior-old-%d-%d", tid, seq)
		newname := fmt.Sprintf("/tmp/ior-new-%d-%d", tid, seq)
		return gen.NamePair(time, pid, tid, oldname, newname, types.SYS_ENTER_RENAME, types.SYS_EXIT_RENAME, 0)
	case MixLink:
		oldname := fmt.Sprintf("/tmp/ior-link-old-%d-%d", tid, seq)
		newname := fmt.Sprintf("/tmp/ior-link-new-%d-%d", tid, seq)
		return gen.NamePair(time, pid, tid, oldname, newname, types.SYS_ENTER_LINK, types.SYS_EXIT_LINK, 0)
	case MixFcntl:
		return gen.FcntlPair(time, pid, tid, uint32(fd), syscall.F_SETFL, syscall.O_NONBLOCK, types.SYS_EXIT_FCNTL, 0)
	case MixDup3:
		return gen.Dup3Pair(time, pid, tid, fd, syscall.O_CLOEXEC, types.SYS_EXIT_DUP3, int64(fd+1))
	case MixOpenByHandleAt:
		_, enter, err := gen.EnterOpenByHandleAtEvent(time, pid, tid, syscall.O_RDWR)
		if err != nil {
			return nil, nil, err
		}
		_, exit, err := gen.ExitRetEvent(time+gen.pairDelta(), pid, tid, types.SYS_EXIT_OPEN_BY_HANDLE_AT, int64(fd))
		if err != nil {
			return nil, nil, err
		}
		return enter, exit, nil
	default:
		return gen.NullPair(time, pid, tid, types.SYS_ENTER_SYNC, types.SYS_EXIT_SYNC)
	}
}
