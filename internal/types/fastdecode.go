package types

import "encoding/binary"

const (
	openEventSize           = 300
	nullEventSize           = 24
	fdEventSize             = 28
	retEventSize            = 36
	nameEventSize           = 536
	pathEventSize           = 280
	fcntlEventSize          = 40
	dup3EventSize           = 32
	openByHandleAtEventSize = 28
)

func NewOpenEventFast(raw []byte) *OpenEvent {
	if len(raw) != openEventSize {
		return NewOpenEvent(raw)
	}
	o := poolOfOpenEvents.Get().(*OpenEvent)
	o.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	o.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	o.Time = binary.LittleEndian.Uint64(raw[8:16])
	o.Pid = binary.LittleEndian.Uint32(raw[16:20])
	o.Tid = binary.LittleEndian.Uint32(raw[20:24])
	o.Flags = int32(binary.LittleEndian.Uint32(raw[24:28]))
	copy(o.Filename[:], raw[28:284])
	copy(o.Comm[:], raw[284:300])
	return o
}

func NewNullEventFast(raw []byte) *NullEvent {
	if len(raw) != nullEventSize {
		return NewNullEvent(raw)
	}
	n := poolOfNullEvents.Get().(*NullEvent)
	n.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	n.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	n.Time = binary.LittleEndian.Uint64(raw[8:16])
	n.Pid = binary.LittleEndian.Uint32(raw[16:20])
	n.Tid = binary.LittleEndian.Uint32(raw[20:24])
	return n
}

func NewFdEventFast(raw []byte) *FdEvent {
	if len(raw) != fdEventSize {
		return NewFdEvent(raw)
	}
	f := poolOfFdEvents.Get().(*FdEvent)
	f.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	f.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	f.Time = binary.LittleEndian.Uint64(raw[8:16])
	f.Pid = binary.LittleEndian.Uint32(raw[16:20])
	f.Tid = binary.LittleEndian.Uint32(raw[20:24])
	f.Fd = int32(binary.LittleEndian.Uint32(raw[24:28]))
	return f
}

func NewRetEventFast(raw []byte) *RetEvent {
	if len(raw) != retEventSize {
		return NewRetEvent(raw)
	}
	r := poolOfRetEvents.Get().(*RetEvent)
	r.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	r.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	r.Time = binary.LittleEndian.Uint64(raw[8:16])
	r.Ret = int64(binary.LittleEndian.Uint64(raw[16:24]))
	r.Pid = binary.LittleEndian.Uint32(raw[24:28])
	r.Tid = binary.LittleEndian.Uint32(raw[28:32])
	r.RetType = binary.LittleEndian.Uint32(raw[32:36])
	return r
}

func NewNameEventFast(raw []byte) *NameEvent {
	if len(raw) != nameEventSize {
		return NewNameEvent(raw)
	}
	n := poolOfNameEvents.Get().(*NameEvent)
	n.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	n.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	n.Time = binary.LittleEndian.Uint64(raw[8:16])
	n.Pid = binary.LittleEndian.Uint32(raw[16:20])
	n.Tid = binary.LittleEndian.Uint32(raw[20:24])
	copy(n.Oldname[:], raw[24:280])
	copy(n.Newname[:], raw[280:536])
	return n
}

func NewPathEventFast(raw []byte) *PathEvent {
	if len(raw) != pathEventSize {
		return NewPathEvent(raw)
	}
	p := poolOfPathEvents.Get().(*PathEvent)
	p.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	p.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	p.Time = binary.LittleEndian.Uint64(raw[8:16])
	p.Pid = binary.LittleEndian.Uint32(raw[16:20])
	p.Tid = binary.LittleEndian.Uint32(raw[20:24])
	copy(p.Pathname[:], raw[24:280])
	return p
}

func NewFcntlEventFast(raw []byte) *FcntlEvent {
	if len(raw) != fcntlEventSize {
		return NewFcntlEvent(raw)
	}
	f := poolOfFcntlEvents.Get().(*FcntlEvent)
	f.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	f.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	f.Time = binary.LittleEndian.Uint64(raw[8:16])
	f.Pid = binary.LittleEndian.Uint32(raw[16:20])
	f.Tid = binary.LittleEndian.Uint32(raw[20:24])
	f.Fd = binary.LittleEndian.Uint32(raw[24:28])
	f.Cmd = binary.LittleEndian.Uint32(raw[28:32])
	f.Arg = binary.LittleEndian.Uint64(raw[32:40])
	return f
}

func NewDup3EventFast(raw []byte) *Dup3Event {
	if len(raw) != dup3EventSize {
		return NewDup3Event(raw)
	}
	d := poolOfDup3Events.Get().(*Dup3Event)
	d.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	d.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	d.Time = binary.LittleEndian.Uint64(raw[8:16])
	d.Pid = binary.LittleEndian.Uint32(raw[16:20])
	d.Tid = binary.LittleEndian.Uint32(raw[20:24])
	d.Fd = int32(binary.LittleEndian.Uint32(raw[24:28]))
	d.Flags = int32(binary.LittleEndian.Uint32(raw[28:32]))
	return d
}

func NewOpenByHandleAtEventFast(raw []byte) *OpenByHandleAtEvent {
	if len(raw) != openByHandleAtEventSize {
		return NewOpenByHandleAtEvent(raw)
	}
	o := poolOfOpenByHandleAtEvents.Get().(*OpenByHandleAtEvent)
	o.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	o.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	o.Time = binary.LittleEndian.Uint64(raw[8:16])
	o.Pid = binary.LittleEndian.Uint32(raw[16:20])
	o.Tid = binary.LittleEndian.Uint32(raw[20:24])
	o.Flags = int32(binary.LittleEndian.Uint32(raw[24:28]))
	return o
}
