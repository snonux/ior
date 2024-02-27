package internal

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"

	. "ioriotng/internal/generated/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

type openFile struct {
	fd   int32
	path string
}

func (o openFile) String() string {
	return fmt.Sprintf("(%d) %s", o.fd, o.path)
}

func binaryCompare(ev *OpenEnterEvent, raw []byte) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, *ev); err != nil {
		panic(err)
	}
	bytes := buf.Bytes()
	fmt.Println("bytes", bytes)
	fmt.Println("raw  ", raw)
}

type Event interface {
	String() string
	GetTid() uint32
}

func eventLoop(bpfModule *bpf.Module, ch <-chan []byte) {
	type Event interface {
		String() string
	}

	for raw := range ch {
		var ev Event
		switch EventType(raw[0]) {
		case ENTER_OPEN_EVENT:
			ev = NewOpenEnterEvent(raw)
		case EXIT_OPEN_EVENT:
			ev = NewFdEvent(raw)
		case ENTER_FD_EVENT:
			ev = NewFdEvent(raw)
		case EXIT_FD_EVENT:
			ev = NewFdEvent(raw)
		case ENTER_NULL_EVENT:
			ev = NewNullEvent(raw)
		case EXIT_NULL_EVENT:
			ev = NewNullEvent(raw)
		case EXIT_RET_EVENT:
			ev = NewRetEvent(raw)
		default:
			panic("Unknown event type")
		}
		fmt.Println(ev)
	}

	fmt.Println("Good bye")
}
