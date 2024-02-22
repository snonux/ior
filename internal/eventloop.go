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

func eventLoop(bpfModule *bpf.Module, ch <-chan []byte) {
	enterOpen := make(map[uint32]*OpenEnterEvent)
	enterFd := make(map[uint32]*FdEvent)

	openFdMap := make(map[int32]openFile)

	for raw := range ch {
		switch OpId(raw[0]) {
		case OPENAT_ENTER_OP_ID:
			fallthrough
		case OPEN_ENTER_OP_ID:
			ev := NewOpenEnterEvent(raw)
			enterOpen[ev.Tid] = ev

		case OPENAT_EXIT_OP_ID:
			fallthrough
		case OPEN_EXIT_OP_ID:
			ev := NewFdEvent(raw)
			enterEv, ok := enterOpen[ev.Tid]
			if !ok {
				ev.Recycle()
				continue
			}
			file := openFile{
				fd:   ev.Fd,
				path: string(enterEv.Filename[:]),
			}
			openFdMap[ev.Fd] = file
			duration := float64(ev.Time-enterEv.Time) / float64(1_000_000)
			fmt.Println(duration, "ms", "opened", file)

			delete(enterOpen, ev.Tid)
			ev.Recycle()
			enterEv.Recycle()

		case CLOSE_ENTER_OP_ID:
			fallthrough
		case WRITE_ENTER_OP_ID:
			fallthrough
		case WRITEV_ENTER_OP_ID:
			ev := NewFdEvent(raw)
			if _, ok := openFdMap[ev.Fd]; !ok {
				// File open not traced (todo: read from procfs?)
				ev.Recycle()
				continue
			}
			enterFd[ev.Tid] = ev

		case CLOSE_EXIT_OP_ID:
			ev := NewNullEvent(raw)
			enterEv, ok := enterFd[ev.Tid]
			if !ok {
				ev.Recycle()
				continue
			}
			duration := float64(ev.Time-enterEv.Time) / float64(1_000_000)
			file, _ := openFdMap[enterEv.Fd]
			fmt.Println(duration, "ms", "closed", file)

			delete(openFdMap, enterEv.Fd)
			delete(enterFd, ev.Tid)
			ev.Recycle()
			enterEv.Recycle()

		case WRITE_EXIT_OP_ID:
			fallthrough
		case WRITEV_EXIT_OP_ID:
			ev := NewNullEvent(raw)
			enterEv, ok := enterFd[ev.Tid]
			if !ok {
				ev.Recycle()
				continue
			}
			duration := float64(ev.Time-enterEv.Time) / float64(1_000_000)
			if file, ok := openFdMap[enterEv.Fd]; ok {
				fmt.Println(duration, "ms", "wrote", file)
			}

			delete(enterFd, ev.Tid)
			ev.Recycle()
			enterEv.Recycle()

		default:
			panic(fmt.Sprintf("UNKNOWN Ringbuf data received len:%d raw:%v", len(raw), raw))
		}
	}

	fmt.Println("Good bye")
}
