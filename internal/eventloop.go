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
		switch SyscallId(raw[0]) {
		case SYS_ENTER_OPENAT:
			fallthrough
		case SYS_ENTER_OPEN:
			ev := NewOpenEnterEvent(raw)
			enterOpen[ev.Tid] = ev

		case SYS_EXIT_OPENAT:
			fallthrough
		case SYS_EXIT_OPEN:
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
			duration := ev.Time - enterEv.Time
			fmt.Println(duration, "μs", "closed", file)

			delete(enterOpen, ev.Tid)
			ev.Recycle()
			enterEv.Recycle()

		case SYS_ENTER_CLOSE:
			fallthrough
		case SYS_ENTER_WRITE:
			ev := NewFdEvent(raw)
			if _, ok := openFdMap[ev.Fd]; !ok {
				// File open not traced (todo: read from procfs?)
				ev.Recycle()
				continue
			}
			enterFd[ev.Tid] = ev

		case SYS_EXIT_CLOSE:
			ev := NewNullEvent(raw)
			enterEv, ok := enterFd[ev.Tid]
			if !ok {
				ev.Recycle()
				continue
			}
			duration := ev.Time - enterEv.Time
			file, _ := openFdMap[enterEv.Fd]
			fmt.Println(duration, "μs", "closed", file)

			delete(openFdMap, enterEv.Fd)
			delete(enterFd, ev.Tid)
			ev.Recycle()
			enterEv.Recycle()

		case SYS_EXIT_WRITE:
			ev := NewRetEvent(raw)
			enterEv, ok := enterFd[ev.Tid]
			if !ok {
				ev.Recycle()
				continue
			}
			duration := ev.Time - enterEv.Time
			if file, ok := openFdMap[enterEv.Fd]; ok {
				fmt.Println(duration, "μs", "retval", ev.Ret, file)
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
