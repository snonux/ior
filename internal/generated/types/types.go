// This file was generated - don't change manually!
package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

type EventType uint32
type SyscallId uint32

func (s SyscallId) String() string {
	switch s {
	case SYS_EXIT_CACHESTAT:
		return "exit_cachestat"
	case SYS_ENTER_CACHESTAT:
		return "enter_cachestat"
	case SYS_EXIT_CLOSE_RANGE:
		return "exit_close_range"
	case SYS_ENTER_CLOSE_RANGE:
		return "enter_close_range"
	case SYS_EXIT_CLOSE:
		return "exit_close"
	case SYS_ENTER_CLOSE:
		return "enter_close"
	case SYS_EXIT_FCHOWN:
		return "exit_fchown"
	case SYS_ENTER_FCHOWN:
		return "enter_fchown"
	case SYS_EXIT_FCHMOD:
		return "exit_fchmod"
	case SYS_ENTER_FCHMOD:
		return "enter_fchmod"
	case SYS_EXIT_FCHDIR:
		return "exit_fchdir"
	case SYS_ENTER_FCHDIR:
		return "enter_fchdir"
	case SYS_EXIT_FTRUNCATE:
		return "exit_ftruncate"
	case SYS_ENTER_FTRUNCATE:
		return "enter_ftruncate"
	case SYS_EXIT_COPY_FILE_RANGE:
		return "exit_copy_file_range"
	case SYS_ENTER_COPY_FILE_RANGE:
		return "enter_copy_file_range"
	case SYS_EXIT_PWRITE64:
		return "exit_pwrite64"
	case SYS_ENTER_PWRITE64:
		return "enter_pwrite64"
	case SYS_EXIT_PREAD64:
		return "exit_pread64"
	case SYS_ENTER_PREAD64:
		return "enter_pread64"
	case SYS_EXIT_WRITE:
		return "exit_write"
	case SYS_ENTER_WRITE:
		return "enter_write"
	case SYS_EXIT_READ:
		return "exit_read"
	case SYS_ENTER_READ:
		return "enter_read"
	case SYS_EXIT_LSEEK:
		return "exit_lseek"
	case SYS_ENTER_LSEEK:
		return "enter_lseek"
	case SYS_EXIT_NEWFSTAT:
		return "exit_newfstat"
	case SYS_ENTER_NEWFSTAT:
		return "enter_newfstat"
	case SYS_EXIT_FCNTL:
		return "exit_fcntl"
	case SYS_ENTER_FCNTL:
		return "enter_fcntl"
	case SYS_EXIT_IOCTL:
		return "exit_ioctl"
	case SYS_ENTER_IOCTL:
		return "enter_ioctl"
	case SYS_EXIT_GETDENTS64:
		return "exit_getdents64"
	case SYS_ENTER_GETDENTS64:
		return "enter_getdents64"
	case SYS_EXIT_GETDENTS:
		return "exit_getdents"
	case SYS_ENTER_GETDENTS:
		return "enter_getdents"
	case SYS_EXIT_SYNC_FILE_RANGE:
		return "exit_sync_file_range"
	case SYS_ENTER_SYNC_FILE_RANGE:
		return "enter_sync_file_range"
	case SYS_EXIT_FDATASYNC:
		return "exit_fdatasync"
	case SYS_ENTER_FDATASYNC:
		return "enter_fdatasync"
	case SYS_EXIT_FSYNC:
		return "exit_fsync"
	case SYS_ENTER_FSYNC:
		return "enter_fsync"
	case SYS_EXIT_FSTATFS:
		return "exit_fstatfs"
	case SYS_ENTER_FSTATFS:
		return "enter_fstatfs"
	case SYS_EXIT_FLOCK:
		return "exit_flock"
	case SYS_ENTER_FLOCK:
		return "enter_flock"
	case SYS_EXIT_QUOTACTL_FD:
		return "exit_quotactl_fd"
	case SYS_ENTER_QUOTACTL_FD:
		return "enter_quotactl_fd"
	case SYS_EXIT_IO_URING_REGISTER:
		return "exit_io_uring_register"
	case SYS_ENTER_IO_URING_REGISTER:
		return "enter_io_uring_register"
	case SYS_EXIT_IO_URING_ENTER:
		return "exit_io_uring_enter"
	case SYS_ENTER_IO_URING_ENTER:
		return "enter_io_uring_enter"
	case SYS_ENTER_OPEN:
		return "enter_open"
	case SYS_EXIT_OPEN:
		return "exit_open"
	case SYS_ENTER_OPENAT:
		return "enter_openat"
	case SYS_EXIT_OPENAT:
		return "exit_openat"
	default:
		panic(fmt.Sprintf("Unknown SyscallId: %d", s))
	}
}

const MAX_FILENAME_LENGTH = 256
const MAX_PROGNAME_LENGTH = 16
const ENTER_OPEN_EVENT = 1
const EXIT_OPEN_EVENT = 2
const ENTER_NULL_EVENT = 3
const EXIT_NULL_EVENT = 4
const ENTER_FD_EVENT = 5
const EXIT_FD_EVENT = 6
const ENTER_RET_EVENT = 7
const EXIT_RET_EVENT = 8

type OpenEnterEvent struct {
	EventType EventType
	SyscallId SyscallId
	Pid       uint32
	Tid       uint32
	Time      uint32
	Filename  [MAX_FILENAME_LENGTH]byte
	Comm      [MAX_PROGNAME_LENGTH]byte
}

func (o OpenEnterEvent) String() string {
	return fmt.Sprintf("EventType:%v SyscallId:%v Pid:%v Tid:%v Time:%v Filename:%v Comm:%v", o.EventType, o.SyscallId, o.Pid, o.Tid, o.Time, string(o.Filename[:]), string(o.Comm[:]))
}

func (o *OpenEnterEvent) TID() uint32 {
	return o.Tid
}

func (o *OpenEnterEvent) Timestamp() uint32 {
	return o.Time
}

var poolOfOpenEnterEvents = sync.Pool{
	New: func() interface{} { return &OpenEnterEvent{} },
}

func NewOpenEnterEvent(raw []byte) *OpenEnterEvent {
	o := poolOfOpenEnterEvents.Get().(*OpenEnterEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, o); err != nil {
		fmt.Println(o, raw, len(raw), err)
		panic(raw)
	}
	return o
}

func (o *OpenEnterEvent) Recycle() {
	poolOfOpenEnterEvents.Put(o)
}

type NullEvent struct {
	EventType EventType
	SyscallId SyscallId
	Pid       uint32
	Tid       uint32
	Time      uint32
}

func (n NullEvent) String() string {
	return fmt.Sprintf("EventType:%v SyscallId:%v Pid:%v Tid:%v Time:%v", n.EventType, n.SyscallId, n.Pid, n.Tid, n.Time)
}

func (n *NullEvent) TID() uint32 {
	return n.Tid
}

func (n *NullEvent) Timestamp() uint32 {
	return n.Time
}

var poolOfNullEvents = sync.Pool{
	New: func() interface{} { return &NullEvent{} },
}

func NewNullEvent(raw []byte) *NullEvent {
	n := poolOfNullEvents.Get().(*NullEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, n); err != nil {
		fmt.Println(n, raw, len(raw), err)
		panic(raw)
	}
	return n
}

func (n *NullEvent) Recycle() {
	poolOfNullEvents.Put(n)
}

type FdEvent struct {
	EventType EventType
	SyscallId SyscallId
	Pid       uint32
	Tid       uint32
	Time      uint32
	Fd        int32
}

func (f FdEvent) String() string {
	return fmt.Sprintf("EventType:%v SyscallId:%v Pid:%v Tid:%v Time:%v Fd:%v", f.EventType, f.SyscallId, f.Pid, f.Tid, f.Time, f.Fd)
}

func (f *FdEvent) TID() uint32 {
	return f.Tid
}

func (f *FdEvent) Timestamp() uint32 {
	return f.Time
}

var poolOfFdEvents = sync.Pool{
	New: func() interface{} { return &FdEvent{} },
}

func NewFdEvent(raw []byte) *FdEvent {
	f := poolOfFdEvents.Get().(*FdEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, f); err != nil {
		fmt.Println(f, raw, len(raw), err)
		panic(raw)
	}
	return f
}

func (f *FdEvent) Recycle() {
	poolOfFdEvents.Put(f)
}

type RetEvent struct {
	EventType EventType
	SyscallId SyscallId
	Pid       uint32
	Tid       uint32
	Ret       int64
	Time      uint32
}

func (r RetEvent) String() string {
	return fmt.Sprintf("EventType:%v SyscallId:%v Pid:%v Tid:%v Ret:%v Time:%v", r.EventType, r.SyscallId, r.Pid, r.Tid, r.Ret, r.Time)
}

func (r *RetEvent) TID() uint32 {
	return r.Tid
}

func (r *RetEvent) Timestamp() uint32 {
	return r.Time
}

var poolOfRetEvents = sync.Pool{
	New: func() interface{} { return &RetEvent{} },
}

func NewRetEvent(raw []byte) *RetEvent {
	r := poolOfRetEvents.Get().(*RetEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, r); err != nil {
		fmt.Println(r, raw, len(raw), err)
		panic(raw)
	}
	return r
}

func (r *RetEvent) Recycle() {
	poolOfRetEvents.Put(r)
}

const SYS_EXIT_CACHESTAT SyscallId = 520
const SYS_ENTER_CACHESTAT SyscallId = 521
const SYS_EXIT_CLOSE_RANGE SyscallId = 692
const SYS_ENTER_CLOSE_RANGE SyscallId = 693
const SYS_EXIT_CLOSE SyscallId = 694
const SYS_ENTER_CLOSE SyscallId = 695
const SYS_EXIT_FCHOWN SyscallId = 704
const SYS_ENTER_FCHOWN SyscallId = 705
const SYS_EXIT_FCHMOD SyscallId = 718
const SYS_ENTER_FCHMOD SyscallId = 719
const SYS_EXIT_FCHDIR SyscallId = 722
const SYS_ENTER_FCHDIR SyscallId = 723
const SYS_EXIT_FTRUNCATE SyscallId = 734
const SYS_ENTER_FTRUNCATE SyscallId = 735
const SYS_EXIT_COPY_FILE_RANGE SyscallId = 738
const SYS_ENTER_COPY_FILE_RANGE SyscallId = 739
const SYS_EXIT_PWRITE64 SyscallId = 754
const SYS_ENTER_PWRITE64 SyscallId = 755
const SYS_EXIT_PREAD64 SyscallId = 756
const SYS_ENTER_PREAD64 SyscallId = 757
const SYS_EXIT_WRITE SyscallId = 758
const SYS_ENTER_WRITE SyscallId = 759
const SYS_EXIT_READ SyscallId = 760
const SYS_ENTER_READ SyscallId = 761
const SYS_EXIT_LSEEK SyscallId = 762
const SYS_ENTER_LSEEK SyscallId = 763
const SYS_EXIT_NEWFSTAT SyscallId = 770
const SYS_ENTER_NEWFSTAT SyscallId = 771
const SYS_EXIT_FCNTL SyscallId = 814
const SYS_ENTER_FCNTL SyscallId = 815
const SYS_EXIT_IOCTL SyscallId = 816
const SYS_ENTER_IOCTL SyscallId = 817
const SYS_EXIT_GETDENTS64 SyscallId = 818
const SYS_ENTER_GETDENTS64 SyscallId = 819
const SYS_EXIT_GETDENTS SyscallId = 820
const SYS_ENTER_GETDENTS SyscallId = 821
const SYS_EXIT_SYNC_FILE_RANGE SyscallId = 914
const SYS_ENTER_SYNC_FILE_RANGE SyscallId = 915
const SYS_EXIT_FDATASYNC SyscallId = 916
const SYS_ENTER_FDATASYNC SyscallId = 917
const SYS_EXIT_FSYNC SyscallId = 918
const SYS_ENTER_FSYNC SyscallId = 919
const SYS_EXIT_FSTATFS SyscallId = 936
const SYS_ENTER_FSTATFS SyscallId = 937
const SYS_EXIT_FLOCK SyscallId = 1012
const SYS_ENTER_FLOCK SyscallId = 1013
const SYS_EXIT_QUOTACTL_FD SyscallId = 1043
const SYS_ENTER_QUOTACTL_FD SyscallId = 1044
const SYS_EXIT_IO_URING_REGISTER SyscallId = 1366
const SYS_ENTER_IO_URING_REGISTER SyscallId = 1367
const SYS_EXIT_IO_URING_ENTER SyscallId = 1370
const SYS_ENTER_IO_URING_ENTER SyscallId = 1371
const SYS_ENTER_OPEN SyscallId = 1
const SYS_EXIT_OPEN SyscallId = 2
const SYS_ENTER_OPENAT SyscallId = 3
const SYS_EXIT_OPENAT SyscallId = 4
