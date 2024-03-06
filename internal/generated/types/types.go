// Code generated - don't change manually!
package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

type EventType uint32
type TraceId uint32

func (s TraceId) String() string {
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
	case SYS_EXIT_RENAME:
		return "exit_rename"
	case SYS_ENTER_RENAME:
		return "enter_rename"
	case SYS_EXIT_RENAMEAT:
		return "exit_renameat"
	case SYS_ENTER_RENAMEAT:
		return "enter_renameat"
	case SYS_EXIT_RENAMEAT2:
		return "exit_renameat2"
	case SYS_ENTER_RENAMEAT2:
		return "enter_renameat2"
	case SYS_EXIT_LINK:
		return "exit_link"
	case SYS_ENTER_LINK:
		return "enter_link"
	case SYS_EXIT_LINKAT:
		return "exit_linkat"
	case SYS_ENTER_LINKAT:
		return "enter_linkat"
	case SYS_EXIT_SYMLINK:
		return "exit_symlink"
	case SYS_ENTER_SYMLINK:
		return "enter_symlink"
	case SYS_EXIT_SYMLINKAT:
		return "exit_symlinkat"
	case SYS_ENTER_SYMLINKAT:
		return "enter_symlinkat"
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
	case SYS_EXIT_OPEN:
		return "exit_open"
	case SYS_ENTER_OPEN:
		return "enter_open"
	case SYS_EXIT_OPENAT:
		return "exit_openat"
	case SYS_ENTER_OPENAT:
		return "enter_openat"
	default:
		panic(fmt.Sprintf("Unknown TraceId: %d", s))
	}
}

func (s TraceId) Name() string {
	switch s {
	case SYS_EXIT_CACHESTAT:
		return "cachestat"
	case SYS_ENTER_CACHESTAT:
		return "cachestat"
	case SYS_EXIT_CLOSE_RANGE:
		return "close_range"
	case SYS_ENTER_CLOSE_RANGE:
		return "close_range"
	case SYS_EXIT_CLOSE:
		return "close"
	case SYS_ENTER_CLOSE:
		return "close"
	case SYS_EXIT_FCHOWN:
		return "fchown"
	case SYS_ENTER_FCHOWN:
		return "fchown"
	case SYS_EXIT_FCHMOD:
		return "fchmod"
	case SYS_ENTER_FCHMOD:
		return "fchmod"
	case SYS_EXIT_FCHDIR:
		return "fchdir"
	case SYS_ENTER_FCHDIR:
		return "fchdir"
	case SYS_EXIT_FTRUNCATE:
		return "ftruncate"
	case SYS_ENTER_FTRUNCATE:
		return "ftruncate"
	case SYS_EXIT_COPY_FILE_RANGE:
		return "copy_file_range"
	case SYS_ENTER_COPY_FILE_RANGE:
		return "copy_file_range"
	case SYS_EXIT_PWRITE64:
		return "pwrite64"
	case SYS_ENTER_PWRITE64:
		return "pwrite64"
	case SYS_EXIT_PREAD64:
		return "pread64"
	case SYS_ENTER_PREAD64:
		return "pread64"
	case SYS_EXIT_WRITE:
		return "write"
	case SYS_ENTER_WRITE:
		return "write"
	case SYS_EXIT_READ:
		return "read"
	case SYS_ENTER_READ:
		return "read"
	case SYS_EXIT_LSEEK:
		return "lseek"
	case SYS_ENTER_LSEEK:
		return "lseek"
	case SYS_EXIT_NEWFSTAT:
		return "newfstat"
	case SYS_ENTER_NEWFSTAT:
		return "newfstat"
	case SYS_EXIT_RENAME:
		return "rename"
	case SYS_ENTER_RENAME:
		return "rename"
	case SYS_EXIT_RENAMEAT:
		return "renameat"
	case SYS_ENTER_RENAMEAT:
		return "renameat"
	case SYS_EXIT_RENAMEAT2:
		return "renameat2"
	case SYS_ENTER_RENAMEAT2:
		return "renameat2"
	case SYS_EXIT_LINK:
		return "link"
	case SYS_ENTER_LINK:
		return "link"
	case SYS_EXIT_LINKAT:
		return "linkat"
	case SYS_ENTER_LINKAT:
		return "linkat"
	case SYS_EXIT_SYMLINK:
		return "symlink"
	case SYS_ENTER_SYMLINK:
		return "symlink"
	case SYS_EXIT_SYMLINKAT:
		return "symlinkat"
	case SYS_ENTER_SYMLINKAT:
		return "symlinkat"
	case SYS_EXIT_FCNTL:
		return "fcntl"
	case SYS_ENTER_FCNTL:
		return "fcntl"
	case SYS_EXIT_IOCTL:
		return "ioctl"
	case SYS_ENTER_IOCTL:
		return "ioctl"
	case SYS_EXIT_GETDENTS64:
		return "getdents64"
	case SYS_ENTER_GETDENTS64:
		return "getdents64"
	case SYS_EXIT_GETDENTS:
		return "getdents"
	case SYS_ENTER_GETDENTS:
		return "getdents"
	case SYS_EXIT_SYNC_FILE_RANGE:
		return "sync_file_range"
	case SYS_ENTER_SYNC_FILE_RANGE:
		return "sync_file_range"
	case SYS_EXIT_FDATASYNC:
		return "fdatasync"
	case SYS_ENTER_FDATASYNC:
		return "fdatasync"
	case SYS_EXIT_FSYNC:
		return "fsync"
	case SYS_ENTER_FSYNC:
		return "fsync"
	case SYS_EXIT_FSTATFS:
		return "fstatfs"
	case SYS_ENTER_FSTATFS:
		return "fstatfs"
	case SYS_EXIT_FLOCK:
		return "flock"
	case SYS_ENTER_FLOCK:
		return "flock"
	case SYS_EXIT_QUOTACTL_FD:
		return "quotactl_fd"
	case SYS_ENTER_QUOTACTL_FD:
		return "quotactl_fd"
	case SYS_EXIT_IO_URING_REGISTER:
		return "io_uring_register"
	case SYS_ENTER_IO_URING_REGISTER:
		return "io_uring_register"
	case SYS_EXIT_IO_URING_ENTER:
		return "io_uring_enter"
	case SYS_ENTER_IO_URING_ENTER:
		return "io_uring_enter"
	case SYS_EXIT_OPEN:
		return "open"
	case SYS_ENTER_OPEN:
		return "open"
	case SYS_EXIT_OPENAT:
		return "openat"
	case SYS_ENTER_OPENAT:
		return "openat"
	default:
		panic(fmt.Sprintf("Unknown TraceId: %d", s))
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
const ENTER_NAME_EVENT = 9
const EXIT_NAME_EVENT = 10

type OpenEvent struct {
	EventType EventType
	TraceId   TraceId
	Pid       uint32
	Tid       uint32
	Time      uint32
	Filename  [MAX_FILENAME_LENGTH]byte
	Comm      [MAX_PROGNAME_LENGTH]byte
}

func (o OpenEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Pid:%v Tid:%v Time:%v Filename:%v Comm:%v", o.EventType, o.TraceId, o.Pid, o.Tid, o.Time, string(o.Filename[:]), string(o.Comm[:]))
}

func (o *OpenEvent) GetEventType() EventType {
	return o.EventType
}

func (o *OpenEvent) GetTraceId() TraceId {
	return o.TraceId
}

func (o *OpenEvent) GetPid() uint32 {
	return o.Pid
}

func (o *OpenEvent) GetTid() uint32 {
	return o.Tid
}

func (o *OpenEvent) GetTime() uint32 {
	return o.Time
}

var poolOfOpenEvents = sync.Pool{
	New: func() interface{} { return &OpenEvent{} },
}

func NewOpenEvent(raw []byte) *OpenEvent {
	o := poolOfOpenEvents.Get().(*OpenEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, o); err != nil {
		fmt.Println(o, raw, len(raw), err)
		panic(raw)
	}
	return o
}

func (o *OpenEvent) Recycle() {
	poolOfOpenEvents.Put(o)
}

type NullEvent struct {
	EventType EventType
	TraceId   TraceId
	Pid       uint32
	Tid       uint32
	Time      uint32
}

func (n NullEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Pid:%v Tid:%v Time:%v", n.EventType, n.TraceId, n.Pid, n.Tid, n.Time)
}

func (n *NullEvent) GetEventType() EventType {
	return n.EventType
}

func (n *NullEvent) GetTraceId() TraceId {
	return n.TraceId
}

func (n *NullEvent) GetPid() uint32 {
	return n.Pid
}

func (n *NullEvent) GetTid() uint32 {
	return n.Tid
}

func (n *NullEvent) GetTime() uint32 {
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
	TraceId   TraceId
	Pid       uint32
	Tid       uint32
	Time      uint32
	Fd        int32
}

func (f FdEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Pid:%v Tid:%v Time:%v Fd:%v", f.EventType, f.TraceId, f.Pid, f.Tid, f.Time, f.Fd)
}

func (f *FdEvent) GetEventType() EventType {
	return f.EventType
}

func (f *FdEvent) GetTraceId() TraceId {
	return f.TraceId
}

func (f *FdEvent) GetPid() uint32 {
	return f.Pid
}

func (f *FdEvent) GetTid() uint32 {
	return f.Tid
}

func (f *FdEvent) GetTime() uint32 {
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
	TraceId   TraceId
	Pid       uint32
	Tid       uint32
	Ret       int64
	Time      uint32
}

func (r RetEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Pid:%v Tid:%v Ret:%v Time:%v", r.EventType, r.TraceId, r.Pid, r.Tid, r.Ret, r.Time)
}

func (r *RetEvent) GetEventType() EventType {
	return r.EventType
}

func (r *RetEvent) GetTraceId() TraceId {
	return r.TraceId
}

func (r *RetEvent) GetPid() uint32 {
	return r.Pid
}

func (r *RetEvent) GetTid() uint32 {
	return r.Tid
}

func (r *RetEvent) GetTime() uint32 {
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

type NameEvent struct {
	EventType EventType
	TraceId   TraceId
	Pid       uint32
	Tid       uint32
	Time      uint32
	Oldname   [MAX_FILENAME_LENGTH]byte
	Newname   [MAX_FILENAME_LENGTH]byte
}

func (n NameEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Pid:%v Tid:%v Time:%v Oldname:%v Newname:%v", n.EventType, n.TraceId, n.Pid, n.Tid, n.Time, string(n.Oldname[:]), string(n.Newname[:]))
}

func (n *NameEvent) GetEventType() EventType {
	return n.EventType
}

func (n *NameEvent) GetTraceId() TraceId {
	return n.TraceId
}

func (n *NameEvent) GetPid() uint32 {
	return n.Pid
}

func (n *NameEvent) GetTid() uint32 {
	return n.Tid
}

func (n *NameEvent) GetTime() uint32 {
	return n.Time
}

var poolOfNameEvents = sync.Pool{
	New: func() interface{} { return &NameEvent{} },
}

func NewNameEvent(raw []byte) *NameEvent {
	n := poolOfNameEvents.Get().(*NameEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, n); err != nil {
		fmt.Println(n, raw, len(raw), err)
		panic(raw)
	}
	return n
}

func (n *NameEvent) Recycle() {
	poolOfNameEvents.Put(n)
}

const SYS_EXIT_CACHESTAT TraceId = 527
const SYS_ENTER_CACHESTAT TraceId = 528
const SYS_EXIT_CLOSE_RANGE TraceId = 700
const SYS_ENTER_CLOSE_RANGE TraceId = 701
const SYS_EXIT_CLOSE TraceId = 702
const SYS_ENTER_CLOSE TraceId = 703
const SYS_EXIT_FCHOWN TraceId = 712
const SYS_ENTER_FCHOWN TraceId = 713
const SYS_EXIT_FCHMOD TraceId = 726
const SYS_ENTER_FCHMOD TraceId = 727
const SYS_EXIT_FCHDIR TraceId = 730
const SYS_ENTER_FCHDIR TraceId = 731
const SYS_EXIT_FTRUNCATE TraceId = 742
const SYS_ENTER_FTRUNCATE TraceId = 743
const SYS_EXIT_COPY_FILE_RANGE TraceId = 746
const SYS_ENTER_COPY_FILE_RANGE TraceId = 747
const SYS_EXIT_PWRITE64 TraceId = 762
const SYS_ENTER_PWRITE64 TraceId = 763
const SYS_EXIT_PREAD64 TraceId = 764
const SYS_ENTER_PREAD64 TraceId = 765
const SYS_EXIT_WRITE TraceId = 766
const SYS_ENTER_WRITE TraceId = 767
const SYS_EXIT_READ TraceId = 768
const SYS_ENTER_READ TraceId = 769
const SYS_EXIT_LSEEK TraceId = 770
const SYS_ENTER_LSEEK TraceId = 771
const SYS_EXIT_NEWFSTAT TraceId = 778
const SYS_ENTER_NEWFSTAT TraceId = 779
const SYS_EXIT_RENAME TraceId = 794
const SYS_ENTER_RENAME TraceId = 795
const SYS_EXIT_RENAMEAT TraceId = 796
const SYS_ENTER_RENAMEAT TraceId = 797
const SYS_EXIT_RENAMEAT2 TraceId = 798
const SYS_ENTER_RENAMEAT2 TraceId = 799
const SYS_EXIT_LINK TraceId = 800
const SYS_ENTER_LINK TraceId = 801
const SYS_EXIT_LINKAT TraceId = 802
const SYS_ENTER_LINKAT TraceId = 803
const SYS_EXIT_SYMLINK TraceId = 804
const SYS_ENTER_SYMLINK TraceId = 805
const SYS_EXIT_SYMLINKAT TraceId = 806
const SYS_ENTER_SYMLINKAT TraceId = 807
const SYS_EXIT_FCNTL TraceId = 822
const SYS_ENTER_FCNTL TraceId = 823
const SYS_EXIT_IOCTL TraceId = 824
const SYS_ENTER_IOCTL TraceId = 825
const SYS_EXIT_GETDENTS64 TraceId = 826
const SYS_ENTER_GETDENTS64 TraceId = 827
const SYS_EXIT_GETDENTS TraceId = 828
const SYS_ENTER_GETDENTS TraceId = 829
const SYS_EXIT_SYNC_FILE_RANGE TraceId = 922
const SYS_ENTER_SYNC_FILE_RANGE TraceId = 923
const SYS_EXIT_FDATASYNC TraceId = 924
const SYS_ENTER_FDATASYNC TraceId = 925
const SYS_EXIT_FSYNC TraceId = 926
const SYS_ENTER_FSYNC TraceId = 927
const SYS_EXIT_FSTATFS TraceId = 944
const SYS_ENTER_FSTATFS TraceId = 945
const SYS_EXIT_FLOCK TraceId = 1020
const SYS_ENTER_FLOCK TraceId = 1021
const SYS_EXIT_QUOTACTL_FD TraceId = 1051
const SYS_ENTER_QUOTACTL_FD TraceId = 1052
const SYS_EXIT_IO_URING_REGISTER TraceId = 1377
const SYS_ENTER_IO_URING_REGISTER TraceId = 1378
const SYS_EXIT_IO_URING_ENTER TraceId = 1381
const SYS_ENTER_IO_URING_ENTER TraceId = 1382
const SYS_EXIT_OPEN TraceId = 1
const SYS_ENTER_OPEN TraceId = 2
const SYS_EXIT_OPENAT TraceId = 3
const SYS_ENTER_OPENAT TraceId = 4
