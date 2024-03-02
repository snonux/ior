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
		panic(fmt.Sprintf("Unknown SyscallId: %d", s))
	}
}

func (s SyscallId) Name() string {
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
const ENTER_NAME_EVENT = 9
const EXIT_NAME_EVENT = 10

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

func (o *OpenEnterEvent) GetEventType() EventType {
	return o.EventType
}

func (o *OpenEnterEvent) GetSyscallId() SyscallId {
	return o.SyscallId
}

func (o *OpenEnterEvent) GetPid() uint32 {
	return o.Pid
}

func (o *OpenEnterEvent) GetTid() uint32 {
	return o.Tid
}

func (o *OpenEnterEvent) GetTime() uint32 {
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

func (n *NullEvent) GetEventType() EventType {
	return n.EventType
}

func (n *NullEvent) GetSyscallId() SyscallId {
	return n.SyscallId
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
	SyscallId SyscallId
	Pid       uint32
	Tid       uint32
	Time      uint32
	Fd        int32
}

func (f FdEvent) String() string {
	return fmt.Sprintf("EventType:%v SyscallId:%v Pid:%v Tid:%v Time:%v Fd:%v", f.EventType, f.SyscallId, f.Pid, f.Tid, f.Time, f.Fd)
}

func (f *FdEvent) GetEventType() EventType {
	return f.EventType
}

func (f *FdEvent) GetSyscallId() SyscallId {
	return f.SyscallId
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
	SyscallId SyscallId
	Pid       uint32
	Tid       uint32
	Ret       int64
	Time      uint32
}

func (r RetEvent) String() string {
	return fmt.Sprintf("EventType:%v SyscallId:%v Pid:%v Tid:%v Ret:%v Time:%v", r.EventType, r.SyscallId, r.Pid, r.Tid, r.Ret, r.Time)
}

func (r *RetEvent) GetEventType() EventType {
	return r.EventType
}

func (r *RetEvent) GetSyscallId() SyscallId {
	return r.SyscallId
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
	SyscallId SyscallId
	Pid       uint32
	Tid       uint32
	Time      uint32
	Oldname   [MAX_FILENAME_LENGTH]byte
	Newname   [MAX_FILENAME_LENGTH]byte
}

func (n NameEvent) String() string {
	return fmt.Sprintf("EventType:%v SyscallId:%v Pid:%v Tid:%v Time:%v Oldname:%v Newname:%v", n.EventType, n.SyscallId, n.Pid, n.Tid, n.Time, string(n.Oldname[:]), string(n.Newname[:]))
}

func (n *NameEvent) GetEventType() EventType {
	return n.EventType
}

func (n *NameEvent) GetSyscallId() SyscallId {
	return n.SyscallId
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
const SYS_EXIT_RENAME SyscallId = 786
const SYS_ENTER_RENAME SyscallId = 787
const SYS_EXIT_RENAMEAT SyscallId = 788
const SYS_ENTER_RENAMEAT SyscallId = 789
const SYS_EXIT_RENAMEAT2 SyscallId = 790
const SYS_ENTER_RENAMEAT2 SyscallId = 791
const SYS_EXIT_LINK SyscallId = 792
const SYS_ENTER_LINK SyscallId = 793
const SYS_EXIT_LINKAT SyscallId = 794
const SYS_ENTER_LINKAT SyscallId = 795
const SYS_EXIT_SYMLINK SyscallId = 796
const SYS_ENTER_SYMLINK SyscallId = 797
const SYS_EXIT_SYMLINKAT SyscallId = 798
const SYS_ENTER_SYMLINKAT SyscallId = 799
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
const SYS_EXIT_OPEN SyscallId = 1
const SYS_ENTER_OPEN SyscallId = 2
const SYS_EXIT_OPENAT SyscallId = 3
const SYS_ENTER_OPENAT SyscallId = 4
