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

var traceId2String = map[TraceId]string{
	527: "exit_cachestat", 528: "enter_cachestat", 700: "exit_close_range", 701: "enter_close_range", 702: "exit_close", 703: "enter_close", 704: "exit_creat", 705: "enter_creat", 712: "exit_fchown", 713: "enter_fchown", 726: "exit_fchmod", 727: "enter_fchmod", 730: "exit_fchdir", 731: "enter_fchdir", 742: "exit_ftruncate", 743: "enter_ftruncate", 746: "exit_copy_file_range", 747: "enter_copy_file_range", 762: "exit_pwrite64", 763: "enter_pwrite64", 764: "exit_pread64", 765: "enter_pread64", 766: "exit_write", 767: "enter_write", 768: "exit_read", 769: "enter_read", 770: "exit_lseek", 771: "enter_lseek", 776: "exit_readlinkat", 777: "enter_readlinkat", 778: "exit_newfstat", 779: "enter_newfstat", 794: "exit_rename", 795: "enter_rename", 796: "exit_renameat", 797: "enter_renameat", 798: "exit_renameat2", 799: "enter_renameat2", 800: "exit_link", 801: "enter_link", 802: "exit_linkat", 803: "enter_linkat", 804: "exit_symlink", 805: "enter_symlink", 806: "exit_symlinkat", 807: "enter_symlinkat", 808: "exit_unlink", 809: "enter_unlink", 810: "exit_unlinkat", 811: "enter_unlinkat", 812: "exit_rmdir", 813: "enter_rmdir", 814: "exit_mkdir", 815: "enter_mkdir", 816: "exit_mkdirat", 817: "enter_mkdirat", 822: "exit_fcntl", 823: "enter_fcntl", 824: "exit_ioctl", 825: "enter_ioctl", 826: "exit_getdents64", 827: "enter_getdents64", 828: "exit_getdents", 829: "enter_getdents", 862: "exit_lremovexattr", 863: "enter_lremovexattr", 864: "exit_removexattr", 865: "enter_removexattr", 868: "exit_llistxattr", 869: "enter_llistxattr", 870: "exit_listxattr", 871: "enter_listxattr", 874: "exit_lgetxattr", 875: "enter_lgetxattr", 876: "exit_getxattr", 877: "enter_getxattr", 880: "exit_lsetxattr", 881: "enter_lsetxattr", 882: "exit_setxattr", 883: "enter_setxattr", 922: "exit_sync_file_range", 923: "enter_sync_file_range", 924: "exit_fdatasync", 925: "enter_fdatasync", 926: "exit_fsync", 927: "enter_fsync", 944: "exit_fstatfs", 945: "enter_fstatfs", 946: "exit_statfs", 947: "enter_statfs", 954: "exit_inotify_rm_watch", 955: "enter_inotify_rm_watch", 956: "exit_inotify_add_watch", 957: "enter_inotify_add_watch", 962: "exit_fanotify_mark", 963: "enter_fanotify_mark", 1020: "exit_flock", 1021: "enter_flock", 1051: "exit_quotactl_fd", 1052: "enter_quotactl_fd", 1321: "exit_mq_unlink", 1322: "enter_mq_unlink", 1377: "exit_io_uring_register", 1378: "enter_io_uring_register", 1381: "exit_io_uring_enter", 1382: "enter_io_uring_enter", 1: "exit_open", 2: "enter_open", 3: "exit_openat", 4: "enter_openat",
}

var traceId2Name = map[TraceId]string{
	527: "cachestat", 528: "cachestat", 700: "close_range", 701: "close_range", 702: "close", 703: "close", 704: "creat", 705: "creat", 712: "fchown", 713: "fchown", 726: "fchmod", 727: "fchmod", 730: "fchdir", 731: "fchdir", 742: "ftruncate", 743: "ftruncate", 746: "copy_file_range", 747: "copy_file_range", 762: "pwrite64", 763: "pwrite64", 764: "pread64", 765: "pread64", 766: "write", 767: "write", 768: "read", 769: "read", 770: "lseek", 771: "lseek", 776: "readlinkat", 777: "readlinkat", 778: "newfstat", 779: "newfstat", 794: "rename", 795: "rename", 796: "renameat", 797: "renameat", 798: "renameat2", 799: "renameat2", 800: "link", 801: "link", 802: "linkat", 803: "linkat", 804: "symlink", 805: "symlink", 806: "symlinkat", 807: "symlinkat", 808: "unlink", 809: "unlink", 810: "unlinkat", 811: "unlinkat", 812: "rmdir", 813: "rmdir", 814: "mkdir", 815: "mkdir", 816: "mkdirat", 817: "mkdirat", 822: "fcntl", 823: "fcntl", 824: "ioctl", 825: "ioctl", 826: "getdents64", 827: "getdents64", 828: "getdents", 829: "getdents", 862: "lremovexattr", 863: "lremovexattr", 864: "removexattr", 865: "removexattr", 868: "llistxattr", 869: "llistxattr", 870: "listxattr", 871: "listxattr", 874: "lgetxattr", 875: "lgetxattr", 876: "getxattr", 877: "getxattr", 880: "lsetxattr", 881: "lsetxattr", 882: "setxattr", 883: "setxattr", 922: "sync_file_range", 923: "sync_file_range", 924: "fdatasync", 925: "fdatasync", 926: "fsync", 927: "fsync", 944: "fstatfs", 945: "fstatfs", 946: "statfs", 947: "statfs", 954: "inotify_rm_watch", 955: "inotify_rm_watch", 956: "inotify_add_watch", 957: "inotify_add_watch", 962: "fanotify_mark", 963: "fanotify_mark", 1020: "flock", 1021: "flock", 1051: "quotactl_fd", 1052: "quotactl_fd", 1321: "mq_unlink", 1322: "mq_unlink", 1377: "io_uring_register", 1378: "io_uring_register", 1381: "io_uring_enter", 1382: "io_uring_enter", 1: "open", 2: "open", 3: "openat", 4: "openat",
}

func (s TraceId) String() string {
	str, ok := traceId2String[s]
	if !ok {
		panic(fmt.Sprintf("no string representation for trace ID %d found", s))
	}
	return str
}

func (s TraceId) Name() string {
	str, ok := traceId2Name[s]
	if !ok {
		panic(fmt.Sprintf("no name for trace ID %d found", s))
	}
	return str
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
const ENTER_PATH_EVENT = 11
const EXIT_PATH_EVENT = 12

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

type PathEvent struct {
	EventType EventType
	TraceId   TraceId
	Pid       uint32
	Tid       uint32
	Time      uint32
	Pathname  [MAX_FILENAME_LENGTH]byte
}

func (p PathEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Pid:%v Tid:%v Time:%v Pathname:%v", p.EventType, p.TraceId, p.Pid, p.Tid, p.Time, string(p.Pathname[:]))
}

func (p *PathEvent) GetEventType() EventType {
	return p.EventType
}

func (p *PathEvent) GetTraceId() TraceId {
	return p.TraceId
}

func (p *PathEvent) GetPid() uint32 {
	return p.Pid
}

func (p *PathEvent) GetTid() uint32 {
	return p.Tid
}

func (p *PathEvent) GetTime() uint32 {
	return p.Time
}

var poolOfPathEvents = sync.Pool{
	New: func() interface{} { return &PathEvent{} },
}

func NewPathEvent(raw []byte) *PathEvent {
	p := poolOfPathEvents.Get().(*PathEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, p); err != nil {
		fmt.Println(p, raw, len(raw), err)
		panic(raw)
	}
	return p
}

func (p *PathEvent) Recycle() {
	poolOfPathEvents.Put(p)
}

const SYS_EXIT_CACHESTAT TraceId = 527
const SYS_ENTER_CACHESTAT TraceId = 528
const SYS_EXIT_CLOSE_RANGE TraceId = 700
const SYS_ENTER_CLOSE_RANGE TraceId = 701
const SYS_EXIT_CLOSE TraceId = 702
const SYS_ENTER_CLOSE TraceId = 703
const SYS_EXIT_CREAT TraceId = 704
const SYS_ENTER_CREAT TraceId = 705
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
const SYS_EXIT_READLINKAT TraceId = 776
const SYS_ENTER_READLINKAT TraceId = 777
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
const SYS_EXIT_UNLINK TraceId = 808
const SYS_ENTER_UNLINK TraceId = 809
const SYS_EXIT_UNLINKAT TraceId = 810
const SYS_ENTER_UNLINKAT TraceId = 811
const SYS_EXIT_RMDIR TraceId = 812
const SYS_ENTER_RMDIR TraceId = 813
const SYS_EXIT_MKDIR TraceId = 814
const SYS_ENTER_MKDIR TraceId = 815
const SYS_EXIT_MKDIRAT TraceId = 816
const SYS_ENTER_MKDIRAT TraceId = 817
const SYS_EXIT_FCNTL TraceId = 822
const SYS_ENTER_FCNTL TraceId = 823
const SYS_EXIT_IOCTL TraceId = 824
const SYS_ENTER_IOCTL TraceId = 825
const SYS_EXIT_GETDENTS64 TraceId = 826
const SYS_ENTER_GETDENTS64 TraceId = 827
const SYS_EXIT_GETDENTS TraceId = 828
const SYS_ENTER_GETDENTS TraceId = 829
const SYS_EXIT_LREMOVEXATTR TraceId = 862
const SYS_ENTER_LREMOVEXATTR TraceId = 863
const SYS_EXIT_REMOVEXATTR TraceId = 864
const SYS_ENTER_REMOVEXATTR TraceId = 865
const SYS_EXIT_LLISTXATTR TraceId = 868
const SYS_ENTER_LLISTXATTR TraceId = 869
const SYS_EXIT_LISTXATTR TraceId = 870
const SYS_ENTER_LISTXATTR TraceId = 871
const SYS_EXIT_LGETXATTR TraceId = 874
const SYS_ENTER_LGETXATTR TraceId = 875
const SYS_EXIT_GETXATTR TraceId = 876
const SYS_ENTER_GETXATTR TraceId = 877
const SYS_EXIT_LSETXATTR TraceId = 880
const SYS_ENTER_LSETXATTR TraceId = 881
const SYS_EXIT_SETXATTR TraceId = 882
const SYS_ENTER_SETXATTR TraceId = 883
const SYS_EXIT_SYNC_FILE_RANGE TraceId = 922
const SYS_ENTER_SYNC_FILE_RANGE TraceId = 923
const SYS_EXIT_FDATASYNC TraceId = 924
const SYS_ENTER_FDATASYNC TraceId = 925
const SYS_EXIT_FSYNC TraceId = 926
const SYS_ENTER_FSYNC TraceId = 927
const SYS_EXIT_FSTATFS TraceId = 944
const SYS_ENTER_FSTATFS TraceId = 945
const SYS_EXIT_STATFS TraceId = 946
const SYS_ENTER_STATFS TraceId = 947
const SYS_EXIT_INOTIFY_RM_WATCH TraceId = 954
const SYS_ENTER_INOTIFY_RM_WATCH TraceId = 955
const SYS_EXIT_INOTIFY_ADD_WATCH TraceId = 956
const SYS_ENTER_INOTIFY_ADD_WATCH TraceId = 957
const SYS_EXIT_FANOTIFY_MARK TraceId = 962
const SYS_ENTER_FANOTIFY_MARK TraceId = 963
const SYS_EXIT_FLOCK TraceId = 1020
const SYS_ENTER_FLOCK TraceId = 1021
const SYS_EXIT_QUOTACTL_FD TraceId = 1051
const SYS_ENTER_QUOTACTL_FD TraceId = 1052
const SYS_EXIT_MQ_UNLINK TraceId = 1321
const SYS_ENTER_MQ_UNLINK TraceId = 1322
const SYS_EXIT_IO_URING_REGISTER TraceId = 1377
const SYS_ENTER_IO_URING_REGISTER TraceId = 1378
const SYS_EXIT_IO_URING_ENTER TraceId = 1381
const SYS_ENTER_IO_URING_ENTER TraceId = 1382
const SYS_EXIT_OPEN TraceId = 1
const SYS_ENTER_OPEN TraceId = 2
const SYS_EXIT_OPENAT TraceId = 3
const SYS_ENTER_OPENAT TraceId = 4
