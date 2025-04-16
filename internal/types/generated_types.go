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
	1513: "enter_io_uring_register", 1512: "exit_io_uring_register", 1494: "enter_io_uring_enter", 1493: "exit_io_uring_enter", 1492: "enter_io_uring_setup", 1491: "exit_io_uring_setup", 1151: "enter_quotactl_fd", 1150: "exit_quotactl_fd", 1120: "enter_flock", 1119: "exit_flock", 1104: "enter_io_setup", 1103: "exit_io_setup", 1102: "enter_io_destroy", 1101: "exit_io_destroy", 1100: "enter_io_submit", 1099: "exit_io_submit", 1098: "enter_io_cancel", 1097: "exit_io_cancel", 1096: "enter_io_getevents", 1095: "exit_io_getevents", 1094: "enter_io_pgetevents", 1093: "exit_io_pgetevents", 1062: "enter_fanotify_mark", 1061: "exit_fanotify_mark", 1050: "enter_fspick", 1049: "exit_fspick", 1048: "enter_fsconfig", 1047: "exit_fsconfig", 1046: "enter_statfs", 1045: "exit_statfs", 1044: "enter_fstatfs", 1043: "exit_fstatfs", 1038: "enter_utimensat", 1037: "exit_utimensat", 1036: "enter_futimesat", 1035: "exit_futimesat", 1030: "enter_sync", 1029: "exit_sync", 1028: "enter_syncfs", 1027: "exit_syncfs", 1026: "enter_fsync", 1025: "exit_fsync", 1024: "enter_fdatasync", 1023: "exit_fdatasync", 1022: "enter_sync_file_range", 1021: "exit_sync_file_range", 1020: "enter_vmsplice", 1019: "exit_vmsplice", 982: "enter_setxattrat", 981: "exit_setxattrat", 980: "enter_setxattr", 979: "exit_setxattr", 978: "enter_lsetxattr", 977: "exit_lsetxattr", 976: "enter_fsetxattr", 975: "exit_fsetxattr", 974: "enter_getxattrat", 973: "exit_getxattrat", 972: "enter_getxattr", 971: "exit_getxattr", 970: "enter_lgetxattr", 969: "exit_lgetxattr", 968: "enter_fgetxattr", 967: "exit_fgetxattr", 966: "enter_listxattrat", 965: "exit_listxattrat", 964: "enter_listxattr", 963: "exit_listxattr", 962: "enter_llistxattr", 961: "exit_llistxattr", 960: "enter_flistxattr", 959: "exit_flistxattr", 958: "enter_removexattrat", 957: "exit_removexattrat", 956: "enter_removexattr", 955: "exit_removexattr", 954: "enter_lremovexattr", 953: "exit_lremovexattr", 952: "enter_fremovexattr", 951: "exit_fremovexattr", 948: "enter_open_tree", 947: "exit_open_tree", 938: "enter_mount_setattr", 937: "exit_mount_setattr", 930: "enter_close_range", 929: "exit_close_range", 928: "enter_dup3", 927: "exit_dup3", 926: "enter_dup2", 925: "exit_dup2", 924: "enter_dup", 923: "exit_dup", 910: "enter_getdents", 909: "exit_getdents", 908: "enter_getdents64", 907: "exit_getdents64", 906: "enter_ioctl", 905: "exit_ioctl", 904: "enter_fcntl", 903: "exit_fcntl", 898: "enter_mkdirat", 897: "exit_mkdirat", 896: "enter_mkdir", 895: "exit_mkdir", 894: "enter_rmdir", 893: "exit_rmdir", 892: "enter_unlinkat", 891: "exit_unlinkat", 890: "enter_unlink", 889: "exit_unlink", 888: "enter_symlinkat", 887: "exit_symlinkat", 886: "enter_symlink", 885: "exit_symlink", 884: "enter_linkat", 883: "exit_linkat", 882: "enter_link", 881: "exit_link", 880: "enter_renameat2", 879: "exit_renameat2", 878: "enter_renameat", 877: "exit_renameat", 876: "enter_rename", 875: "exit_rename", 866: "enter_newstat", 865: "exit_newstat", 864: "enter_newlstat", 863: "exit_newlstat", 862: "enter_newfstatat", 861: "exit_newfstatat", 860: "enter_newfstat", 859: "exit_newfstat", 858: "enter_readlinkat", 857: "exit_readlinkat", 856: "enter_readlink", 855: "exit_readlink", 854: "enter_statx", 853: "exit_statx", 852: "enter_lseek", 851: "exit_lseek", 850: "enter_read", 849: "exit_read", 848: "enter_write", 847: "exit_write", 846: "enter_pread64", 845: "exit_pread64", 844: "enter_pwrite64", 843: "exit_pwrite64", 842: "enter_readv", 841: "exit_readv", 840: "enter_writev", 839: "exit_writev", 838: "enter_preadv", 837: "exit_preadv", 836: "enter_preadv2", 835: "exit_preadv2", 834: "enter_pwritev", 833: "exit_pwritev", 832: "enter_pwritev2", 831: "exit_pwritev2", 826: "enter_truncate", 825: "exit_truncate", 824: "enter_ftruncate", 823: "exit_ftruncate", 822: "enter_fallocate", 821: "exit_fallocate", 820: "enter_faccessat", 819: "exit_faccessat", 818: "enter_faccessat2", 817: "exit_faccessat2", 816: "enter_access", 815: "exit_access", 814: "enter_chdir", 813: "exit_chdir", 812: "enter_fchdir", 811: "exit_fchdir", 810: "enter_chroot", 809: "exit_chroot", 808: "enter_fchmod", 807: "exit_fchmod", 806: "enter_fchmodat2", 805: "exit_fchmodat2", 804: "enter_fchmodat", 803: "exit_fchmodat", 802: "enter_chmod", 801: "exit_chmod", 800: "enter_fchownat", 799: "exit_fchownat", 798: "enter_chown", 797: "exit_chown", 796: "enter_lchown", 795: "exit_lchown", 794: "enter_fchown", 793: "exit_fchown", 792: "enter_open", 791: "exit_open", 790: "enter_openat", 789: "exit_openat", 788: "enter_openat2", 787: "exit_openat2", 786: "enter_creat", 785: "exit_creat", 784: "enter_close", 783: "exit_close", 620: "enter_readahead", 619: "exit_readahead", 618: "enter_fadvise64", 617: "exit_fadvise64", 599: "enter_cachestat", 598: "exit_cachestat", 409: "enter_finit_module", 408: "exit_finit_module", 349: "enter_syslog", 348: "exit_syslog", 102: "enter_mmap", 101: "exit_mmap",
}

var traceId2Name = map[TraceId]string{
	1513: "io_uring_register", 1512: "io_uring_register", 1494: "io_uring_enter", 1493: "io_uring_enter", 1492: "io_uring_setup", 1491: "io_uring_setup", 1151: "quotactl_fd", 1150: "quotactl_fd", 1120: "flock", 1119: "flock", 1104: "io_setup", 1103: "io_setup", 1102: "io_destroy", 1101: "io_destroy", 1100: "io_submit", 1099: "io_submit", 1098: "io_cancel", 1097: "io_cancel", 1096: "io_getevents", 1095: "io_getevents", 1094: "io_pgetevents", 1093: "io_pgetevents", 1062: "fanotify_mark", 1061: "fanotify_mark", 1050: "fspick", 1049: "fspick", 1048: "fsconfig", 1047: "fsconfig", 1046: "statfs", 1045: "statfs", 1044: "fstatfs", 1043: "fstatfs", 1038: "utimensat", 1037: "utimensat", 1036: "futimesat", 1035: "futimesat", 1030: "sync", 1029: "sync", 1028: "syncfs", 1027: "syncfs", 1026: "fsync", 1025: "fsync", 1024: "fdatasync", 1023: "fdatasync", 1022: "sync_file_range", 1021: "sync_file_range", 1020: "vmsplice", 1019: "vmsplice", 982: "setxattrat", 981: "setxattrat", 980: "setxattr", 979: "setxattr", 978: "lsetxattr", 977: "lsetxattr", 976: "fsetxattr", 975: "fsetxattr", 974: "getxattrat", 973: "getxattrat", 972: "getxattr", 971: "getxattr", 970: "lgetxattr", 969: "lgetxattr", 968: "fgetxattr", 967: "fgetxattr", 966: "listxattrat", 965: "listxattrat", 964: "listxattr", 963: "listxattr", 962: "llistxattr", 961: "llistxattr", 960: "flistxattr", 959: "flistxattr", 958: "removexattrat", 957: "removexattrat", 956: "removexattr", 955: "removexattr", 954: "lremovexattr", 953: "lremovexattr", 952: "fremovexattr", 951: "fremovexattr", 948: "open_tree", 947: "open_tree", 938: "mount_setattr", 937: "mount_setattr", 930: "close_range", 929: "close_range", 928: "dup3", 927: "dup3", 926: "dup2", 925: "dup2", 924: "dup", 923: "dup", 910: "getdents", 909: "getdents", 908: "getdents64", 907: "getdents64", 906: "ioctl", 905: "ioctl", 904: "fcntl", 903: "fcntl", 898: "mkdirat", 897: "mkdirat", 896: "mkdir", 895: "mkdir", 894: "rmdir", 893: "rmdir", 892: "unlinkat", 891: "unlinkat", 890: "unlink", 889: "unlink", 888: "symlinkat", 887: "symlinkat", 886: "symlink", 885: "symlink", 884: "linkat", 883: "linkat", 882: "link", 881: "link", 880: "renameat2", 879: "renameat2", 878: "renameat", 877: "renameat", 876: "rename", 875: "rename", 866: "newstat", 865: "newstat", 864: "newlstat", 863: "newlstat", 862: "newfstatat", 861: "newfstatat", 860: "newfstat", 859: "newfstat", 858: "readlinkat", 857: "readlinkat", 856: "readlink", 855: "readlink", 854: "statx", 853: "statx", 852: "lseek", 851: "lseek", 850: "read", 849: "read", 848: "write", 847: "write", 846: "pread64", 845: "pread64", 844: "pwrite64", 843: "pwrite64", 842: "readv", 841: "readv", 840: "writev", 839: "writev", 838: "preadv", 837: "preadv", 836: "preadv2", 835: "preadv2", 834: "pwritev", 833: "pwritev", 832: "pwritev2", 831: "pwritev2", 826: "truncate", 825: "truncate", 824: "ftruncate", 823: "ftruncate", 822: "fallocate", 821: "fallocate", 820: "faccessat", 819: "faccessat", 818: "faccessat2", 817: "faccessat2", 816: "access", 815: "access", 814: "chdir", 813: "chdir", 812: "fchdir", 811: "fchdir", 810: "chroot", 809: "chroot", 808: "fchmod", 807: "fchmod", 806: "fchmodat2", 805: "fchmodat2", 804: "fchmodat", 803: "fchmodat", 802: "chmod", 801: "chmod", 800: "fchownat", 799: "fchownat", 798: "chown", 797: "chown", 796: "lchown", 795: "lchown", 794: "fchown", 793: "fchown", 792: "open", 791: "open", 790: "openat", 789: "openat", 788: "openat2", 787: "openat2", 786: "creat", 785: "creat", 784: "close", 783: "close", 620: "readahead", 619: "readahead", 618: "fadvise64", 617: "fadvise64", 599: "cachestat", 598: "cachestat", 409: "finit_module", 408: "finit_module", 349: "syslog", 348: "syslog", 102: "mmap", 101: "mmap",
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
const ENTER_FCNTL_EVENT = 13
const EXIT_FCNTL_EVENT = 14
const ENTER_DUP3_EVENT = 15
const EXIT_DUP3_EVENT = 16

type OpenEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Flags     int32
	Filename  [MAX_FILENAME_LENGTH]byte
	Comm      [MAX_PROGNAME_LENGTH]byte
}

func (o OpenEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Flags:%v Filename:%v Comm:%v", o.EventType, o.TraceId, o.Time, o.Pid, o.Tid, o.Flags, string(o.Filename[:]), string(o.Comm[:]))
}

func (o OpenEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*OpenEvent)
	if !ok {
		return false
	}
	return o.EventType == otherConcrete.EventType && o.TraceId == otherConcrete.TraceId && o.Time == otherConcrete.Time && o.Pid == otherConcrete.Pid && o.Tid == otherConcrete.Tid && o.Flags == otherConcrete.Flags && o.Filename == otherConcrete.Filename && o.Comm == otherConcrete.Comm
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

func (o *OpenEvent) GetTime() uint64 {
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

func (o *OpenEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, o)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (o *OpenEvent) Recycle() {
	poolOfOpenEvents.Put(o)
}

type NullEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
}

func (n NullEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v", n.EventType, n.TraceId, n.Time, n.Pid, n.Tid)
}

func (n NullEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*NullEvent)
	if !ok {
		return false
	}
	return n.EventType == otherConcrete.EventType && n.TraceId == otherConcrete.TraceId && n.Time == otherConcrete.Time && n.Pid == otherConcrete.Pid && n.Tid == otherConcrete.Tid
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

func (n *NullEvent) GetTime() uint64 {
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

func (n *NullEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, n)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (n *NullEvent) Recycle() {
	poolOfNullEvents.Put(n)
}

type FdEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Fd        int32
}

func (f FdEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v", f.EventType, f.TraceId, f.Time, f.Pid, f.Tid, f.Fd)
}

func (f FdEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*FdEvent)
	if !ok {
		return false
	}
	return f.EventType == otherConcrete.EventType && f.TraceId == otherConcrete.TraceId && f.Time == otherConcrete.Time && f.Pid == otherConcrete.Pid && f.Tid == otherConcrete.Tid && f.Fd == otherConcrete.Fd
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

func (f *FdEvent) GetTime() uint64 {
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

func (f *FdEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, f)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (f *FdEvent) Recycle() {
	poolOfFdEvents.Put(f)
}

type RetEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Ret       int64
	Pid       uint32
	Tid       uint32
}

func (r RetEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Ret:%v Pid:%v Tid:%v", r.EventType, r.TraceId, r.Time, r.Ret, r.Pid, r.Tid)
}

func (r RetEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*RetEvent)
	if !ok {
		return false
	}
	return r.EventType == otherConcrete.EventType && r.TraceId == otherConcrete.TraceId && r.Time == otherConcrete.Time && r.Ret == otherConcrete.Ret && r.Pid == otherConcrete.Pid && r.Tid == otherConcrete.Tid
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

func (r *RetEvent) GetTime() uint64 {
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

func (r *RetEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, r)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *RetEvent) Recycle() {
	poolOfRetEvents.Put(r)
}

type NameEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Oldname   [MAX_FILENAME_LENGTH]byte
	Newname   [MAX_FILENAME_LENGTH]byte
}

func (n NameEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Oldname:%v Newname:%v", n.EventType, n.TraceId, n.Time, n.Pid, n.Tid, string(n.Oldname[:]), string(n.Newname[:]))
}

func (n NameEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*NameEvent)
	if !ok {
		return false
	}
	return n.EventType == otherConcrete.EventType && n.TraceId == otherConcrete.TraceId && n.Time == otherConcrete.Time && n.Pid == otherConcrete.Pid && n.Tid == otherConcrete.Tid && n.Oldname == otherConcrete.Oldname && n.Newname == otherConcrete.Newname
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

func (n *NameEvent) GetTime() uint64 {
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

func (n *NameEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, n)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (n *NameEvent) Recycle() {
	poolOfNameEvents.Put(n)
}

type PathEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Pathname  [MAX_FILENAME_LENGTH]byte
}

func (p PathEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Pathname:%v", p.EventType, p.TraceId, p.Time, p.Pid, p.Tid, string(p.Pathname[:]))
}

func (p PathEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*PathEvent)
	if !ok {
		return false
	}
	return p.EventType == otherConcrete.EventType && p.TraceId == otherConcrete.TraceId && p.Time == otherConcrete.Time && p.Pid == otherConcrete.Pid && p.Tid == otherConcrete.Tid && p.Pathname == otherConcrete.Pathname
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

func (p *PathEvent) GetTime() uint64 {
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

func (p *PathEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *PathEvent) Recycle() {
	poolOfPathEvents.Put(p)
}

type FcntlEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Fd        uint32
	Cmd       uint32
	Arg       uint64
}

func (f FcntlEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v Cmd:%v Arg:%v", f.EventType, f.TraceId, f.Time, f.Pid, f.Tid, f.Fd, f.Cmd, f.Arg)
}

func (f FcntlEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*FcntlEvent)
	if !ok {
		return false
	}
	return f.EventType == otherConcrete.EventType && f.TraceId == otherConcrete.TraceId && f.Time == otherConcrete.Time && f.Pid == otherConcrete.Pid && f.Tid == otherConcrete.Tid && f.Fd == otherConcrete.Fd && f.Cmd == otherConcrete.Cmd && f.Arg == otherConcrete.Arg
}

func (f *FcntlEvent) GetEventType() EventType {
	return f.EventType
}

func (f *FcntlEvent) GetTraceId() TraceId {
	return f.TraceId
}

func (f *FcntlEvent) GetPid() uint32 {
	return f.Pid
}

func (f *FcntlEvent) GetTid() uint32 {
	return f.Tid
}

func (f *FcntlEvent) GetTime() uint64 {
	return f.Time
}

var poolOfFcntlEvents = sync.Pool{
	New: func() interface{} { return &FcntlEvent{} },
}

func NewFcntlEvent(raw []byte) *FcntlEvent {
	f := poolOfFcntlEvents.Get().(*FcntlEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, f); err != nil {
		fmt.Println(f, raw, len(raw), err)
		panic(raw)
	}
	return f
}

func (f *FcntlEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, f)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (f *FcntlEvent) Recycle() {
	poolOfFcntlEvents.Put(f)
}

type Dup3Event struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Fd        int32
	Flags     int32
}

func (d Dup3Event) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v Flags:%v", d.EventType, d.TraceId, d.Time, d.Pid, d.Tid, d.Fd, d.Flags)
}

func (d Dup3Event) Equals(other any) bool {
	otherConcrete, ok := other.(*Dup3Event)
	if !ok {
		return false
	}
	return d.EventType == otherConcrete.EventType && d.TraceId == otherConcrete.TraceId && d.Time == otherConcrete.Time && d.Pid == otherConcrete.Pid && d.Tid == otherConcrete.Tid && d.Fd == otherConcrete.Fd && d.Flags == otherConcrete.Flags
}

func (d *Dup3Event) GetEventType() EventType {
	return d.EventType
}

func (d *Dup3Event) GetTraceId() TraceId {
	return d.TraceId
}

func (d *Dup3Event) GetPid() uint32 {
	return d.Pid
}

func (d *Dup3Event) GetTid() uint32 {
	return d.Tid
}

func (d *Dup3Event) GetTime() uint64 {
	return d.Time
}

var poolOfDup3Events = sync.Pool{
	New: func() interface{} { return &Dup3Event{} },
}

func NewDup3Event(raw []byte) *Dup3Event {
	d := poolOfDup3Events.Get().(*Dup3Event)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, d); err != nil {
		fmt.Println(d, raw, len(raw), err)
		panic(raw)
	}
	return d
}

func (d *Dup3Event) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, d)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *Dup3Event) Recycle() {
	poolOfDup3Events.Put(d)
}

const SYS_ENTER_IO_URING_REGISTER TraceId = 1513
const SYS_EXIT_IO_URING_REGISTER TraceId = 1512
const SYS_ENTER_IO_URING_ENTER TraceId = 1494
const SYS_EXIT_IO_URING_ENTER TraceId = 1493
const SYS_ENTER_IO_URING_SETUP TraceId = 1492
const SYS_EXIT_IO_URING_SETUP TraceId = 1491
const SYS_ENTER_QUOTACTL_FD TraceId = 1151
const SYS_EXIT_QUOTACTL_FD TraceId = 1150
const SYS_ENTER_FLOCK TraceId = 1120
const SYS_EXIT_FLOCK TraceId = 1119
const SYS_ENTER_IO_SETUP TraceId = 1104
const SYS_EXIT_IO_SETUP TraceId = 1103
const SYS_ENTER_IO_DESTROY TraceId = 1102
const SYS_EXIT_IO_DESTROY TraceId = 1101
const SYS_ENTER_IO_SUBMIT TraceId = 1100
const SYS_EXIT_IO_SUBMIT TraceId = 1099
const SYS_ENTER_IO_CANCEL TraceId = 1098
const SYS_EXIT_IO_CANCEL TraceId = 1097
const SYS_ENTER_IO_GETEVENTS TraceId = 1096
const SYS_EXIT_IO_GETEVENTS TraceId = 1095
const SYS_ENTER_IO_PGETEVENTS TraceId = 1094
const SYS_EXIT_IO_PGETEVENTS TraceId = 1093
const SYS_ENTER_FANOTIFY_MARK TraceId = 1062
const SYS_EXIT_FANOTIFY_MARK TraceId = 1061
const SYS_ENTER_FSPICK TraceId = 1050
const SYS_EXIT_FSPICK TraceId = 1049
const SYS_ENTER_FSCONFIG TraceId = 1048
const SYS_EXIT_FSCONFIG TraceId = 1047
const SYS_ENTER_STATFS TraceId = 1046
const SYS_EXIT_STATFS TraceId = 1045
const SYS_ENTER_FSTATFS TraceId = 1044
const SYS_EXIT_FSTATFS TraceId = 1043
const SYS_ENTER_UTIMENSAT TraceId = 1038
const SYS_EXIT_UTIMENSAT TraceId = 1037
const SYS_ENTER_FUTIMESAT TraceId = 1036
const SYS_EXIT_FUTIMESAT TraceId = 1035
const SYS_ENTER_SYNC TraceId = 1030
const SYS_EXIT_SYNC TraceId = 1029
const SYS_ENTER_SYNCFS TraceId = 1028
const SYS_EXIT_SYNCFS TraceId = 1027
const SYS_ENTER_FSYNC TraceId = 1026
const SYS_EXIT_FSYNC TraceId = 1025
const SYS_ENTER_FDATASYNC TraceId = 1024
const SYS_EXIT_FDATASYNC TraceId = 1023
const SYS_ENTER_SYNC_FILE_RANGE TraceId = 1022
const SYS_EXIT_SYNC_FILE_RANGE TraceId = 1021
const SYS_ENTER_VMSPLICE TraceId = 1020
const SYS_EXIT_VMSPLICE TraceId = 1019
const SYS_ENTER_SETXATTRAT TraceId = 982
const SYS_EXIT_SETXATTRAT TraceId = 981
const SYS_ENTER_SETXATTR TraceId = 980
const SYS_EXIT_SETXATTR TraceId = 979
const SYS_ENTER_LSETXATTR TraceId = 978
const SYS_EXIT_LSETXATTR TraceId = 977
const SYS_ENTER_FSETXATTR TraceId = 976
const SYS_EXIT_FSETXATTR TraceId = 975
const SYS_ENTER_GETXATTRAT TraceId = 974
const SYS_EXIT_GETXATTRAT TraceId = 973
const SYS_ENTER_GETXATTR TraceId = 972
const SYS_EXIT_GETXATTR TraceId = 971
const SYS_ENTER_LGETXATTR TraceId = 970
const SYS_EXIT_LGETXATTR TraceId = 969
const SYS_ENTER_FGETXATTR TraceId = 968
const SYS_EXIT_FGETXATTR TraceId = 967
const SYS_ENTER_LISTXATTRAT TraceId = 966
const SYS_EXIT_LISTXATTRAT TraceId = 965
const SYS_ENTER_LISTXATTR TraceId = 964
const SYS_EXIT_LISTXATTR TraceId = 963
const SYS_ENTER_LLISTXATTR TraceId = 962
const SYS_EXIT_LLISTXATTR TraceId = 961
const SYS_ENTER_FLISTXATTR TraceId = 960
const SYS_EXIT_FLISTXATTR TraceId = 959
const SYS_ENTER_REMOVEXATTRAT TraceId = 958
const SYS_EXIT_REMOVEXATTRAT TraceId = 957
const SYS_ENTER_REMOVEXATTR TraceId = 956
const SYS_EXIT_REMOVEXATTR TraceId = 955
const SYS_ENTER_LREMOVEXATTR TraceId = 954
const SYS_EXIT_LREMOVEXATTR TraceId = 953
const SYS_ENTER_FREMOVEXATTR TraceId = 952
const SYS_EXIT_FREMOVEXATTR TraceId = 951
const SYS_ENTER_OPEN_TREE TraceId = 948
const SYS_EXIT_OPEN_TREE TraceId = 947
const SYS_ENTER_MOUNT_SETATTR TraceId = 938
const SYS_EXIT_MOUNT_SETATTR TraceId = 937
const SYS_ENTER_CLOSE_RANGE TraceId = 930
const SYS_EXIT_CLOSE_RANGE TraceId = 929
const SYS_ENTER_DUP3 TraceId = 928
const SYS_EXIT_DUP3 TraceId = 927
const SYS_ENTER_DUP2 TraceId = 926
const SYS_EXIT_DUP2 TraceId = 925
const SYS_ENTER_DUP TraceId = 924
const SYS_EXIT_DUP TraceId = 923
const SYS_ENTER_GETDENTS TraceId = 910
const SYS_EXIT_GETDENTS TraceId = 909
const SYS_ENTER_GETDENTS64 TraceId = 908
const SYS_EXIT_GETDENTS64 TraceId = 907
const SYS_ENTER_IOCTL TraceId = 906
const SYS_EXIT_IOCTL TraceId = 905
const SYS_ENTER_FCNTL TraceId = 904
const SYS_EXIT_FCNTL TraceId = 903
const SYS_ENTER_MKDIRAT TraceId = 898
const SYS_EXIT_MKDIRAT TraceId = 897
const SYS_ENTER_MKDIR TraceId = 896
const SYS_EXIT_MKDIR TraceId = 895
const SYS_ENTER_RMDIR TraceId = 894
const SYS_EXIT_RMDIR TraceId = 893
const SYS_ENTER_UNLINKAT TraceId = 892
const SYS_EXIT_UNLINKAT TraceId = 891
const SYS_ENTER_UNLINK TraceId = 890
const SYS_EXIT_UNLINK TraceId = 889
const SYS_ENTER_SYMLINKAT TraceId = 888
const SYS_EXIT_SYMLINKAT TraceId = 887
const SYS_ENTER_SYMLINK TraceId = 886
const SYS_EXIT_SYMLINK TraceId = 885
const SYS_ENTER_LINKAT TraceId = 884
const SYS_EXIT_LINKAT TraceId = 883
const SYS_ENTER_LINK TraceId = 882
const SYS_EXIT_LINK TraceId = 881
const SYS_ENTER_RENAMEAT2 TraceId = 880
const SYS_EXIT_RENAMEAT2 TraceId = 879
const SYS_ENTER_RENAMEAT TraceId = 878
const SYS_EXIT_RENAMEAT TraceId = 877
const SYS_ENTER_RENAME TraceId = 876
const SYS_EXIT_RENAME TraceId = 875
const SYS_ENTER_NEWSTAT TraceId = 866
const SYS_EXIT_NEWSTAT TraceId = 865
const SYS_ENTER_NEWLSTAT TraceId = 864
const SYS_EXIT_NEWLSTAT TraceId = 863
const SYS_ENTER_NEWFSTATAT TraceId = 862
const SYS_EXIT_NEWFSTATAT TraceId = 861
const SYS_ENTER_NEWFSTAT TraceId = 860
const SYS_EXIT_NEWFSTAT TraceId = 859
const SYS_ENTER_READLINKAT TraceId = 858
const SYS_EXIT_READLINKAT TraceId = 857
const SYS_ENTER_READLINK TraceId = 856
const SYS_EXIT_READLINK TraceId = 855
const SYS_ENTER_STATX TraceId = 854
const SYS_EXIT_STATX TraceId = 853
const SYS_ENTER_LSEEK TraceId = 852
const SYS_EXIT_LSEEK TraceId = 851
const SYS_ENTER_READ TraceId = 850
const SYS_EXIT_READ TraceId = 849
const SYS_ENTER_WRITE TraceId = 848
const SYS_EXIT_WRITE TraceId = 847
const SYS_ENTER_PREAD64 TraceId = 846
const SYS_EXIT_PREAD64 TraceId = 845
const SYS_ENTER_PWRITE64 TraceId = 844
const SYS_EXIT_PWRITE64 TraceId = 843
const SYS_ENTER_READV TraceId = 842
const SYS_EXIT_READV TraceId = 841
const SYS_ENTER_WRITEV TraceId = 840
const SYS_EXIT_WRITEV TraceId = 839
const SYS_ENTER_PREADV TraceId = 838
const SYS_EXIT_PREADV TraceId = 837
const SYS_ENTER_PREADV2 TraceId = 836
const SYS_EXIT_PREADV2 TraceId = 835
const SYS_ENTER_PWRITEV TraceId = 834
const SYS_EXIT_PWRITEV TraceId = 833
const SYS_ENTER_PWRITEV2 TraceId = 832
const SYS_EXIT_PWRITEV2 TraceId = 831
const SYS_ENTER_TRUNCATE TraceId = 826
const SYS_EXIT_TRUNCATE TraceId = 825
const SYS_ENTER_FTRUNCATE TraceId = 824
const SYS_EXIT_FTRUNCATE TraceId = 823
const SYS_ENTER_FALLOCATE TraceId = 822
const SYS_EXIT_FALLOCATE TraceId = 821
const SYS_ENTER_FACCESSAT TraceId = 820
const SYS_EXIT_FACCESSAT TraceId = 819
const SYS_ENTER_FACCESSAT2 TraceId = 818
const SYS_EXIT_FACCESSAT2 TraceId = 817
const SYS_ENTER_ACCESS TraceId = 816
const SYS_EXIT_ACCESS TraceId = 815
const SYS_ENTER_CHDIR TraceId = 814
const SYS_EXIT_CHDIR TraceId = 813
const SYS_ENTER_FCHDIR TraceId = 812
const SYS_EXIT_FCHDIR TraceId = 811
const SYS_ENTER_CHROOT TraceId = 810
const SYS_EXIT_CHROOT TraceId = 809
const SYS_ENTER_FCHMOD TraceId = 808
const SYS_EXIT_FCHMOD TraceId = 807
const SYS_ENTER_FCHMODAT2 TraceId = 806
const SYS_EXIT_FCHMODAT2 TraceId = 805
const SYS_ENTER_FCHMODAT TraceId = 804
const SYS_EXIT_FCHMODAT TraceId = 803
const SYS_ENTER_CHMOD TraceId = 802
const SYS_EXIT_CHMOD TraceId = 801
const SYS_ENTER_FCHOWNAT TraceId = 800
const SYS_EXIT_FCHOWNAT TraceId = 799
const SYS_ENTER_CHOWN TraceId = 798
const SYS_EXIT_CHOWN TraceId = 797
const SYS_ENTER_LCHOWN TraceId = 796
const SYS_EXIT_LCHOWN TraceId = 795
const SYS_ENTER_FCHOWN TraceId = 794
const SYS_EXIT_FCHOWN TraceId = 793
const SYS_ENTER_OPEN TraceId = 792
const SYS_EXIT_OPEN TraceId = 791
const SYS_ENTER_OPENAT TraceId = 790
const SYS_EXIT_OPENAT TraceId = 789
const SYS_ENTER_OPENAT2 TraceId = 788
const SYS_EXIT_OPENAT2 TraceId = 787
const SYS_ENTER_CREAT TraceId = 786
const SYS_EXIT_CREAT TraceId = 785
const SYS_ENTER_CLOSE TraceId = 784
const SYS_EXIT_CLOSE TraceId = 783
const SYS_ENTER_READAHEAD TraceId = 620
const SYS_EXIT_READAHEAD TraceId = 619
const SYS_ENTER_FADVISE64 TraceId = 618
const SYS_EXIT_FADVISE64 TraceId = 617
const SYS_ENTER_CACHESTAT TraceId = 599
const SYS_EXIT_CACHESTAT TraceId = 598
const SYS_ENTER_FINIT_MODULE TraceId = 409
const SYS_EXIT_FINIT_MODULE TraceId = 408
const SYS_ENTER_SYSLOG TraceId = 349
const SYS_EXIT_SYSLOG TraceId = 348
const SYS_ENTER_MMAP TraceId = 102
const SYS_EXIT_MMAP TraceId = 101
