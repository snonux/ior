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
	1524: "enter_io_uring_register", 1523: "exit_io_uring_register", 1505: "enter_io_uring_enter", 1504: "exit_io_uring_enter", 1503: "enter_io_uring_setup", 1502: "exit_io_uring_setup", 1161: "enter_quotactl_fd", 1160: "exit_quotactl_fd", 1130: "enter_flock", 1129: "exit_flock", 1114: "enter_io_setup", 1113: "exit_io_setup", 1112: "enter_io_destroy", 1111: "exit_io_destroy", 1110: "enter_io_submit", 1109: "exit_io_submit", 1108: "enter_io_cancel", 1107: "exit_io_cancel", 1106: "enter_io_getevents", 1105: "exit_io_getevents", 1104: "enter_io_pgetevents", 1103: "exit_io_pgetevents", 1072: "enter_fanotify_mark", 1071: "exit_fanotify_mark", 1060: "enter_fspick", 1059: "exit_fspick", 1058: "enter_fsconfig", 1057: "exit_fsconfig", 1056: "enter_statfs", 1055: "exit_statfs", 1054: "enter_fstatfs", 1053: "exit_fstatfs", 1048: "enter_utimensat", 1047: "exit_utimensat", 1046: "enter_futimesat", 1045: "exit_futimesat", 1040: "enter_sync", 1039: "exit_sync", 1038: "enter_syncfs", 1037: "exit_syncfs", 1036: "enter_fsync", 1035: "exit_fsync", 1034: "enter_fdatasync", 1033: "exit_fdatasync", 1032: "enter_sync_file_range", 1031: "exit_sync_file_range", 1030: "enter_vmsplice", 1029: "exit_vmsplice", 992: "enter_setxattrat", 991: "exit_setxattrat", 990: "enter_setxattr", 989: "exit_setxattr", 988: "enter_lsetxattr", 987: "exit_lsetxattr", 986: "enter_fsetxattr", 985: "exit_fsetxattr", 984: "enter_getxattrat", 983: "exit_getxattrat", 982: "enter_getxattr", 981: "exit_getxattr", 980: "enter_lgetxattr", 979: "exit_lgetxattr", 978: "enter_fgetxattr", 977: "exit_fgetxattr", 976: "enter_listxattrat", 975: "exit_listxattrat", 974: "enter_listxattr", 973: "exit_listxattr", 972: "enter_llistxattr", 971: "exit_llistxattr", 970: "enter_flistxattr", 969: "exit_flistxattr", 968: "enter_removexattrat", 967: "exit_removexattrat", 966: "enter_removexattr", 965: "exit_removexattr", 964: "enter_lremovexattr", 963: "exit_lremovexattr", 962: "enter_fremovexattr", 961: "exit_fremovexattr", 958: "enter_open_tree", 957: "exit_open_tree", 948: "enter_mount_setattr", 947: "exit_mount_setattr", 946: "enter_open_tree_attr", 945: "exit_open_tree_attr", 938: "enter_close_range", 937: "exit_close_range", 936: "enter_dup3", 935: "exit_dup3", 934: "enter_dup2", 933: "exit_dup2", 932: "enter_dup", 931: "exit_dup", 918: "enter_getdents", 917: "exit_getdents", 916: "enter_getdents64", 915: "exit_getdents64", 914: "enter_ioctl", 913: "exit_ioctl", 912: "enter_fcntl", 911: "exit_fcntl", 906: "enter_mkdirat", 905: "exit_mkdirat", 904: "enter_mkdir", 903: "exit_mkdir", 902: "enter_rmdir", 901: "exit_rmdir", 900: "enter_unlinkat", 899: "exit_unlinkat", 898: "enter_unlink", 897: "exit_unlink", 896: "enter_symlinkat", 895: "exit_symlinkat", 894: "enter_symlink", 893: "exit_symlink", 892: "enter_linkat", 891: "exit_linkat", 890: "enter_link", 889: "exit_link", 888: "enter_renameat2", 887: "exit_renameat2", 886: "enter_renameat", 885: "exit_renameat", 884: "enter_rename", 883: "exit_rename", 874: "enter_newstat", 873: "exit_newstat", 872: "enter_newlstat", 871: "exit_newlstat", 870: "enter_newfstatat", 869: "exit_newfstatat", 868: "enter_newfstat", 867: "exit_newfstat", 866: "enter_readlinkat", 865: "exit_readlinkat", 864: "enter_readlink", 863: "exit_readlink", 862: "enter_statx", 861: "exit_statx", 860: "enter_lseek", 859: "exit_lseek", 858: "enter_read", 857: "exit_read", 856: "enter_write", 855: "exit_write", 854: "enter_pread64", 853: "exit_pread64", 852: "enter_pwrite64", 851: "exit_pwrite64", 850: "enter_readv", 849: "exit_readv", 848: "enter_writev", 847: "exit_writev", 846: "enter_preadv", 845: "exit_preadv", 844: "enter_preadv2", 843: "exit_preadv2", 842: "enter_pwritev", 841: "exit_pwritev", 840: "enter_pwritev2", 839: "exit_pwritev2", 834: "enter_truncate", 833: "exit_truncate", 832: "enter_ftruncate", 831: "exit_ftruncate", 830: "enter_fallocate", 829: "exit_fallocate", 828: "enter_faccessat", 827: "exit_faccessat", 826: "enter_faccessat2", 825: "exit_faccessat2", 824: "enter_access", 823: "exit_access", 822: "enter_chdir", 821: "exit_chdir", 820: "enter_fchdir", 819: "exit_fchdir", 818: "enter_chroot", 817: "exit_chroot", 816: "enter_fchmod", 815: "exit_fchmod", 814: "enter_fchmodat2", 813: "exit_fchmodat2", 812: "enter_fchmodat", 811: "exit_fchmodat", 810: "enter_chmod", 809: "exit_chmod", 808: "enter_fchownat", 807: "exit_fchownat", 806: "enter_chown", 805: "exit_chown", 804: "enter_lchown", 803: "exit_lchown", 802: "enter_fchown", 801: "exit_fchown", 800: "enter_open", 799: "exit_open", 798: "enter_openat", 797: "exit_openat", 796: "enter_openat2", 795: "exit_openat2", 794: "enter_creat", 793: "exit_creat", 792: "enter_close", 791: "exit_close", 625: "enter_readahead", 624: "exit_readahead", 623: "enter_fadvise64", 622: "exit_fadvise64", 604: "enter_cachestat", 603: "exit_cachestat", 410: "enter_finit_module", 409: "exit_finit_module", 351: "enter_syslog", 350: "exit_syslog", 100: "enter_mmap", 99: "exit_mmap",
}

var traceId2Name = map[TraceId]string{
	1524: "io_uring_register", 1523: "io_uring_register", 1505: "io_uring_enter", 1504: "io_uring_enter", 1503: "io_uring_setup", 1502: "io_uring_setup", 1161: "quotactl_fd", 1160: "quotactl_fd", 1130: "flock", 1129: "flock", 1114: "io_setup", 1113: "io_setup", 1112: "io_destroy", 1111: "io_destroy", 1110: "io_submit", 1109: "io_submit", 1108: "io_cancel", 1107: "io_cancel", 1106: "io_getevents", 1105: "io_getevents", 1104: "io_pgetevents", 1103: "io_pgetevents", 1072: "fanotify_mark", 1071: "fanotify_mark", 1060: "fspick", 1059: "fspick", 1058: "fsconfig", 1057: "fsconfig", 1056: "statfs", 1055: "statfs", 1054: "fstatfs", 1053: "fstatfs", 1048: "utimensat", 1047: "utimensat", 1046: "futimesat", 1045: "futimesat", 1040: "sync", 1039: "sync", 1038: "syncfs", 1037: "syncfs", 1036: "fsync", 1035: "fsync", 1034: "fdatasync", 1033: "fdatasync", 1032: "sync_file_range", 1031: "sync_file_range", 1030: "vmsplice", 1029: "vmsplice", 992: "setxattrat", 991: "setxattrat", 990: "setxattr", 989: "setxattr", 988: "lsetxattr", 987: "lsetxattr", 986: "fsetxattr", 985: "fsetxattr", 984: "getxattrat", 983: "getxattrat", 982: "getxattr", 981: "getxattr", 980: "lgetxattr", 979: "lgetxattr", 978: "fgetxattr", 977: "fgetxattr", 976: "listxattrat", 975: "listxattrat", 974: "listxattr", 973: "listxattr", 972: "llistxattr", 971: "llistxattr", 970: "flistxattr", 969: "flistxattr", 968: "removexattrat", 967: "removexattrat", 966: "removexattr", 965: "removexattr", 964: "lremovexattr", 963: "lremovexattr", 962: "fremovexattr", 961: "fremovexattr", 958: "open_tree", 957: "open_tree", 948: "mount_setattr", 947: "mount_setattr", 946: "open_tree_attr", 945: "open_tree_attr", 938: "close_range", 937: "close_range", 936: "dup3", 935: "dup3", 934: "dup2", 933: "dup2", 932: "dup", 931: "dup", 918: "getdents", 917: "getdents", 916: "getdents64", 915: "getdents64", 914: "ioctl", 913: "ioctl", 912: "fcntl", 911: "fcntl", 906: "mkdirat", 905: "mkdirat", 904: "mkdir", 903: "mkdir", 902: "rmdir", 901: "rmdir", 900: "unlinkat", 899: "unlinkat", 898: "unlink", 897: "unlink", 896: "symlinkat", 895: "symlinkat", 894: "symlink", 893: "symlink", 892: "linkat", 891: "linkat", 890: "link", 889: "link", 888: "renameat2", 887: "renameat2", 886: "renameat", 885: "renameat", 884: "rename", 883: "rename", 874: "newstat", 873: "newstat", 872: "newlstat", 871: "newlstat", 870: "newfstatat", 869: "newfstatat", 868: "newfstat", 867: "newfstat", 866: "readlinkat", 865: "readlinkat", 864: "readlink", 863: "readlink", 862: "statx", 861: "statx", 860: "lseek", 859: "lseek", 858: "read", 857: "read", 856: "write", 855: "write", 854: "pread64", 853: "pread64", 852: "pwrite64", 851: "pwrite64", 850: "readv", 849: "readv", 848: "writev", 847: "writev", 846: "preadv", 845: "preadv", 844: "preadv2", 843: "preadv2", 842: "pwritev", 841: "pwritev", 840: "pwritev2", 839: "pwritev2", 834: "truncate", 833: "truncate", 832: "ftruncate", 831: "ftruncate", 830: "fallocate", 829: "fallocate", 828: "faccessat", 827: "faccessat", 826: "faccessat2", 825: "faccessat2", 824: "access", 823: "access", 822: "chdir", 821: "chdir", 820: "fchdir", 819: "fchdir", 818: "chroot", 817: "chroot", 816: "fchmod", 815: "fchmod", 814: "fchmodat2", 813: "fchmodat2", 812: "fchmodat", 811: "fchmodat", 810: "chmod", 809: "chmod", 808: "fchownat", 807: "fchownat", 806: "chown", 805: "chown", 804: "lchown", 803: "lchown", 802: "fchown", 801: "fchown", 800: "open", 799: "open", 798: "openat", 797: "openat", 796: "openat2", 795: "openat2", 794: "creat", 793: "creat", 792: "close", 791: "close", 625: "readahead", 624: "readahead", 623: "fadvise64", 622: "fadvise64", 604: "cachestat", 603: "cachestat", 410: "finit_module", 409: "finit_module", 351: "syslog", 350: "syslog", 100: "mmap", 99: "mmap",
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
const RET_EVENT_IS_OTHER = 0
const RET_EVENT_IS_READ = 1
const RET_EVENT_IS_WRITE = 2

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
	RetType   uint32
}

func (r RetEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Ret:%v Pid:%v Tid:%v RetType:%v", r.EventType, r.TraceId, r.Time, r.Ret, r.Pid, r.Tid, r.RetType)
}

func (r RetEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*RetEvent)
	if !ok {
		return false
	}
	return r.EventType == otherConcrete.EventType && r.TraceId == otherConcrete.TraceId && r.Time == otherConcrete.Time && r.Ret == otherConcrete.Ret && r.Pid == otherConcrete.Pid && r.Tid == otherConcrete.Tid && r.RetType == otherConcrete.RetType
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

const SYS_ENTER_IO_URING_REGISTER TraceId = 1524
const SYS_EXIT_IO_URING_REGISTER TraceId = 1523
const SYS_ENTER_IO_URING_ENTER TraceId = 1505
const SYS_EXIT_IO_URING_ENTER TraceId = 1504
const SYS_ENTER_IO_URING_SETUP TraceId = 1503
const SYS_EXIT_IO_URING_SETUP TraceId = 1502
const SYS_ENTER_QUOTACTL_FD TraceId = 1161
const SYS_EXIT_QUOTACTL_FD TraceId = 1160
const SYS_ENTER_FLOCK TraceId = 1130
const SYS_EXIT_FLOCK TraceId = 1129
const SYS_ENTER_IO_SETUP TraceId = 1114
const SYS_EXIT_IO_SETUP TraceId = 1113
const SYS_ENTER_IO_DESTROY TraceId = 1112
const SYS_EXIT_IO_DESTROY TraceId = 1111
const SYS_ENTER_IO_SUBMIT TraceId = 1110
const SYS_EXIT_IO_SUBMIT TraceId = 1109
const SYS_ENTER_IO_CANCEL TraceId = 1108
const SYS_EXIT_IO_CANCEL TraceId = 1107
const SYS_ENTER_IO_GETEVENTS TraceId = 1106
const SYS_EXIT_IO_GETEVENTS TraceId = 1105
const SYS_ENTER_IO_PGETEVENTS TraceId = 1104
const SYS_EXIT_IO_PGETEVENTS TraceId = 1103
const SYS_ENTER_FANOTIFY_MARK TraceId = 1072
const SYS_EXIT_FANOTIFY_MARK TraceId = 1071
const SYS_ENTER_FSPICK TraceId = 1060
const SYS_EXIT_FSPICK TraceId = 1059
const SYS_ENTER_FSCONFIG TraceId = 1058
const SYS_EXIT_FSCONFIG TraceId = 1057
const SYS_ENTER_STATFS TraceId = 1056
const SYS_EXIT_STATFS TraceId = 1055
const SYS_ENTER_FSTATFS TraceId = 1054
const SYS_EXIT_FSTATFS TraceId = 1053
const SYS_ENTER_UTIMENSAT TraceId = 1048
const SYS_EXIT_UTIMENSAT TraceId = 1047
const SYS_ENTER_FUTIMESAT TraceId = 1046
const SYS_EXIT_FUTIMESAT TraceId = 1045
const SYS_ENTER_SYNC TraceId = 1040
const SYS_EXIT_SYNC TraceId = 1039
const SYS_ENTER_SYNCFS TraceId = 1038
const SYS_EXIT_SYNCFS TraceId = 1037
const SYS_ENTER_FSYNC TraceId = 1036
const SYS_EXIT_FSYNC TraceId = 1035
const SYS_ENTER_FDATASYNC TraceId = 1034
const SYS_EXIT_FDATASYNC TraceId = 1033
const SYS_ENTER_SYNC_FILE_RANGE TraceId = 1032
const SYS_EXIT_SYNC_FILE_RANGE TraceId = 1031
const SYS_ENTER_VMSPLICE TraceId = 1030
const SYS_EXIT_VMSPLICE TraceId = 1029
const SYS_ENTER_SETXATTRAT TraceId = 992
const SYS_EXIT_SETXATTRAT TraceId = 991
const SYS_ENTER_SETXATTR TraceId = 990
const SYS_EXIT_SETXATTR TraceId = 989
const SYS_ENTER_LSETXATTR TraceId = 988
const SYS_EXIT_LSETXATTR TraceId = 987
const SYS_ENTER_FSETXATTR TraceId = 986
const SYS_EXIT_FSETXATTR TraceId = 985
const SYS_ENTER_GETXATTRAT TraceId = 984
const SYS_EXIT_GETXATTRAT TraceId = 983
const SYS_ENTER_GETXATTR TraceId = 982
const SYS_EXIT_GETXATTR TraceId = 981
const SYS_ENTER_LGETXATTR TraceId = 980
const SYS_EXIT_LGETXATTR TraceId = 979
const SYS_ENTER_FGETXATTR TraceId = 978
const SYS_EXIT_FGETXATTR TraceId = 977
const SYS_ENTER_LISTXATTRAT TraceId = 976
const SYS_EXIT_LISTXATTRAT TraceId = 975
const SYS_ENTER_LISTXATTR TraceId = 974
const SYS_EXIT_LISTXATTR TraceId = 973
const SYS_ENTER_LLISTXATTR TraceId = 972
const SYS_EXIT_LLISTXATTR TraceId = 971
const SYS_ENTER_FLISTXATTR TraceId = 970
const SYS_EXIT_FLISTXATTR TraceId = 969
const SYS_ENTER_REMOVEXATTRAT TraceId = 968
const SYS_EXIT_REMOVEXATTRAT TraceId = 967
const SYS_ENTER_REMOVEXATTR TraceId = 966
const SYS_EXIT_REMOVEXATTR TraceId = 965
const SYS_ENTER_LREMOVEXATTR TraceId = 964
const SYS_EXIT_LREMOVEXATTR TraceId = 963
const SYS_ENTER_FREMOVEXATTR TraceId = 962
const SYS_EXIT_FREMOVEXATTR TraceId = 961
const SYS_ENTER_OPEN_TREE TraceId = 958
const SYS_EXIT_OPEN_TREE TraceId = 957
const SYS_ENTER_MOUNT_SETATTR TraceId = 948
const SYS_EXIT_MOUNT_SETATTR TraceId = 947
const SYS_ENTER_OPEN_TREE_ATTR TraceId = 946
const SYS_EXIT_OPEN_TREE_ATTR TraceId = 945
const SYS_ENTER_CLOSE_RANGE TraceId = 938
const SYS_EXIT_CLOSE_RANGE TraceId = 937
const SYS_ENTER_DUP3 TraceId = 936
const SYS_EXIT_DUP3 TraceId = 935
const SYS_ENTER_DUP2 TraceId = 934
const SYS_EXIT_DUP2 TraceId = 933
const SYS_ENTER_DUP TraceId = 932
const SYS_EXIT_DUP TraceId = 931
const SYS_ENTER_GETDENTS TraceId = 918
const SYS_EXIT_GETDENTS TraceId = 917
const SYS_ENTER_GETDENTS64 TraceId = 916
const SYS_EXIT_GETDENTS64 TraceId = 915
const SYS_ENTER_IOCTL TraceId = 914
const SYS_EXIT_IOCTL TraceId = 913
const SYS_ENTER_FCNTL TraceId = 912
const SYS_EXIT_FCNTL TraceId = 911
const SYS_ENTER_MKDIRAT TraceId = 906
const SYS_EXIT_MKDIRAT TraceId = 905
const SYS_ENTER_MKDIR TraceId = 904
const SYS_EXIT_MKDIR TraceId = 903
const SYS_ENTER_RMDIR TraceId = 902
const SYS_EXIT_RMDIR TraceId = 901
const SYS_ENTER_UNLINKAT TraceId = 900
const SYS_EXIT_UNLINKAT TraceId = 899
const SYS_ENTER_UNLINK TraceId = 898
const SYS_EXIT_UNLINK TraceId = 897
const SYS_ENTER_SYMLINKAT TraceId = 896
const SYS_EXIT_SYMLINKAT TraceId = 895
const SYS_ENTER_SYMLINK TraceId = 894
const SYS_EXIT_SYMLINK TraceId = 893
const SYS_ENTER_LINKAT TraceId = 892
const SYS_EXIT_LINKAT TraceId = 891
const SYS_ENTER_LINK TraceId = 890
const SYS_EXIT_LINK TraceId = 889
const SYS_ENTER_RENAMEAT2 TraceId = 888
const SYS_EXIT_RENAMEAT2 TraceId = 887
const SYS_ENTER_RENAMEAT TraceId = 886
const SYS_EXIT_RENAMEAT TraceId = 885
const SYS_ENTER_RENAME TraceId = 884
const SYS_EXIT_RENAME TraceId = 883
const SYS_ENTER_NEWSTAT TraceId = 874
const SYS_EXIT_NEWSTAT TraceId = 873
const SYS_ENTER_NEWLSTAT TraceId = 872
const SYS_EXIT_NEWLSTAT TraceId = 871
const SYS_ENTER_NEWFSTATAT TraceId = 870
const SYS_EXIT_NEWFSTATAT TraceId = 869
const SYS_ENTER_NEWFSTAT TraceId = 868
const SYS_EXIT_NEWFSTAT TraceId = 867
const SYS_ENTER_READLINKAT TraceId = 866
const SYS_EXIT_READLINKAT TraceId = 865
const SYS_ENTER_READLINK TraceId = 864
const SYS_EXIT_READLINK TraceId = 863
const SYS_ENTER_STATX TraceId = 862
const SYS_EXIT_STATX TraceId = 861
const SYS_ENTER_LSEEK TraceId = 860
const SYS_EXIT_LSEEK TraceId = 859
const SYS_ENTER_READ TraceId = 858
const SYS_EXIT_READ TraceId = 857
const SYS_ENTER_WRITE TraceId = 856
const SYS_EXIT_WRITE TraceId = 855
const SYS_ENTER_PREAD64 TraceId = 854
const SYS_EXIT_PREAD64 TraceId = 853
const SYS_ENTER_PWRITE64 TraceId = 852
const SYS_EXIT_PWRITE64 TraceId = 851
const SYS_ENTER_READV TraceId = 850
const SYS_EXIT_READV TraceId = 849
const SYS_ENTER_WRITEV TraceId = 848
const SYS_EXIT_WRITEV TraceId = 847
const SYS_ENTER_PREADV TraceId = 846
const SYS_EXIT_PREADV TraceId = 845
const SYS_ENTER_PREADV2 TraceId = 844
const SYS_EXIT_PREADV2 TraceId = 843
const SYS_ENTER_PWRITEV TraceId = 842
const SYS_EXIT_PWRITEV TraceId = 841
const SYS_ENTER_PWRITEV2 TraceId = 840
const SYS_EXIT_PWRITEV2 TraceId = 839
const SYS_ENTER_TRUNCATE TraceId = 834
const SYS_EXIT_TRUNCATE TraceId = 833
const SYS_ENTER_FTRUNCATE TraceId = 832
const SYS_EXIT_FTRUNCATE TraceId = 831
const SYS_ENTER_FALLOCATE TraceId = 830
const SYS_EXIT_FALLOCATE TraceId = 829
const SYS_ENTER_FACCESSAT TraceId = 828
const SYS_EXIT_FACCESSAT TraceId = 827
const SYS_ENTER_FACCESSAT2 TraceId = 826
const SYS_EXIT_FACCESSAT2 TraceId = 825
const SYS_ENTER_ACCESS TraceId = 824
const SYS_EXIT_ACCESS TraceId = 823
const SYS_ENTER_CHDIR TraceId = 822
const SYS_EXIT_CHDIR TraceId = 821
const SYS_ENTER_FCHDIR TraceId = 820
const SYS_EXIT_FCHDIR TraceId = 819
const SYS_ENTER_CHROOT TraceId = 818
const SYS_EXIT_CHROOT TraceId = 817
const SYS_ENTER_FCHMOD TraceId = 816
const SYS_EXIT_FCHMOD TraceId = 815
const SYS_ENTER_FCHMODAT2 TraceId = 814
const SYS_EXIT_FCHMODAT2 TraceId = 813
const SYS_ENTER_FCHMODAT TraceId = 812
const SYS_EXIT_FCHMODAT TraceId = 811
const SYS_ENTER_CHMOD TraceId = 810
const SYS_EXIT_CHMOD TraceId = 809
const SYS_ENTER_FCHOWNAT TraceId = 808
const SYS_EXIT_FCHOWNAT TraceId = 807
const SYS_ENTER_CHOWN TraceId = 806
const SYS_EXIT_CHOWN TraceId = 805
const SYS_ENTER_LCHOWN TraceId = 804
const SYS_EXIT_LCHOWN TraceId = 803
const SYS_ENTER_FCHOWN TraceId = 802
const SYS_EXIT_FCHOWN TraceId = 801
const SYS_ENTER_OPEN TraceId = 800
const SYS_EXIT_OPEN TraceId = 799
const SYS_ENTER_OPENAT TraceId = 798
const SYS_EXIT_OPENAT TraceId = 797
const SYS_ENTER_OPENAT2 TraceId = 796
const SYS_EXIT_OPENAT2 TraceId = 795
const SYS_ENTER_CREAT TraceId = 794
const SYS_EXIT_CREAT TraceId = 793
const SYS_ENTER_CLOSE TraceId = 792
const SYS_EXIT_CLOSE TraceId = 791
const SYS_ENTER_READAHEAD TraceId = 625
const SYS_EXIT_READAHEAD TraceId = 624
const SYS_ENTER_FADVISE64 TraceId = 623
const SYS_EXIT_FADVISE64 TraceId = 622
const SYS_ENTER_CACHESTAT TraceId = 604
const SYS_EXIT_CACHESTAT TraceId = 603
const SYS_ENTER_FINIT_MODULE TraceId = 410
const SYS_EXIT_FINIT_MODULE TraceId = 409
const SYS_ENTER_SYSLOG TraceId = 351
const SYS_EXIT_SYSLOG TraceId = 350
const SYS_ENTER_MMAP TraceId = 100
const SYS_EXIT_MMAP TraceId = 99
