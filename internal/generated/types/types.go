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
	1485: "enter_io_uring_register", 1484: "exit_io_uring_register", 1466: "enter_io_uring_enter", 1465: "exit_io_uring_enter", 1127: "enter_quotactl_fd", 1126: "exit_quotactl_fd", 1096: "enter_flock", 1095: "exit_flock", 1038: "enter_fanotify_mark", 1037: "exit_fanotify_mark", 1032: "enter_inotify_add_watch", 1031: "exit_inotify_add_watch", 1022: "enter_statfs", 1021: "exit_statfs", 1020: "enter_fstatfs", 1019: "exit_fstatfs", 1014: "enter_utimensat", 1013: "exit_utimensat", 1012: "enter_futimesat", 1011: "exit_futimesat", 1002: "enter_fsync", 1001: "exit_fsync", 1000: "enter_fdatasync", 999: "exit_fdatasync", 958: "enter_setxattr", 957: "exit_setxattr", 956: "enter_lsetxattr", 955: "exit_lsetxattr", 952: "enter_getxattr", 951: "exit_getxattr", 950: "enter_lgetxattr", 949: "exit_lgetxattr", 946: "enter_listxattr", 945: "exit_listxattr", 944: "enter_llistxattr", 943: "exit_llistxattr", 940: "enter_removexattr", 939: "exit_removexattr", 938: "enter_lremovexattr", 937: "exit_lremovexattr", 932: "enter_open_tree", 931: "exit_open_tree", 900: "enter_getdents", 899: "exit_getdents", 898: "enter_getdents64", 897: "exit_getdents64", 896: "enter_ioctl", 895: "exit_ioctl", 894: "enter_fcntl", 893: "exit_fcntl", 892: "enter_mknodat", 891: "exit_mknodat", 890: "enter_mknod", 889: "exit_mknod", 888: "enter_mkdirat", 887: "exit_mkdirat", 886: "enter_mkdir", 885: "exit_mkdir", 884: "enter_rmdir", 883: "exit_rmdir", 882: "enter_unlinkat", 881: "exit_unlinkat", 880: "enter_unlink", 879: "exit_unlink", 878: "enter_symlinkat", 877: "exit_symlinkat", 876: "enter_symlink", 875: "exit_symlink", 874: "enter_linkat", 873: "exit_linkat", 872: "enter_link", 871: "exit_link", 870: "enter_renameat2", 869: "exit_renameat2", 868: "enter_renameat", 867: "exit_renameat", 866: "enter_rename", 865: "exit_rename", 860: "enter_execve", 859: "exit_execve", 858: "enter_execveat", 857: "exit_execveat", 856: "enter_newstat", 855: "exit_newstat", 854: "enter_newlstat", 853: "exit_newlstat", 852: "enter_newfstatat", 851: "exit_newfstatat", 850: "enter_newfstat", 849: "exit_newfstat", 848: "enter_readlinkat", 847: "exit_readlinkat", 844: "enter_statx", 843: "exit_statx", 842: "enter_lseek", 841: "exit_lseek", 840: "enter_read", 839: "exit_read", 838: "enter_write", 837: "exit_write", 836: "enter_pread64", 835: "exit_pread64", 834: "enter_pwrite64", 833: "exit_pwrite64", 814: "enter_ftruncate", 813: "exit_ftruncate", 810: "enter_faccessat", 809: "exit_faccessat", 808: "enter_faccessat2", 807: "exit_faccessat2", 806: "enter_access", 805: "exit_access", 804: "enter_chdir", 803: "exit_chdir", 802: "enter_fchdir", 801: "exit_fchdir", 800: "enter_chroot", 799: "exit_chroot", 798: "enter_fchmod", 797: "exit_fchmod", 796: "enter_fchmodat2", 795: "exit_fchmodat2", 794: "enter_fchmodat", 793: "exit_fchmodat", 792: "enter_chmod", 791: "exit_chmod", 790: "enter_fchownat", 789: "exit_fchownat", 788: "enter_chown", 787: "exit_chown", 786: "enter_lchown", 785: "exit_lchown", 784: "enter_fchown", 783: "exit_fchown", 782: "enter_open", 781: "exit_open", 780: "enter_openat", 779: "exit_openat", 778: "enter_openat2", 777: "exit_openat2", 776: "enter_creat", 775: "exit_creat", 774: "enter_close", 773: "exit_close", 772: "enter_close_range", 771: "exit_close_range", 592: "enter_cachestat", 591: "exit_cachestat",
}

var traceId2Name = map[TraceId]string{
	1485: "io_uring_register", 1484: "io_uring_register", 1466: "io_uring_enter", 1465: "io_uring_enter", 1127: "quotactl_fd", 1126: "quotactl_fd", 1096: "flock", 1095: "flock", 1038: "fanotify_mark", 1037: "fanotify_mark", 1032: "inotify_add_watch", 1031: "inotify_add_watch", 1022: "statfs", 1021: "statfs", 1020: "fstatfs", 1019: "fstatfs", 1014: "utimensat", 1013: "utimensat", 1012: "futimesat", 1011: "futimesat", 1002: "fsync", 1001: "fsync", 1000: "fdatasync", 999: "fdatasync", 958: "setxattr", 957: "setxattr", 956: "lsetxattr", 955: "lsetxattr", 952: "getxattr", 951: "getxattr", 950: "lgetxattr", 949: "lgetxattr", 946: "listxattr", 945: "listxattr", 944: "llistxattr", 943: "llistxattr", 940: "removexattr", 939: "removexattr", 938: "lremovexattr", 937: "lremovexattr", 932: "open_tree", 931: "open_tree", 900: "getdents", 899: "getdents", 898: "getdents64", 897: "getdents64", 896: "ioctl", 895: "ioctl", 894: "fcntl", 893: "fcntl", 892: "mknodat", 891: "mknodat", 890: "mknod", 889: "mknod", 888: "mkdirat", 887: "mkdirat", 886: "mkdir", 885: "mkdir", 884: "rmdir", 883: "rmdir", 882: "unlinkat", 881: "unlinkat", 880: "unlink", 879: "unlink", 878: "symlinkat", 877: "symlinkat", 876: "symlink", 875: "symlink", 874: "linkat", 873: "linkat", 872: "link", 871: "link", 870: "renameat2", 869: "renameat2", 868: "renameat", 867: "renameat", 866: "rename", 865: "rename", 860: "execve", 859: "execve", 858: "execveat", 857: "execveat", 856: "newstat", 855: "newstat", 854: "newlstat", 853: "newlstat", 852: "newfstatat", 851: "newfstatat", 850: "newfstat", 849: "newfstat", 848: "readlinkat", 847: "readlinkat", 844: "statx", 843: "statx", 842: "lseek", 841: "lseek", 840: "read", 839: "read", 838: "write", 837: "write", 836: "pread64", 835: "pread64", 834: "pwrite64", 833: "pwrite64", 814: "ftruncate", 813: "ftruncate", 810: "faccessat", 809: "faccessat", 808: "faccessat2", 807: "faccessat2", 806: "access", 805: "access", 804: "chdir", 803: "chdir", 802: "fchdir", 801: "fchdir", 800: "chroot", 799: "chroot", 798: "fchmod", 797: "fchmod", 796: "fchmodat2", 795: "fchmodat2", 794: "fchmodat", 793: "fchmodat", 792: "chmod", 791: "chmod", 790: "fchownat", 789: "fchownat", 788: "chown", 787: "chown", 786: "lchown", 785: "lchown", 784: "fchown", 783: "fchown", 782: "open", 781: "open", 780: "openat", 779: "openat", 778: "openat2", 777: "openat2", 776: "creat", 775: "creat", 774: "close", 773: "close", 772: "close_range", 771: "close_range", 592: "cachestat", 591: "cachestat",
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
	fmt.Println("DEBUG, ", o)
	return o
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

func (p *PathEvent) Recycle() {
	poolOfPathEvents.Put(p)
}

const SYS_ENTER_IO_URING_REGISTER TraceId = 1485
const SYS_EXIT_IO_URING_REGISTER TraceId = 1484
const SYS_ENTER_IO_URING_ENTER TraceId = 1466
const SYS_EXIT_IO_URING_ENTER TraceId = 1465
const SYS_ENTER_QUOTACTL_FD TraceId = 1127
const SYS_EXIT_QUOTACTL_FD TraceId = 1126
const SYS_ENTER_FLOCK TraceId = 1096
const SYS_EXIT_FLOCK TraceId = 1095
const SYS_ENTER_FANOTIFY_MARK TraceId = 1038
const SYS_EXIT_FANOTIFY_MARK TraceId = 1037
const SYS_ENTER_INOTIFY_ADD_WATCH TraceId = 1032
const SYS_EXIT_INOTIFY_ADD_WATCH TraceId = 1031
const SYS_ENTER_STATFS TraceId = 1022
const SYS_EXIT_STATFS TraceId = 1021
const SYS_ENTER_FSTATFS TraceId = 1020
const SYS_EXIT_FSTATFS TraceId = 1019
const SYS_ENTER_UTIMENSAT TraceId = 1014
const SYS_EXIT_UTIMENSAT TraceId = 1013
const SYS_ENTER_FUTIMESAT TraceId = 1012
const SYS_EXIT_FUTIMESAT TraceId = 1011
const SYS_ENTER_FSYNC TraceId = 1002
const SYS_EXIT_FSYNC TraceId = 1001
const SYS_ENTER_FDATASYNC TraceId = 1000
const SYS_EXIT_FDATASYNC TraceId = 999
const SYS_ENTER_SETXATTR TraceId = 958
const SYS_EXIT_SETXATTR TraceId = 957
const SYS_ENTER_LSETXATTR TraceId = 956
const SYS_EXIT_LSETXATTR TraceId = 955
const SYS_ENTER_GETXATTR TraceId = 952
const SYS_EXIT_GETXATTR TraceId = 951
const SYS_ENTER_LGETXATTR TraceId = 950
const SYS_EXIT_LGETXATTR TraceId = 949
const SYS_ENTER_LISTXATTR TraceId = 946
const SYS_EXIT_LISTXATTR TraceId = 945
const SYS_ENTER_LLISTXATTR TraceId = 944
const SYS_EXIT_LLISTXATTR TraceId = 943
const SYS_ENTER_REMOVEXATTR TraceId = 940
const SYS_EXIT_REMOVEXATTR TraceId = 939
const SYS_ENTER_LREMOVEXATTR TraceId = 938
const SYS_EXIT_LREMOVEXATTR TraceId = 937
const SYS_ENTER_OPEN_TREE TraceId = 932
const SYS_EXIT_OPEN_TREE TraceId = 931
const SYS_ENTER_GETDENTS TraceId = 900
const SYS_EXIT_GETDENTS TraceId = 899
const SYS_ENTER_GETDENTS64 TraceId = 898
const SYS_EXIT_GETDENTS64 TraceId = 897
const SYS_ENTER_IOCTL TraceId = 896
const SYS_EXIT_IOCTL TraceId = 895
const SYS_ENTER_FCNTL TraceId = 894
const SYS_EXIT_FCNTL TraceId = 893
const SYS_ENTER_MKNODAT TraceId = 892
const SYS_EXIT_MKNODAT TraceId = 891
const SYS_ENTER_MKNOD TraceId = 890
const SYS_EXIT_MKNOD TraceId = 889
const SYS_ENTER_MKDIRAT TraceId = 888
const SYS_EXIT_MKDIRAT TraceId = 887
const SYS_ENTER_MKDIR TraceId = 886
const SYS_EXIT_MKDIR TraceId = 885
const SYS_ENTER_RMDIR TraceId = 884
const SYS_EXIT_RMDIR TraceId = 883
const SYS_ENTER_UNLINKAT TraceId = 882
const SYS_EXIT_UNLINKAT TraceId = 881
const SYS_ENTER_UNLINK TraceId = 880
const SYS_EXIT_UNLINK TraceId = 879
const SYS_ENTER_SYMLINKAT TraceId = 878
const SYS_EXIT_SYMLINKAT TraceId = 877
const SYS_ENTER_SYMLINK TraceId = 876
const SYS_EXIT_SYMLINK TraceId = 875
const SYS_ENTER_LINKAT TraceId = 874
const SYS_EXIT_LINKAT TraceId = 873
const SYS_ENTER_LINK TraceId = 872
const SYS_EXIT_LINK TraceId = 871
const SYS_ENTER_RENAMEAT2 TraceId = 870
const SYS_EXIT_RENAMEAT2 TraceId = 869
const SYS_ENTER_RENAMEAT TraceId = 868
const SYS_EXIT_RENAMEAT TraceId = 867
const SYS_ENTER_RENAME TraceId = 866
const SYS_EXIT_RENAME TraceId = 865
const SYS_ENTER_EXECVE TraceId = 860
const SYS_EXIT_EXECVE TraceId = 859
const SYS_ENTER_EXECVEAT TraceId = 858
const SYS_EXIT_EXECVEAT TraceId = 857
const SYS_ENTER_NEWSTAT TraceId = 856
const SYS_EXIT_NEWSTAT TraceId = 855
const SYS_ENTER_NEWLSTAT TraceId = 854
const SYS_EXIT_NEWLSTAT TraceId = 853
const SYS_ENTER_NEWFSTATAT TraceId = 852
const SYS_EXIT_NEWFSTATAT TraceId = 851
const SYS_ENTER_NEWFSTAT TraceId = 850
const SYS_EXIT_NEWFSTAT TraceId = 849
const SYS_ENTER_READLINKAT TraceId = 848
const SYS_EXIT_READLINKAT TraceId = 847
const SYS_ENTER_STATX TraceId = 844
const SYS_EXIT_STATX TraceId = 843
const SYS_ENTER_LSEEK TraceId = 842
const SYS_EXIT_LSEEK TraceId = 841
const SYS_ENTER_READ TraceId = 840
const SYS_EXIT_READ TraceId = 839
const SYS_ENTER_WRITE TraceId = 838
const SYS_EXIT_WRITE TraceId = 837
const SYS_ENTER_PREAD64 TraceId = 836
const SYS_EXIT_PREAD64 TraceId = 835
const SYS_ENTER_PWRITE64 TraceId = 834
const SYS_EXIT_PWRITE64 TraceId = 833
const SYS_ENTER_FTRUNCATE TraceId = 814
const SYS_EXIT_FTRUNCATE TraceId = 813
const SYS_ENTER_FACCESSAT TraceId = 810
const SYS_EXIT_FACCESSAT TraceId = 809
const SYS_ENTER_FACCESSAT2 TraceId = 808
const SYS_EXIT_FACCESSAT2 TraceId = 807
const SYS_ENTER_ACCESS TraceId = 806
const SYS_EXIT_ACCESS TraceId = 805
const SYS_ENTER_CHDIR TraceId = 804
const SYS_EXIT_CHDIR TraceId = 803
const SYS_ENTER_FCHDIR TraceId = 802
const SYS_EXIT_FCHDIR TraceId = 801
const SYS_ENTER_CHROOT TraceId = 800
const SYS_EXIT_CHROOT TraceId = 799
const SYS_ENTER_FCHMOD TraceId = 798
const SYS_EXIT_FCHMOD TraceId = 797
const SYS_ENTER_FCHMODAT2 TraceId = 796
const SYS_EXIT_FCHMODAT2 TraceId = 795
const SYS_ENTER_FCHMODAT TraceId = 794
const SYS_EXIT_FCHMODAT TraceId = 793
const SYS_ENTER_CHMOD TraceId = 792
const SYS_EXIT_CHMOD TraceId = 791
const SYS_ENTER_FCHOWNAT TraceId = 790
const SYS_EXIT_FCHOWNAT TraceId = 789
const SYS_ENTER_CHOWN TraceId = 788
const SYS_EXIT_CHOWN TraceId = 787
const SYS_ENTER_LCHOWN TraceId = 786
const SYS_EXIT_LCHOWN TraceId = 785
const SYS_ENTER_FCHOWN TraceId = 784
const SYS_EXIT_FCHOWN TraceId = 783
const SYS_ENTER_OPEN TraceId = 782
const SYS_EXIT_OPEN TraceId = 781
const SYS_ENTER_OPENAT TraceId = 780
const SYS_EXIT_OPENAT TraceId = 779
const SYS_ENTER_OPENAT2 TraceId = 778
const SYS_EXIT_OPENAT2 TraceId = 777
const SYS_ENTER_CREAT TraceId = 776
const SYS_EXIT_CREAT TraceId = 775
const SYS_ENTER_CLOSE TraceId = 774
const SYS_EXIT_CLOSE TraceId = 773
const SYS_ENTER_CLOSE_RANGE TraceId = 772
const SYS_EXIT_CLOSE_RANGE TraceId = 771
const SYS_ENTER_CACHESTAT TraceId = 592
const SYS_EXIT_CACHESTAT TraceId = 591
