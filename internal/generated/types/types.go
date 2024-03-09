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
	1382: "enter_io_uring_enter", 1381: "exit_io_uring_enter", 1378: "enter_io_uring_register", 1377: "exit_io_uring_register", 1052: "enter_quotactl_fd", 1051: "exit_quotactl_fd", 1021: "enter_flock", 1020: "exit_flock", 963: "enter_fanotify_mark", 962: "exit_fanotify_mark", 957: "enter_inotify_add_watch", 956: "exit_inotify_add_watch", 947: "enter_statfs", 946: "exit_statfs", 945: "enter_fstatfs", 944: "exit_fstatfs", 939: "enter_utimensat", 938: "exit_utimensat", 937: "enter_futimesat", 936: "exit_futimesat", 927: "enter_fsync", 926: "exit_fsync", 925: "enter_fdatasync", 924: "exit_fdatasync", 883: "enter_setxattr", 882: "exit_setxattr", 881: "enter_lsetxattr", 880: "exit_lsetxattr", 877: "enter_getxattr", 876: "exit_getxattr", 875: "enter_lgetxattr", 874: "exit_lgetxattr", 871: "enter_listxattr", 870: "exit_listxattr", 869: "enter_llistxattr", 868: "exit_llistxattr", 865: "enter_removexattr", 864: "exit_removexattr", 863: "enter_lremovexattr", 862: "exit_lremovexattr", 857: "enter_open_tree", 856: "exit_open_tree", 829: "enter_getdents", 828: "exit_getdents", 827: "enter_getdents64", 826: "exit_getdents64", 825: "enter_ioctl", 824: "exit_ioctl", 823: "enter_fcntl", 822: "exit_fcntl", 821: "enter_mknodat", 820: "exit_mknodat", 819: "enter_mknod", 818: "exit_mknod", 817: "enter_mkdirat", 816: "exit_mkdirat", 815: "enter_mkdir", 814: "exit_mkdir", 813: "enter_rmdir", 812: "exit_rmdir", 811: "enter_unlinkat", 810: "exit_unlinkat", 809: "enter_unlink", 808: "exit_unlink", 807: "enter_symlinkat", 806: "exit_symlinkat", 805: "enter_symlink", 804: "exit_symlink", 803: "enter_linkat", 802: "exit_linkat", 801: "enter_link", 800: "exit_link", 799: "enter_renameat2", 798: "exit_renameat2", 797: "enter_renameat", 796: "exit_renameat", 795: "enter_rename", 794: "exit_rename", 789: "enter_execve", 788: "exit_execve", 787: "enter_execveat", 786: "exit_execveat", 785: "enter_newstat", 784: "exit_newstat", 783: "enter_newlstat", 782: "exit_newlstat", 781: "enter_newfstatat", 780: "exit_newfstatat", 779: "enter_newfstat", 778: "exit_newfstat", 777: "enter_readlinkat", 776: "exit_readlinkat", 773: "enter_statx", 772: "exit_statx", 771: "enter_lseek", 770: "exit_lseek", 769: "enter_read", 768: "exit_read", 767: "enter_write", 766: "exit_write", 765: "enter_pread64", 764: "exit_pread64", 763: "enter_pwrite64", 762: "exit_pwrite64", 743: "enter_ftruncate", 742: "exit_ftruncate", 739: "enter_faccessat", 738: "exit_faccessat", 737: "enter_faccessat2", 736: "exit_faccessat2", 735: "enter_access", 734: "exit_access", 733: "enter_chdir", 732: "exit_chdir", 731: "enter_fchdir", 730: "exit_fchdir", 729: "enter_chroot", 728: "exit_chroot", 727: "enter_fchmod", 726: "exit_fchmod", 725: "enter_fchmodat2", 724: "exit_fchmodat2", 723: "enter_fchmodat", 722: "exit_fchmodat", 721: "enter_chmod", 720: "exit_chmod", 719: "enter_fchownat", 718: "exit_fchownat", 717: "enter_chown", 716: "exit_chown", 715: "enter_lchown", 714: "exit_lchown", 713: "enter_fchown", 712: "exit_fchown", 711: "enter_open", 710: "exit_open", 709: "enter_openat", 708: "exit_openat", 707: "enter_openat2", 706: "exit_openat2", 705: "enter_creat", 704: "exit_creat", 703: "enter_close", 702: "exit_close", 701: "enter_close_range", 700: "exit_close_range", 528: "enter_cachestat", 527: "exit_cachestat",
}

var traceId2Name = map[TraceId]string{
	1382: "io_uring_enter", 1381: "io_uring_enter", 1378: "io_uring_register", 1377: "io_uring_register", 1052: "quotactl_fd", 1051: "quotactl_fd", 1021: "flock", 1020: "flock", 963: "fanotify_mark", 962: "fanotify_mark", 957: "inotify_add_watch", 956: "inotify_add_watch", 947: "statfs", 946: "statfs", 945: "fstatfs", 944: "fstatfs", 939: "utimensat", 938: "utimensat", 937: "futimesat", 936: "futimesat", 927: "fsync", 926: "fsync", 925: "fdatasync", 924: "fdatasync", 883: "setxattr", 882: "setxattr", 881: "lsetxattr", 880: "lsetxattr", 877: "getxattr", 876: "getxattr", 875: "lgetxattr", 874: "lgetxattr", 871: "listxattr", 870: "listxattr", 869: "llistxattr", 868: "llistxattr", 865: "removexattr", 864: "removexattr", 863: "lremovexattr", 862: "lremovexattr", 857: "open_tree", 856: "open_tree", 829: "getdents", 828: "getdents", 827: "getdents64", 826: "getdents64", 825: "ioctl", 824: "ioctl", 823: "fcntl", 822: "fcntl", 821: "mknodat", 820: "mknodat", 819: "mknod", 818: "mknod", 817: "mkdirat", 816: "mkdirat", 815: "mkdir", 814: "mkdir", 813: "rmdir", 812: "rmdir", 811: "unlinkat", 810: "unlinkat", 809: "unlink", 808: "unlink", 807: "symlinkat", 806: "symlinkat", 805: "symlink", 804: "symlink", 803: "linkat", 802: "linkat", 801: "link", 800: "link", 799: "renameat2", 798: "renameat2", 797: "renameat", 796: "renameat", 795: "rename", 794: "rename", 789: "execve", 788: "execve", 787: "execveat", 786: "execveat", 785: "newstat", 784: "newstat", 783: "newlstat", 782: "newlstat", 781: "newfstatat", 780: "newfstatat", 779: "newfstat", 778: "newfstat", 777: "readlinkat", 776: "readlinkat", 773: "statx", 772: "statx", 771: "lseek", 770: "lseek", 769: "read", 768: "read", 767: "write", 766: "write", 765: "pread64", 764: "pread64", 763: "pwrite64", 762: "pwrite64", 743: "ftruncate", 742: "ftruncate", 739: "faccessat", 738: "faccessat", 737: "faccessat2", 736: "faccessat2", 735: "access", 734: "access", 733: "chdir", 732: "chdir", 731: "fchdir", 730: "fchdir", 729: "chroot", 728: "chroot", 727: "fchmod", 726: "fchmod", 725: "fchmodat2", 724: "fchmodat2", 723: "fchmodat", 722: "fchmodat", 721: "chmod", 720: "chmod", 719: "fchownat", 718: "fchownat", 717: "chown", 716: "chown", 715: "lchown", 714: "lchown", 713: "fchown", 712: "fchown", 711: "open", 710: "open", 709: "openat", 708: "openat", 707: "openat2", 706: "openat2", 705: "creat", 704: "creat", 703: "close", 702: "close", 701: "close_range", 700: "close_range", 528: "cachestat", 527: "cachestat",
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
	Flags     int32
	Filename  [MAX_FILENAME_LENGTH]byte
	Comm      [MAX_PROGNAME_LENGTH]byte
}

func (o OpenEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Pid:%v Tid:%v Time:%v Flags:%v Filename:%v Comm:%v", o.EventType, o.TraceId, o.Pid, o.Tid, o.Time, o.Flags, string(o.Filename[:]), string(o.Comm[:]))
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

const SYS_ENTER_IO_URING_ENTER TraceId = 1382
const SYS_EXIT_IO_URING_ENTER TraceId = 1381
const SYS_ENTER_IO_URING_REGISTER TraceId = 1378
const SYS_EXIT_IO_URING_REGISTER TraceId = 1377
const SYS_ENTER_QUOTACTL_FD TraceId = 1052
const SYS_EXIT_QUOTACTL_FD TraceId = 1051
const SYS_ENTER_FLOCK TraceId = 1021
const SYS_EXIT_FLOCK TraceId = 1020
const SYS_ENTER_FANOTIFY_MARK TraceId = 963
const SYS_EXIT_FANOTIFY_MARK TraceId = 962
const SYS_ENTER_INOTIFY_ADD_WATCH TraceId = 957
const SYS_EXIT_INOTIFY_ADD_WATCH TraceId = 956
const SYS_ENTER_STATFS TraceId = 947
const SYS_EXIT_STATFS TraceId = 946
const SYS_ENTER_FSTATFS TraceId = 945
const SYS_EXIT_FSTATFS TraceId = 944
const SYS_ENTER_UTIMENSAT TraceId = 939
const SYS_EXIT_UTIMENSAT TraceId = 938
const SYS_ENTER_FUTIMESAT TraceId = 937
const SYS_EXIT_FUTIMESAT TraceId = 936
const SYS_ENTER_FSYNC TraceId = 927
const SYS_EXIT_FSYNC TraceId = 926
const SYS_ENTER_FDATASYNC TraceId = 925
const SYS_EXIT_FDATASYNC TraceId = 924
const SYS_ENTER_SETXATTR TraceId = 883
const SYS_EXIT_SETXATTR TraceId = 882
const SYS_ENTER_LSETXATTR TraceId = 881
const SYS_EXIT_LSETXATTR TraceId = 880
const SYS_ENTER_GETXATTR TraceId = 877
const SYS_EXIT_GETXATTR TraceId = 876
const SYS_ENTER_LGETXATTR TraceId = 875
const SYS_EXIT_LGETXATTR TraceId = 874
const SYS_ENTER_LISTXATTR TraceId = 871
const SYS_EXIT_LISTXATTR TraceId = 870
const SYS_ENTER_LLISTXATTR TraceId = 869
const SYS_EXIT_LLISTXATTR TraceId = 868
const SYS_ENTER_REMOVEXATTR TraceId = 865
const SYS_EXIT_REMOVEXATTR TraceId = 864
const SYS_ENTER_LREMOVEXATTR TraceId = 863
const SYS_EXIT_LREMOVEXATTR TraceId = 862
const SYS_ENTER_OPEN_TREE TraceId = 857
const SYS_EXIT_OPEN_TREE TraceId = 856
const SYS_ENTER_GETDENTS TraceId = 829
const SYS_EXIT_GETDENTS TraceId = 828
const SYS_ENTER_GETDENTS64 TraceId = 827
const SYS_EXIT_GETDENTS64 TraceId = 826
const SYS_ENTER_IOCTL TraceId = 825
const SYS_EXIT_IOCTL TraceId = 824
const SYS_ENTER_FCNTL TraceId = 823
const SYS_EXIT_FCNTL TraceId = 822
const SYS_ENTER_MKNODAT TraceId = 821
const SYS_EXIT_MKNODAT TraceId = 820
const SYS_ENTER_MKNOD TraceId = 819
const SYS_EXIT_MKNOD TraceId = 818
const SYS_ENTER_MKDIRAT TraceId = 817
const SYS_EXIT_MKDIRAT TraceId = 816
const SYS_ENTER_MKDIR TraceId = 815
const SYS_EXIT_MKDIR TraceId = 814
const SYS_ENTER_RMDIR TraceId = 813
const SYS_EXIT_RMDIR TraceId = 812
const SYS_ENTER_UNLINKAT TraceId = 811
const SYS_EXIT_UNLINKAT TraceId = 810
const SYS_ENTER_UNLINK TraceId = 809
const SYS_EXIT_UNLINK TraceId = 808
const SYS_ENTER_SYMLINKAT TraceId = 807
const SYS_EXIT_SYMLINKAT TraceId = 806
const SYS_ENTER_SYMLINK TraceId = 805
const SYS_EXIT_SYMLINK TraceId = 804
const SYS_ENTER_LINKAT TraceId = 803
const SYS_EXIT_LINKAT TraceId = 802
const SYS_ENTER_LINK TraceId = 801
const SYS_EXIT_LINK TraceId = 800
const SYS_ENTER_RENAMEAT2 TraceId = 799
const SYS_EXIT_RENAMEAT2 TraceId = 798
const SYS_ENTER_RENAMEAT TraceId = 797
const SYS_EXIT_RENAMEAT TraceId = 796
const SYS_ENTER_RENAME TraceId = 795
const SYS_EXIT_RENAME TraceId = 794
const SYS_ENTER_EXECVE TraceId = 789
const SYS_EXIT_EXECVE TraceId = 788
const SYS_ENTER_EXECVEAT TraceId = 787
const SYS_EXIT_EXECVEAT TraceId = 786
const SYS_ENTER_NEWSTAT TraceId = 785
const SYS_EXIT_NEWSTAT TraceId = 784
const SYS_ENTER_NEWLSTAT TraceId = 783
const SYS_EXIT_NEWLSTAT TraceId = 782
const SYS_ENTER_NEWFSTATAT TraceId = 781
const SYS_EXIT_NEWFSTATAT TraceId = 780
const SYS_ENTER_NEWFSTAT TraceId = 779
const SYS_EXIT_NEWFSTAT TraceId = 778
const SYS_ENTER_READLINKAT TraceId = 777
const SYS_EXIT_READLINKAT TraceId = 776
const SYS_ENTER_STATX TraceId = 773
const SYS_EXIT_STATX TraceId = 772
const SYS_ENTER_LSEEK TraceId = 771
const SYS_EXIT_LSEEK TraceId = 770
const SYS_ENTER_READ TraceId = 769
const SYS_EXIT_READ TraceId = 768
const SYS_ENTER_WRITE TraceId = 767
const SYS_EXIT_WRITE TraceId = 766
const SYS_ENTER_PREAD64 TraceId = 765
const SYS_EXIT_PREAD64 TraceId = 764
const SYS_ENTER_PWRITE64 TraceId = 763
const SYS_EXIT_PWRITE64 TraceId = 762
const SYS_ENTER_FTRUNCATE TraceId = 743
const SYS_EXIT_FTRUNCATE TraceId = 742
const SYS_ENTER_FACCESSAT TraceId = 739
const SYS_EXIT_FACCESSAT TraceId = 738
const SYS_ENTER_FACCESSAT2 TraceId = 737
const SYS_EXIT_FACCESSAT2 TraceId = 736
const SYS_ENTER_ACCESS TraceId = 735
const SYS_EXIT_ACCESS TraceId = 734
const SYS_ENTER_CHDIR TraceId = 733
const SYS_EXIT_CHDIR TraceId = 732
const SYS_ENTER_FCHDIR TraceId = 731
const SYS_EXIT_FCHDIR TraceId = 730
const SYS_ENTER_CHROOT TraceId = 729
const SYS_EXIT_CHROOT TraceId = 728
const SYS_ENTER_FCHMOD TraceId = 727
const SYS_EXIT_FCHMOD TraceId = 726
const SYS_ENTER_FCHMODAT2 TraceId = 725
const SYS_EXIT_FCHMODAT2 TraceId = 724
const SYS_ENTER_FCHMODAT TraceId = 723
const SYS_EXIT_FCHMODAT TraceId = 722
const SYS_ENTER_CHMOD TraceId = 721
const SYS_EXIT_CHMOD TraceId = 720
const SYS_ENTER_FCHOWNAT TraceId = 719
const SYS_EXIT_FCHOWNAT TraceId = 718
const SYS_ENTER_CHOWN TraceId = 717
const SYS_EXIT_CHOWN TraceId = 716
const SYS_ENTER_LCHOWN TraceId = 715
const SYS_EXIT_LCHOWN TraceId = 714
const SYS_ENTER_FCHOWN TraceId = 713
const SYS_EXIT_FCHOWN TraceId = 712
const SYS_ENTER_OPEN TraceId = 711
const SYS_EXIT_OPEN TraceId = 710
const SYS_ENTER_OPENAT TraceId = 709
const SYS_EXIT_OPENAT TraceId = 708
const SYS_ENTER_OPENAT2 TraceId = 707
const SYS_EXIT_OPENAT2 TraceId = 706
const SYS_ENTER_CREAT TraceId = 705
const SYS_EXIT_CREAT TraceId = 704
const SYS_ENTER_CLOSE TraceId = 703
const SYS_EXIT_CLOSE TraceId = 702
const SYS_ENTER_CLOSE_RANGE TraceId = 701
const SYS_EXIT_CLOSE_RANGE TraceId = 700
const SYS_ENTER_CACHESTAT TraceId = 528
const SYS_EXIT_CACHESTAT TraceId = 527
