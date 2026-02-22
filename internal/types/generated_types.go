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
	1515: "enter_io_uring_register", 1514: "exit_io_uring_register", 1496: "enter_io_uring_enter", 1495: "exit_io_uring_enter", 1494: "enter_io_uring_setup", 1493: "exit_io_uring_setup", 1151: "enter_quotactl_fd", 1150: "exit_quotactl_fd", 1135: "enter_name_to_handle_at", 1134: "exit_name_to_handle_at", 1133: "enter_open_by_handle_at", 1132: "exit_open_by_handle_at", 1119: "enter_flock", 1118: "exit_flock", 1105: "enter_io_setup", 1104: "exit_io_setup", 1103: "enter_io_destroy", 1102: "exit_io_destroy", 1101: "enter_io_submit", 1100: "exit_io_submit", 1099: "enter_io_cancel", 1098: "exit_io_cancel", 1097: "enter_io_getevents", 1096: "exit_io_getevents", 1095: "enter_io_pgetevents", 1094: "exit_io_pgetevents", 1063: "enter_fanotify_mark", 1062: "exit_fanotify_mark", 1053: "enter_file_getattr", 1052: "exit_file_getattr", 1051: "enter_file_setattr", 1050: "exit_file_setattr", 1047: "enter_fspick", 1046: "exit_fspick", 1045: "enter_fsconfig", 1044: "exit_fsconfig", 1043: "enter_statfs", 1042: "exit_statfs", 1041: "enter_fstatfs", 1040: "exit_fstatfs", 1035: "enter_utimensat", 1034: "exit_utimensat", 1033: "enter_futimesat", 1032: "exit_futimesat", 1027: "enter_sync", 1026: "exit_sync", 1025: "enter_syncfs", 1024: "exit_syncfs", 1023: "enter_fsync", 1022: "exit_fsync", 1021: "enter_fdatasync", 1020: "exit_fdatasync", 1019: "enter_sync_file_range", 1018: "exit_sync_file_range", 1017: "enter_vmsplice", 1016: "exit_vmsplice", 978: "enter_setxattrat", 977: "exit_setxattrat", 976: "enter_setxattr", 975: "exit_setxattr", 974: "enter_lsetxattr", 973: "exit_lsetxattr", 972: "enter_fsetxattr", 971: "exit_fsetxattr", 970: "enter_getxattrat", 969: "exit_getxattrat", 968: "enter_getxattr", 967: "exit_getxattr", 966: "enter_lgetxattr", 965: "exit_lgetxattr", 964: "enter_fgetxattr", 963: "exit_fgetxattr", 962: "enter_listxattrat", 961: "exit_listxattrat", 960: "enter_listxattr", 959: "exit_listxattr", 958: "enter_llistxattr", 957: "exit_llistxattr", 956: "enter_flistxattr", 955: "exit_flistxattr", 954: "enter_removexattrat", 953: "exit_removexattrat", 952: "enter_removexattr", 951: "exit_removexattr", 950: "enter_lremovexattr", 949: "exit_lremovexattr", 948: "enter_fremovexattr", 947: "exit_fremovexattr", 944: "enter_open_tree", 943: "exit_open_tree", 934: "enter_mount_setattr", 933: "exit_mount_setattr", 932: "enter_open_tree_attr", 931: "exit_open_tree_attr", 924: "enter_close_range", 923: "exit_close_range", 922: "enter_dup3", 921: "exit_dup3", 920: "enter_dup2", 919: "exit_dup2", 918: "enter_dup", 917: "exit_dup", 904: "enter_getdents", 903: "exit_getdents", 902: "enter_getdents64", 901: "exit_getdents64", 900: "enter_ioctl", 899: "exit_ioctl", 898: "enter_fcntl", 897: "exit_fcntl", 892: "enter_mkdirat", 891: "exit_mkdirat", 890: "enter_mkdir", 889: "exit_mkdir", 888: "enter_rmdir", 887: "exit_rmdir", 886: "enter_unlinkat", 885: "exit_unlinkat", 884: "enter_unlink", 883: "exit_unlink", 882: "enter_symlinkat", 881: "exit_symlinkat", 880: "enter_symlink", 879: "exit_symlink", 878: "enter_linkat", 877: "exit_linkat", 876: "enter_link", 875: "exit_link", 874: "enter_renameat2", 873: "exit_renameat2", 872: "enter_renameat", 871: "exit_renameat", 870: "enter_rename", 869: "exit_rename", 860: "enter_newstat", 859: "exit_newstat", 858: "enter_newlstat", 857: "exit_newlstat", 856: "enter_newfstatat", 855: "exit_newfstatat", 854: "enter_newfstat", 853: "exit_newfstat", 852: "enter_readlinkat", 851: "exit_readlinkat", 850: "enter_readlink", 849: "exit_readlink", 848: "enter_statx", 847: "exit_statx", 846: "enter_lseek", 845: "exit_lseek", 844: "enter_read", 843: "exit_read", 842: "enter_write", 841: "exit_write", 840: "enter_pread64", 839: "exit_pread64", 838: "enter_pwrite64", 837: "exit_pwrite64", 836: "enter_readv", 835: "exit_readv", 834: "enter_writev", 833: "exit_writev", 832: "enter_preadv", 831: "exit_preadv", 830: "enter_preadv2", 829: "exit_preadv2", 828: "enter_pwritev", 827: "exit_pwritev", 826: "enter_pwritev2", 825: "exit_pwritev2", 822: "enter_copy_file_range", 821: "exit_copy_file_range", 820: "enter_truncate", 819: "exit_truncate", 818: "enter_ftruncate", 817: "exit_ftruncate", 816: "enter_fallocate", 815: "exit_fallocate", 814: "enter_faccessat", 813: "exit_faccessat", 812: "enter_faccessat2", 811: "exit_faccessat2", 810: "enter_access", 809: "exit_access", 808: "enter_chdir", 807: "exit_chdir", 806: "enter_fchdir", 805: "exit_fchdir", 804: "enter_chroot", 803: "exit_chroot", 802: "enter_fchmod", 801: "exit_fchmod", 800: "enter_fchmodat2", 799: "exit_fchmodat2", 798: "enter_fchmodat", 797: "exit_fchmodat", 796: "enter_chmod", 795: "exit_chmod", 794: "enter_fchownat", 793: "exit_fchownat", 792: "enter_chown", 791: "exit_chown", 790: "enter_lchown", 789: "exit_lchown", 788: "enter_fchown", 787: "exit_fchown", 786: "enter_open", 785: "exit_open", 784: "enter_openat", 783: "exit_openat", 782: "enter_openat2", 781: "exit_openat2", 780: "enter_creat", 779: "exit_creat", 778: "enter_close", 777: "exit_close", 707: "enter_msync", 706: "exit_msync", 613: "enter_readahead", 612: "exit_readahead", 611: "enter_fadvise64", 610: "exit_fadvise64", 592: "enter_cachestat", 591: "exit_cachestat", 403: "enter_finit_module", 402: "exit_finit_module", 347: "enter_syslog", 346: "exit_syslog", 100: "enter_mmap", 99: "exit_mmap",
}

var traceId2Name = map[TraceId]string{
	1515: "io_uring_register", 1514: "io_uring_register", 1496: "io_uring_enter", 1495: "io_uring_enter", 1494: "io_uring_setup", 1493: "io_uring_setup", 1151: "quotactl_fd", 1150: "quotactl_fd", 1135: "name_to_handle_at", 1134: "name_to_handle_at", 1133: "open_by_handle_at", 1132: "open_by_handle_at", 1119: "flock", 1118: "flock", 1105: "io_setup", 1104: "io_setup", 1103: "io_destroy", 1102: "io_destroy", 1101: "io_submit", 1100: "io_submit", 1099: "io_cancel", 1098: "io_cancel", 1097: "io_getevents", 1096: "io_getevents", 1095: "io_pgetevents", 1094: "io_pgetevents", 1063: "fanotify_mark", 1062: "fanotify_mark", 1053: "file_getattr", 1052: "file_getattr", 1051: "file_setattr", 1050: "file_setattr", 1047: "fspick", 1046: "fspick", 1045: "fsconfig", 1044: "fsconfig", 1043: "statfs", 1042: "statfs", 1041: "fstatfs", 1040: "fstatfs", 1035: "utimensat", 1034: "utimensat", 1033: "futimesat", 1032: "futimesat", 1027: "sync", 1026: "sync", 1025: "syncfs", 1024: "syncfs", 1023: "fsync", 1022: "fsync", 1021: "fdatasync", 1020: "fdatasync", 1019: "sync_file_range", 1018: "sync_file_range", 1017: "vmsplice", 1016: "vmsplice", 978: "setxattrat", 977: "setxattrat", 976: "setxattr", 975: "setxattr", 974: "lsetxattr", 973: "lsetxattr", 972: "fsetxattr", 971: "fsetxattr", 970: "getxattrat", 969: "getxattrat", 968: "getxattr", 967: "getxattr", 966: "lgetxattr", 965: "lgetxattr", 964: "fgetxattr", 963: "fgetxattr", 962: "listxattrat", 961: "listxattrat", 960: "listxattr", 959: "listxattr", 958: "llistxattr", 957: "llistxattr", 956: "flistxattr", 955: "flistxattr", 954: "removexattrat", 953: "removexattrat", 952: "removexattr", 951: "removexattr", 950: "lremovexattr", 949: "lremovexattr", 948: "fremovexattr", 947: "fremovexattr", 944: "open_tree", 943: "open_tree", 934: "mount_setattr", 933: "mount_setattr", 932: "open_tree_attr", 931: "open_tree_attr", 924: "close_range", 923: "close_range", 922: "dup3", 921: "dup3", 920: "dup2", 919: "dup2", 918: "dup", 917: "dup", 904: "getdents", 903: "getdents", 902: "getdents64", 901: "getdents64", 900: "ioctl", 899: "ioctl", 898: "fcntl", 897: "fcntl", 892: "mkdirat", 891: "mkdirat", 890: "mkdir", 889: "mkdir", 888: "rmdir", 887: "rmdir", 886: "unlinkat", 885: "unlinkat", 884: "unlink", 883: "unlink", 882: "symlinkat", 881: "symlinkat", 880: "symlink", 879: "symlink", 878: "linkat", 877: "linkat", 876: "link", 875: "link", 874: "renameat2", 873: "renameat2", 872: "renameat", 871: "renameat", 870: "rename", 869: "rename", 860: "newstat", 859: "newstat", 858: "newlstat", 857: "newlstat", 856: "newfstatat", 855: "newfstatat", 854: "newfstat", 853: "newfstat", 852: "readlinkat", 851: "readlinkat", 850: "readlink", 849: "readlink", 848: "statx", 847: "statx", 846: "lseek", 845: "lseek", 844: "read", 843: "read", 842: "write", 841: "write", 840: "pread64", 839: "pread64", 838: "pwrite64", 837: "pwrite64", 836: "readv", 835: "readv", 834: "writev", 833: "writev", 832: "preadv", 831: "preadv", 830: "preadv2", 829: "preadv2", 828: "pwritev", 827: "pwritev", 826: "pwritev2", 825: "pwritev2", 822: "copy_file_range", 821: "copy_file_range", 820: "truncate", 819: "truncate", 818: "ftruncate", 817: "ftruncate", 816: "fallocate", 815: "fallocate", 814: "faccessat", 813: "faccessat", 812: "faccessat2", 811: "faccessat2", 810: "access", 809: "access", 808: "chdir", 807: "chdir", 806: "fchdir", 805: "fchdir", 804: "chroot", 803: "chroot", 802: "fchmod", 801: "fchmod", 800: "fchmodat2", 799: "fchmodat2", 798: "fchmodat", 797: "fchmodat", 796: "chmod", 795: "chmod", 794: "fchownat", 793: "fchownat", 792: "chown", 791: "chown", 790: "lchown", 789: "lchown", 788: "fchown", 787: "fchown", 786: "open", 785: "open", 784: "openat", 783: "openat", 782: "openat2", 781: "openat2", 780: "creat", 779: "creat", 778: "close", 777: "close", 707: "msync", 706: "msync", 613: "readahead", 612: "readahead", 611: "fadvise64", 610: "fadvise64", 592: "cachestat", 591: "cachestat", 403: "finit_module", 402: "finit_module", 347: "syslog", 346: "syslog", 100: "mmap", 99: "mmap",
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
const ENTER_OPEN_BY_HANDLE_AT_EVENT = 17
const EXIT_OPEN_BY_HANDLE_AT_EVENT = 18
const UNCLASSIFIED = 0
const READ_CLASSIFIED = 1
const WRITE_CLASSIFIED = 2
const TRANSFER_CLASSIFIED = 3
const SYS_ENTER_IO_URING_REGISTER TraceId = 1515
const SYS_EXIT_IO_URING_REGISTER TraceId = 1514
const SYS_ENTER_IO_URING_ENTER TraceId = 1496
const SYS_EXIT_IO_URING_ENTER TraceId = 1495
const SYS_ENTER_IO_URING_SETUP TraceId = 1494
const SYS_EXIT_IO_URING_SETUP TraceId = 1493
const SYS_ENTER_QUOTACTL_FD TraceId = 1151
const SYS_EXIT_QUOTACTL_FD TraceId = 1150
const SYS_ENTER_NAME_TO_HANDLE_AT TraceId = 1135
const SYS_EXIT_NAME_TO_HANDLE_AT TraceId = 1134
const SYS_ENTER_OPEN_BY_HANDLE_AT TraceId = 1133
const SYS_EXIT_OPEN_BY_HANDLE_AT TraceId = 1132
const SYS_ENTER_FLOCK TraceId = 1119
const SYS_EXIT_FLOCK TraceId = 1118
const SYS_ENTER_IO_SETUP TraceId = 1105
const SYS_EXIT_IO_SETUP TraceId = 1104
const SYS_ENTER_IO_DESTROY TraceId = 1103
const SYS_EXIT_IO_DESTROY TraceId = 1102
const SYS_ENTER_IO_SUBMIT TraceId = 1101
const SYS_EXIT_IO_SUBMIT TraceId = 1100
const SYS_ENTER_IO_CANCEL TraceId = 1099
const SYS_EXIT_IO_CANCEL TraceId = 1098
const SYS_ENTER_IO_GETEVENTS TraceId = 1097
const SYS_EXIT_IO_GETEVENTS TraceId = 1096
const SYS_ENTER_IO_PGETEVENTS TraceId = 1095
const SYS_EXIT_IO_PGETEVENTS TraceId = 1094
const SYS_ENTER_FANOTIFY_MARK TraceId = 1063
const SYS_EXIT_FANOTIFY_MARK TraceId = 1062
const SYS_ENTER_FILE_GETATTR TraceId = 1053
const SYS_EXIT_FILE_GETATTR TraceId = 1052
const SYS_ENTER_FILE_SETATTR TraceId = 1051
const SYS_EXIT_FILE_SETATTR TraceId = 1050
const SYS_ENTER_FSPICK TraceId = 1047
const SYS_EXIT_FSPICK TraceId = 1046
const SYS_ENTER_FSCONFIG TraceId = 1045
const SYS_EXIT_FSCONFIG TraceId = 1044
const SYS_ENTER_STATFS TraceId = 1043
const SYS_EXIT_STATFS TraceId = 1042
const SYS_ENTER_FSTATFS TraceId = 1041
const SYS_EXIT_FSTATFS TraceId = 1040
const SYS_ENTER_UTIMENSAT TraceId = 1035
const SYS_EXIT_UTIMENSAT TraceId = 1034
const SYS_ENTER_FUTIMESAT TraceId = 1033
const SYS_EXIT_FUTIMESAT TraceId = 1032
const SYS_ENTER_SYNC TraceId = 1027
const SYS_EXIT_SYNC TraceId = 1026
const SYS_ENTER_SYNCFS TraceId = 1025
const SYS_EXIT_SYNCFS TraceId = 1024
const SYS_ENTER_FSYNC TraceId = 1023
const SYS_EXIT_FSYNC TraceId = 1022
const SYS_ENTER_FDATASYNC TraceId = 1021
const SYS_EXIT_FDATASYNC TraceId = 1020
const SYS_ENTER_SYNC_FILE_RANGE TraceId = 1019
const SYS_EXIT_SYNC_FILE_RANGE TraceId = 1018
const SYS_ENTER_VMSPLICE TraceId = 1017
const SYS_EXIT_VMSPLICE TraceId = 1016
const SYS_ENTER_SETXATTRAT TraceId = 978
const SYS_EXIT_SETXATTRAT TraceId = 977
const SYS_ENTER_SETXATTR TraceId = 976
const SYS_EXIT_SETXATTR TraceId = 975
const SYS_ENTER_LSETXATTR TraceId = 974
const SYS_EXIT_LSETXATTR TraceId = 973
const SYS_ENTER_FSETXATTR TraceId = 972
const SYS_EXIT_FSETXATTR TraceId = 971
const SYS_ENTER_GETXATTRAT TraceId = 970
const SYS_EXIT_GETXATTRAT TraceId = 969
const SYS_ENTER_GETXATTR TraceId = 968
const SYS_EXIT_GETXATTR TraceId = 967
const SYS_ENTER_LGETXATTR TraceId = 966
const SYS_EXIT_LGETXATTR TraceId = 965
const SYS_ENTER_FGETXATTR TraceId = 964
const SYS_EXIT_FGETXATTR TraceId = 963
const SYS_ENTER_LISTXATTRAT TraceId = 962
const SYS_EXIT_LISTXATTRAT TraceId = 961
const SYS_ENTER_LISTXATTR TraceId = 960
const SYS_EXIT_LISTXATTR TraceId = 959
const SYS_ENTER_LLISTXATTR TraceId = 958
const SYS_EXIT_LLISTXATTR TraceId = 957
const SYS_ENTER_FLISTXATTR TraceId = 956
const SYS_EXIT_FLISTXATTR TraceId = 955
const SYS_ENTER_REMOVEXATTRAT TraceId = 954
const SYS_EXIT_REMOVEXATTRAT TraceId = 953
const SYS_ENTER_REMOVEXATTR TraceId = 952
const SYS_EXIT_REMOVEXATTR TraceId = 951
const SYS_ENTER_LREMOVEXATTR TraceId = 950
const SYS_EXIT_LREMOVEXATTR TraceId = 949
const SYS_ENTER_FREMOVEXATTR TraceId = 948
const SYS_EXIT_FREMOVEXATTR TraceId = 947
const SYS_ENTER_OPEN_TREE TraceId = 944
const SYS_EXIT_OPEN_TREE TraceId = 943
const SYS_ENTER_MOUNT_SETATTR TraceId = 934
const SYS_EXIT_MOUNT_SETATTR TraceId = 933
const SYS_ENTER_OPEN_TREE_ATTR TraceId = 932
const SYS_EXIT_OPEN_TREE_ATTR TraceId = 931
const SYS_ENTER_CLOSE_RANGE TraceId = 924
const SYS_EXIT_CLOSE_RANGE TraceId = 923
const SYS_ENTER_DUP3 TraceId = 922
const SYS_EXIT_DUP3 TraceId = 921
const SYS_ENTER_DUP2 TraceId = 920
const SYS_EXIT_DUP2 TraceId = 919
const SYS_ENTER_DUP TraceId = 918
const SYS_EXIT_DUP TraceId = 917
const SYS_ENTER_GETDENTS TraceId = 904
const SYS_EXIT_GETDENTS TraceId = 903
const SYS_ENTER_GETDENTS64 TraceId = 902
const SYS_EXIT_GETDENTS64 TraceId = 901
const SYS_ENTER_IOCTL TraceId = 900
const SYS_EXIT_IOCTL TraceId = 899
const SYS_ENTER_FCNTL TraceId = 898
const SYS_EXIT_FCNTL TraceId = 897
const SYS_ENTER_MKDIRAT TraceId = 892
const SYS_EXIT_MKDIRAT TraceId = 891
const SYS_ENTER_MKDIR TraceId = 890
const SYS_EXIT_MKDIR TraceId = 889
const SYS_ENTER_RMDIR TraceId = 888
const SYS_EXIT_RMDIR TraceId = 887
const SYS_ENTER_UNLINKAT TraceId = 886
const SYS_EXIT_UNLINKAT TraceId = 885
const SYS_ENTER_UNLINK TraceId = 884
const SYS_EXIT_UNLINK TraceId = 883
const SYS_ENTER_SYMLINKAT TraceId = 882
const SYS_EXIT_SYMLINKAT TraceId = 881
const SYS_ENTER_SYMLINK TraceId = 880
const SYS_EXIT_SYMLINK TraceId = 879
const SYS_ENTER_LINKAT TraceId = 878
const SYS_EXIT_LINKAT TraceId = 877
const SYS_ENTER_LINK TraceId = 876
const SYS_EXIT_LINK TraceId = 875
const SYS_ENTER_RENAMEAT2 TraceId = 874
const SYS_EXIT_RENAMEAT2 TraceId = 873
const SYS_ENTER_RENAMEAT TraceId = 872
const SYS_EXIT_RENAMEAT TraceId = 871
const SYS_ENTER_RENAME TraceId = 870
const SYS_EXIT_RENAME TraceId = 869
const SYS_ENTER_NEWSTAT TraceId = 860
const SYS_EXIT_NEWSTAT TraceId = 859
const SYS_ENTER_NEWLSTAT TraceId = 858
const SYS_EXIT_NEWLSTAT TraceId = 857
const SYS_ENTER_NEWFSTATAT TraceId = 856
const SYS_EXIT_NEWFSTATAT TraceId = 855
const SYS_ENTER_NEWFSTAT TraceId = 854
const SYS_EXIT_NEWFSTAT TraceId = 853
const SYS_ENTER_READLINKAT TraceId = 852
const SYS_EXIT_READLINKAT TraceId = 851
const SYS_ENTER_READLINK TraceId = 850
const SYS_EXIT_READLINK TraceId = 849
const SYS_ENTER_STATX TraceId = 848
const SYS_EXIT_STATX TraceId = 847
const SYS_ENTER_LSEEK TraceId = 846
const SYS_EXIT_LSEEK TraceId = 845
const SYS_ENTER_READ TraceId = 844
const SYS_EXIT_READ TraceId = 843
const SYS_ENTER_WRITE TraceId = 842
const SYS_EXIT_WRITE TraceId = 841
const SYS_ENTER_PREAD64 TraceId = 840
const SYS_EXIT_PREAD64 TraceId = 839
const SYS_ENTER_PWRITE64 TraceId = 838
const SYS_EXIT_PWRITE64 TraceId = 837
const SYS_ENTER_READV TraceId = 836
const SYS_EXIT_READV TraceId = 835
const SYS_ENTER_WRITEV TraceId = 834
const SYS_EXIT_WRITEV TraceId = 833
const SYS_ENTER_PREADV TraceId = 832
const SYS_EXIT_PREADV TraceId = 831
const SYS_ENTER_PREADV2 TraceId = 830
const SYS_EXIT_PREADV2 TraceId = 829
const SYS_ENTER_PWRITEV TraceId = 828
const SYS_EXIT_PWRITEV TraceId = 827
const SYS_ENTER_PWRITEV2 TraceId = 826
const SYS_EXIT_PWRITEV2 TraceId = 825
const SYS_ENTER_COPY_FILE_RANGE TraceId = 822
const SYS_EXIT_COPY_FILE_RANGE TraceId = 821
const SYS_ENTER_TRUNCATE TraceId = 820
const SYS_EXIT_TRUNCATE TraceId = 819
const SYS_ENTER_FTRUNCATE TraceId = 818
const SYS_EXIT_FTRUNCATE TraceId = 817
const SYS_ENTER_FALLOCATE TraceId = 816
const SYS_EXIT_FALLOCATE TraceId = 815
const SYS_ENTER_FACCESSAT TraceId = 814
const SYS_EXIT_FACCESSAT TraceId = 813
const SYS_ENTER_FACCESSAT2 TraceId = 812
const SYS_EXIT_FACCESSAT2 TraceId = 811
const SYS_ENTER_ACCESS TraceId = 810
const SYS_EXIT_ACCESS TraceId = 809
const SYS_ENTER_CHDIR TraceId = 808
const SYS_EXIT_CHDIR TraceId = 807
const SYS_ENTER_FCHDIR TraceId = 806
const SYS_EXIT_FCHDIR TraceId = 805
const SYS_ENTER_CHROOT TraceId = 804
const SYS_EXIT_CHROOT TraceId = 803
const SYS_ENTER_FCHMOD TraceId = 802
const SYS_EXIT_FCHMOD TraceId = 801
const SYS_ENTER_FCHMODAT2 TraceId = 800
const SYS_EXIT_FCHMODAT2 TraceId = 799
const SYS_ENTER_FCHMODAT TraceId = 798
const SYS_EXIT_FCHMODAT TraceId = 797
const SYS_ENTER_CHMOD TraceId = 796
const SYS_EXIT_CHMOD TraceId = 795
const SYS_ENTER_FCHOWNAT TraceId = 794
const SYS_EXIT_FCHOWNAT TraceId = 793
const SYS_ENTER_CHOWN TraceId = 792
const SYS_EXIT_CHOWN TraceId = 791
const SYS_ENTER_LCHOWN TraceId = 790
const SYS_EXIT_LCHOWN TraceId = 789
const SYS_ENTER_FCHOWN TraceId = 788
const SYS_EXIT_FCHOWN TraceId = 787
const SYS_ENTER_OPEN TraceId = 786
const SYS_EXIT_OPEN TraceId = 785
const SYS_ENTER_OPENAT TraceId = 784
const SYS_EXIT_OPENAT TraceId = 783
const SYS_ENTER_OPENAT2 TraceId = 782
const SYS_EXIT_OPENAT2 TraceId = 781
const SYS_ENTER_CREAT TraceId = 780
const SYS_EXIT_CREAT TraceId = 779
const SYS_ENTER_CLOSE TraceId = 778
const SYS_EXIT_CLOSE TraceId = 777
const SYS_ENTER_MSYNC TraceId = 707
const SYS_EXIT_MSYNC TraceId = 706
const SYS_ENTER_READAHEAD TraceId = 613
const SYS_EXIT_READAHEAD TraceId = 612
const SYS_ENTER_FADVISE64 TraceId = 611
const SYS_EXIT_FADVISE64 TraceId = 610
const SYS_ENTER_CACHESTAT TraceId = 592
const SYS_EXIT_CACHESTAT TraceId = 591
const SYS_ENTER_FINIT_MODULE TraceId = 403
const SYS_EXIT_FINIT_MODULE TraceId = 402
const SYS_ENTER_SYSLOG TraceId = 347
const SYS_EXIT_SYSLOG TraceId = 346
const SYS_ENTER_MMAP TraceId = 100
const SYS_EXIT_MMAP TraceId = 99

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

type OpenByHandleAtEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Flags     int32
}

func (o OpenByHandleAtEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Flags:%v", o.EventType, o.TraceId, o.Time, o.Pid, o.Tid, o.Flags)
}

func (o OpenByHandleAtEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*OpenByHandleAtEvent)
	if !ok {
		return false
	}
	return o.EventType == otherConcrete.EventType && o.TraceId == otherConcrete.TraceId && o.Time == otherConcrete.Time && o.Pid == otherConcrete.Pid && o.Tid == otherConcrete.Tid && o.Flags == otherConcrete.Flags
}

func (o *OpenByHandleAtEvent) GetEventType() EventType {
	return o.EventType
}

func (o *OpenByHandleAtEvent) GetTraceId() TraceId {
	return o.TraceId
}

func (o *OpenByHandleAtEvent) GetPid() uint32 {
	return o.Pid
}

func (o *OpenByHandleAtEvent) GetTid() uint32 {
	return o.Tid
}

func (o *OpenByHandleAtEvent) GetTime() uint64 {
	return o.Time
}

var poolOfOpenByHandleAtEvents = sync.Pool{
	New: func() interface{} { return &OpenByHandleAtEvent{} },
}

func NewOpenByHandleAtEvent(raw []byte) *OpenByHandleAtEvent {
	o := poolOfOpenByHandleAtEvents.Get().(*OpenByHandleAtEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, o); err != nil {
		fmt.Println(o, raw, len(raw), err)
		panic(raw)
	}
	return o
}

func (o *OpenByHandleAtEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, o)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (o *OpenByHandleAtEvent) Recycle() {
	poolOfOpenByHandleAtEvents.Put(o)
}
