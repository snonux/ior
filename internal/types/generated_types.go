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
	1521: "enter_io_uring_register", 1520: "exit_io_uring_register", 1502: "enter_io_uring_enter", 1501: "exit_io_uring_enter", 1500: "enter_io_uring_setup", 1499: "exit_io_uring_setup", 1155: "enter_quotactl_fd", 1154: "exit_quotactl_fd", 1139: "enter_name_to_handle_at", 1138: "exit_name_to_handle_at", 1137: "enter_open_by_handle_at", 1136: "exit_open_by_handle_at", 1123: "enter_flock", 1122: "exit_flock", 1109: "enter_io_setup", 1108: "exit_io_setup", 1107: "enter_io_destroy", 1106: "exit_io_destroy", 1105: "enter_io_submit", 1104: "exit_io_submit", 1103: "enter_io_cancel", 1102: "exit_io_cancel", 1101: "enter_io_getevents", 1100: "exit_io_getevents", 1099: "enter_io_pgetevents", 1098: "exit_io_pgetevents", 1067: "enter_fanotify_mark", 1066: "exit_fanotify_mark", 1057: "enter_file_getattr", 1056: "exit_file_getattr", 1055: "enter_file_setattr", 1054: "exit_file_setattr", 1051: "enter_fspick", 1050: "exit_fspick", 1049: "enter_fsconfig", 1048: "exit_fsconfig", 1047: "enter_statfs", 1046: "exit_statfs", 1045: "enter_fstatfs", 1044: "exit_fstatfs", 1041: "enter_getcwd", 1040: "exit_getcwd", 1039: "enter_utimensat", 1038: "exit_utimensat", 1037: "enter_futimesat", 1036: "exit_futimesat", 1031: "enter_sync", 1030: "exit_sync", 1029: "enter_syncfs", 1028: "exit_syncfs", 1027: "enter_fsync", 1026: "exit_fsync", 1025: "enter_fdatasync", 1024: "exit_fdatasync", 1023: "enter_sync_file_range", 1022: "exit_sync_file_range", 1021: "enter_vmsplice", 1020: "exit_vmsplice", 982: "enter_setxattrat", 981: "exit_setxattrat", 980: "enter_setxattr", 979: "exit_setxattr", 978: "enter_lsetxattr", 977: "exit_lsetxattr", 976: "enter_fsetxattr", 975: "exit_fsetxattr", 974: "enter_getxattrat", 973: "exit_getxattrat", 972: "enter_getxattr", 971: "exit_getxattr", 970: "enter_lgetxattr", 969: "exit_lgetxattr", 968: "enter_fgetxattr", 967: "exit_fgetxattr", 966: "enter_listxattrat", 965: "exit_listxattrat", 964: "enter_listxattr", 963: "exit_listxattr", 962: "enter_llistxattr", 961: "exit_llistxattr", 960: "enter_flistxattr", 959: "exit_flistxattr", 958: "enter_removexattrat", 957: "exit_removexattrat", 956: "enter_removexattr", 955: "exit_removexattr", 954: "enter_lremovexattr", 953: "exit_lremovexattr", 952: "enter_fremovexattr", 951: "exit_fremovexattr", 948: "enter_open_tree", 947: "exit_open_tree", 938: "enter_mount_setattr", 937: "exit_mount_setattr", 936: "enter_open_tree_attr", 935: "exit_open_tree_attr", 928: "enter_close_range", 927: "exit_close_range", 926: "enter_dup3", 925: "exit_dup3", 924: "enter_dup2", 923: "exit_dup2", 922: "enter_dup", 921: "exit_dup", 908: "enter_getdents", 907: "exit_getdents", 906: "enter_getdents64", 905: "exit_getdents64", 904: "enter_ioctl", 903: "exit_ioctl", 902: "enter_fcntl", 901: "exit_fcntl", 896: "enter_mkdirat", 895: "exit_mkdirat", 894: "enter_mkdir", 893: "exit_mkdir", 892: "enter_rmdir", 891: "exit_rmdir", 890: "enter_unlinkat", 889: "exit_unlinkat", 888: "enter_unlink", 887: "exit_unlink", 886: "enter_symlinkat", 885: "exit_symlinkat", 884: "enter_symlink", 883: "exit_symlink", 882: "enter_linkat", 881: "exit_linkat", 880: "enter_link", 879: "exit_link", 878: "enter_renameat2", 877: "exit_renameat2", 876: "enter_renameat", 875: "exit_renameat", 874: "enter_rename", 873: "exit_rename", 864: "enter_newstat", 863: "exit_newstat", 862: "enter_newlstat", 861: "exit_newlstat", 860: "enter_newfstatat", 859: "exit_newfstatat", 858: "enter_newfstat", 857: "exit_newfstat", 856: "enter_readlinkat", 855: "exit_readlinkat", 854: "enter_readlink", 853: "exit_readlink", 852: "enter_statx", 851: "exit_statx", 850: "enter_lseek", 849: "exit_lseek", 848: "enter_read", 847: "exit_read", 846: "enter_write", 845: "exit_write", 844: "enter_pread64", 843: "exit_pread64", 842: "enter_pwrite64", 841: "exit_pwrite64", 840: "enter_readv", 839: "exit_readv", 838: "enter_writev", 837: "exit_writev", 836: "enter_preadv", 835: "exit_preadv", 834: "enter_preadv2", 833: "exit_preadv2", 832: "enter_pwritev", 831: "exit_pwritev", 830: "enter_pwritev2", 829: "exit_pwritev2", 826: "enter_copy_file_range", 825: "exit_copy_file_range", 824: "enter_truncate", 823: "exit_truncate", 822: "enter_ftruncate", 821: "exit_ftruncate", 820: "enter_fallocate", 819: "exit_fallocate", 818: "enter_faccessat", 817: "exit_faccessat", 816: "enter_faccessat2", 815: "exit_faccessat2", 814: "enter_access", 813: "exit_access", 812: "enter_chdir", 811: "exit_chdir", 810: "enter_fchdir", 809: "exit_fchdir", 808: "enter_chroot", 807: "exit_chroot", 806: "enter_fchmod", 805: "exit_fchmod", 804: "enter_fchmodat2", 803: "exit_fchmodat2", 802: "enter_fchmodat", 801: "exit_fchmodat", 800: "enter_chmod", 799: "exit_chmod", 798: "enter_fchownat", 797: "exit_fchownat", 796: "enter_chown", 795: "exit_chown", 794: "enter_lchown", 793: "exit_lchown", 792: "enter_fchown", 791: "exit_fchown", 790: "enter_open", 789: "exit_open", 788: "enter_openat", 787: "exit_openat", 786: "enter_openat2", 785: "exit_openat2", 784: "enter_creat", 783: "exit_creat", 782: "enter_close", 781: "exit_close", 710: "enter_msync", 709: "exit_msync", 616: "enter_readahead", 615: "exit_readahead", 614: "enter_fadvise64", 613: "exit_fadvise64", 595: "enter_cachestat", 594: "exit_cachestat", 406: "enter_finit_module", 405: "exit_finit_module", 350: "enter_syslog", 349: "exit_syslog", 271: "enter_pidfd_getfd", 270: "exit_pidfd_getfd", 100: "enter_mmap", 99: "exit_mmap",
}

var traceId2Name = map[TraceId]string{
	1521: "io_uring_register", 1520: "io_uring_register", 1502: "io_uring_enter", 1501: "io_uring_enter", 1500: "io_uring_setup", 1499: "io_uring_setup", 1155: "quotactl_fd", 1154: "quotactl_fd", 1139: "name_to_handle_at", 1138: "name_to_handle_at", 1137: "open_by_handle_at", 1136: "open_by_handle_at", 1123: "flock", 1122: "flock", 1109: "io_setup", 1108: "io_setup", 1107: "io_destroy", 1106: "io_destroy", 1105: "io_submit", 1104: "io_submit", 1103: "io_cancel", 1102: "io_cancel", 1101: "io_getevents", 1100: "io_getevents", 1099: "io_pgetevents", 1098: "io_pgetevents", 1067: "fanotify_mark", 1066: "fanotify_mark", 1057: "file_getattr", 1056: "file_getattr", 1055: "file_setattr", 1054: "file_setattr", 1051: "fspick", 1050: "fspick", 1049: "fsconfig", 1048: "fsconfig", 1047: "statfs", 1046: "statfs", 1045: "fstatfs", 1044: "fstatfs", 1041: "getcwd", 1040: "getcwd", 1039: "utimensat", 1038: "utimensat", 1037: "futimesat", 1036: "futimesat", 1031: "sync", 1030: "sync", 1029: "syncfs", 1028: "syncfs", 1027: "fsync", 1026: "fsync", 1025: "fdatasync", 1024: "fdatasync", 1023: "sync_file_range", 1022: "sync_file_range", 1021: "vmsplice", 1020: "vmsplice", 982: "setxattrat", 981: "setxattrat", 980: "setxattr", 979: "setxattr", 978: "lsetxattr", 977: "lsetxattr", 976: "fsetxattr", 975: "fsetxattr", 974: "getxattrat", 973: "getxattrat", 972: "getxattr", 971: "getxattr", 970: "lgetxattr", 969: "lgetxattr", 968: "fgetxattr", 967: "fgetxattr", 966: "listxattrat", 965: "listxattrat", 964: "listxattr", 963: "listxattr", 962: "llistxattr", 961: "llistxattr", 960: "flistxattr", 959: "flistxattr", 958: "removexattrat", 957: "removexattrat", 956: "removexattr", 955: "removexattr", 954: "lremovexattr", 953: "lremovexattr", 952: "fremovexattr", 951: "fremovexattr", 948: "open_tree", 947: "open_tree", 938: "mount_setattr", 937: "mount_setattr", 936: "open_tree_attr", 935: "open_tree_attr", 928: "close_range", 927: "close_range", 926: "dup3", 925: "dup3", 924: "dup2", 923: "dup2", 922: "dup", 921: "dup", 908: "getdents", 907: "getdents", 906: "getdents64", 905: "getdents64", 904: "ioctl", 903: "ioctl", 902: "fcntl", 901: "fcntl", 896: "mkdirat", 895: "mkdirat", 894: "mkdir", 893: "mkdir", 892: "rmdir", 891: "rmdir", 890: "unlinkat", 889: "unlinkat", 888: "unlink", 887: "unlink", 886: "symlinkat", 885: "symlinkat", 884: "symlink", 883: "symlink", 882: "linkat", 881: "linkat", 880: "link", 879: "link", 878: "renameat2", 877: "renameat2", 876: "renameat", 875: "renameat", 874: "rename", 873: "rename", 864: "newstat", 863: "newstat", 862: "newlstat", 861: "newlstat", 860: "newfstatat", 859: "newfstatat", 858: "newfstat", 857: "newfstat", 856: "readlinkat", 855: "readlinkat", 854: "readlink", 853: "readlink", 852: "statx", 851: "statx", 850: "lseek", 849: "lseek", 848: "read", 847: "read", 846: "write", 845: "write", 844: "pread64", 843: "pread64", 842: "pwrite64", 841: "pwrite64", 840: "readv", 839: "readv", 838: "writev", 837: "writev", 836: "preadv", 835: "preadv", 834: "preadv2", 833: "preadv2", 832: "pwritev", 831: "pwritev", 830: "pwritev2", 829: "pwritev2", 826: "copy_file_range", 825: "copy_file_range", 824: "truncate", 823: "truncate", 822: "ftruncate", 821: "ftruncate", 820: "fallocate", 819: "fallocate", 818: "faccessat", 817: "faccessat", 816: "faccessat2", 815: "faccessat2", 814: "access", 813: "access", 812: "chdir", 811: "chdir", 810: "fchdir", 809: "fchdir", 808: "chroot", 807: "chroot", 806: "fchmod", 805: "fchmod", 804: "fchmodat2", 803: "fchmodat2", 802: "fchmodat", 801: "fchmodat", 800: "chmod", 799: "chmod", 798: "fchownat", 797: "fchownat", 796: "chown", 795: "chown", 794: "lchown", 793: "lchown", 792: "fchown", 791: "fchown", 790: "open", 789: "open", 788: "openat", 787: "openat", 786: "openat2", 785: "openat2", 784: "creat", 783: "creat", 782: "close", 781: "close", 710: "msync", 709: "msync", 616: "readahead", 615: "readahead", 614: "fadvise64", 613: "fadvise64", 595: "cachestat", 594: "cachestat", 406: "finit_module", 405: "finit_module", 350: "syslog", 349: "syslog", 271: "pidfd_getfd", 270: "pidfd_getfd", 100: "mmap", 99: "mmap",
}

func (s TraceId) String() string {
	str, ok := traceId2String[s]
	if !ok {
		return fmt.Sprintf("unknown_trace_id_%d", s)
	}
	return str
}

func (s TraceId) Name() string {
	str, ok := traceId2Name[s]
	if !ok {
		return fmt.Sprintf("unknown_trace_id_%d", s)
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
const SYS_ENTER_IO_URING_REGISTER TraceId = 1521
const SYS_EXIT_IO_URING_REGISTER TraceId = 1520
const SYS_ENTER_IO_URING_ENTER TraceId = 1502
const SYS_EXIT_IO_URING_ENTER TraceId = 1501
const SYS_ENTER_IO_URING_SETUP TraceId = 1500
const SYS_EXIT_IO_URING_SETUP TraceId = 1499
const SYS_ENTER_QUOTACTL_FD TraceId = 1155
const SYS_EXIT_QUOTACTL_FD TraceId = 1154
const SYS_ENTER_NAME_TO_HANDLE_AT TraceId = 1139
const SYS_EXIT_NAME_TO_HANDLE_AT TraceId = 1138
const SYS_ENTER_OPEN_BY_HANDLE_AT TraceId = 1137
const SYS_EXIT_OPEN_BY_HANDLE_AT TraceId = 1136
const SYS_ENTER_FLOCK TraceId = 1123
const SYS_EXIT_FLOCK TraceId = 1122
const SYS_ENTER_IO_SETUP TraceId = 1109
const SYS_EXIT_IO_SETUP TraceId = 1108
const SYS_ENTER_IO_DESTROY TraceId = 1107
const SYS_EXIT_IO_DESTROY TraceId = 1106
const SYS_ENTER_IO_SUBMIT TraceId = 1105
const SYS_EXIT_IO_SUBMIT TraceId = 1104
const SYS_ENTER_IO_CANCEL TraceId = 1103
const SYS_EXIT_IO_CANCEL TraceId = 1102
const SYS_ENTER_IO_GETEVENTS TraceId = 1101
const SYS_EXIT_IO_GETEVENTS TraceId = 1100
const SYS_ENTER_IO_PGETEVENTS TraceId = 1099
const SYS_EXIT_IO_PGETEVENTS TraceId = 1098
const SYS_ENTER_FANOTIFY_MARK TraceId = 1067
const SYS_EXIT_FANOTIFY_MARK TraceId = 1066
const SYS_ENTER_FILE_GETATTR TraceId = 1057
const SYS_EXIT_FILE_GETATTR TraceId = 1056
const SYS_ENTER_FILE_SETATTR TraceId = 1055
const SYS_EXIT_FILE_SETATTR TraceId = 1054
const SYS_ENTER_FSPICK TraceId = 1051
const SYS_EXIT_FSPICK TraceId = 1050
const SYS_ENTER_FSCONFIG TraceId = 1049
const SYS_EXIT_FSCONFIG TraceId = 1048
const SYS_ENTER_STATFS TraceId = 1047
const SYS_EXIT_STATFS TraceId = 1046
const SYS_ENTER_FSTATFS TraceId = 1045
const SYS_EXIT_FSTATFS TraceId = 1044
const SYS_ENTER_GETCWD TraceId = 1041
const SYS_EXIT_GETCWD TraceId = 1040
const SYS_ENTER_UTIMENSAT TraceId = 1039
const SYS_EXIT_UTIMENSAT TraceId = 1038
const SYS_ENTER_FUTIMESAT TraceId = 1037
const SYS_EXIT_FUTIMESAT TraceId = 1036
const SYS_ENTER_SYNC TraceId = 1031
const SYS_EXIT_SYNC TraceId = 1030
const SYS_ENTER_SYNCFS TraceId = 1029
const SYS_EXIT_SYNCFS TraceId = 1028
const SYS_ENTER_FSYNC TraceId = 1027
const SYS_EXIT_FSYNC TraceId = 1026
const SYS_ENTER_FDATASYNC TraceId = 1025
const SYS_EXIT_FDATASYNC TraceId = 1024
const SYS_ENTER_SYNC_FILE_RANGE TraceId = 1023
const SYS_EXIT_SYNC_FILE_RANGE TraceId = 1022
const SYS_ENTER_VMSPLICE TraceId = 1021
const SYS_EXIT_VMSPLICE TraceId = 1020
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
const SYS_ENTER_OPEN_TREE_ATTR TraceId = 936
const SYS_EXIT_OPEN_TREE_ATTR TraceId = 935
const SYS_ENTER_CLOSE_RANGE TraceId = 928
const SYS_EXIT_CLOSE_RANGE TraceId = 927
const SYS_ENTER_DUP3 TraceId = 926
const SYS_EXIT_DUP3 TraceId = 925
const SYS_ENTER_DUP2 TraceId = 924
const SYS_EXIT_DUP2 TraceId = 923
const SYS_ENTER_DUP TraceId = 922
const SYS_EXIT_DUP TraceId = 921
const SYS_ENTER_GETDENTS TraceId = 908
const SYS_EXIT_GETDENTS TraceId = 907
const SYS_ENTER_GETDENTS64 TraceId = 906
const SYS_EXIT_GETDENTS64 TraceId = 905
const SYS_ENTER_IOCTL TraceId = 904
const SYS_EXIT_IOCTL TraceId = 903
const SYS_ENTER_FCNTL TraceId = 902
const SYS_EXIT_FCNTL TraceId = 901
const SYS_ENTER_MKDIRAT TraceId = 896
const SYS_EXIT_MKDIRAT TraceId = 895
const SYS_ENTER_MKDIR TraceId = 894
const SYS_EXIT_MKDIR TraceId = 893
const SYS_ENTER_RMDIR TraceId = 892
const SYS_EXIT_RMDIR TraceId = 891
const SYS_ENTER_UNLINKAT TraceId = 890
const SYS_EXIT_UNLINKAT TraceId = 889
const SYS_ENTER_UNLINK TraceId = 888
const SYS_EXIT_UNLINK TraceId = 887
const SYS_ENTER_SYMLINKAT TraceId = 886
const SYS_EXIT_SYMLINKAT TraceId = 885
const SYS_ENTER_SYMLINK TraceId = 884
const SYS_EXIT_SYMLINK TraceId = 883
const SYS_ENTER_LINKAT TraceId = 882
const SYS_EXIT_LINKAT TraceId = 881
const SYS_ENTER_LINK TraceId = 880
const SYS_EXIT_LINK TraceId = 879
const SYS_ENTER_RENAMEAT2 TraceId = 878
const SYS_EXIT_RENAMEAT2 TraceId = 877
const SYS_ENTER_RENAMEAT TraceId = 876
const SYS_EXIT_RENAMEAT TraceId = 875
const SYS_ENTER_RENAME TraceId = 874
const SYS_EXIT_RENAME TraceId = 873
const SYS_ENTER_NEWSTAT TraceId = 864
const SYS_EXIT_NEWSTAT TraceId = 863
const SYS_ENTER_NEWLSTAT TraceId = 862
const SYS_EXIT_NEWLSTAT TraceId = 861
const SYS_ENTER_NEWFSTATAT TraceId = 860
const SYS_EXIT_NEWFSTATAT TraceId = 859
const SYS_ENTER_NEWFSTAT TraceId = 858
const SYS_EXIT_NEWFSTAT TraceId = 857
const SYS_ENTER_READLINKAT TraceId = 856
const SYS_EXIT_READLINKAT TraceId = 855
const SYS_ENTER_READLINK TraceId = 854
const SYS_EXIT_READLINK TraceId = 853
const SYS_ENTER_STATX TraceId = 852
const SYS_EXIT_STATX TraceId = 851
const SYS_ENTER_LSEEK TraceId = 850
const SYS_EXIT_LSEEK TraceId = 849
const SYS_ENTER_READ TraceId = 848
const SYS_EXIT_READ TraceId = 847
const SYS_ENTER_WRITE TraceId = 846
const SYS_EXIT_WRITE TraceId = 845
const SYS_ENTER_PREAD64 TraceId = 844
const SYS_EXIT_PREAD64 TraceId = 843
const SYS_ENTER_PWRITE64 TraceId = 842
const SYS_EXIT_PWRITE64 TraceId = 841
const SYS_ENTER_READV TraceId = 840
const SYS_EXIT_READV TraceId = 839
const SYS_ENTER_WRITEV TraceId = 838
const SYS_EXIT_WRITEV TraceId = 837
const SYS_ENTER_PREADV TraceId = 836
const SYS_EXIT_PREADV TraceId = 835
const SYS_ENTER_PREADV2 TraceId = 834
const SYS_EXIT_PREADV2 TraceId = 833
const SYS_ENTER_PWRITEV TraceId = 832
const SYS_EXIT_PWRITEV TraceId = 831
const SYS_ENTER_PWRITEV2 TraceId = 830
const SYS_EXIT_PWRITEV2 TraceId = 829
const SYS_ENTER_COPY_FILE_RANGE TraceId = 826
const SYS_EXIT_COPY_FILE_RANGE TraceId = 825
const SYS_ENTER_TRUNCATE TraceId = 824
const SYS_EXIT_TRUNCATE TraceId = 823
const SYS_ENTER_FTRUNCATE TraceId = 822
const SYS_EXIT_FTRUNCATE TraceId = 821
const SYS_ENTER_FALLOCATE TraceId = 820
const SYS_EXIT_FALLOCATE TraceId = 819
const SYS_ENTER_FACCESSAT TraceId = 818
const SYS_EXIT_FACCESSAT TraceId = 817
const SYS_ENTER_FACCESSAT2 TraceId = 816
const SYS_EXIT_FACCESSAT2 TraceId = 815
const SYS_ENTER_ACCESS TraceId = 814
const SYS_EXIT_ACCESS TraceId = 813
const SYS_ENTER_CHDIR TraceId = 812
const SYS_EXIT_CHDIR TraceId = 811
const SYS_ENTER_FCHDIR TraceId = 810
const SYS_EXIT_FCHDIR TraceId = 809
const SYS_ENTER_CHROOT TraceId = 808
const SYS_EXIT_CHROOT TraceId = 807
const SYS_ENTER_FCHMOD TraceId = 806
const SYS_EXIT_FCHMOD TraceId = 805
const SYS_ENTER_FCHMODAT2 TraceId = 804
const SYS_EXIT_FCHMODAT2 TraceId = 803
const SYS_ENTER_FCHMODAT TraceId = 802
const SYS_EXIT_FCHMODAT TraceId = 801
const SYS_ENTER_CHMOD TraceId = 800
const SYS_EXIT_CHMOD TraceId = 799
const SYS_ENTER_FCHOWNAT TraceId = 798
const SYS_EXIT_FCHOWNAT TraceId = 797
const SYS_ENTER_CHOWN TraceId = 796
const SYS_EXIT_CHOWN TraceId = 795
const SYS_ENTER_LCHOWN TraceId = 794
const SYS_EXIT_LCHOWN TraceId = 793
const SYS_ENTER_FCHOWN TraceId = 792
const SYS_EXIT_FCHOWN TraceId = 791
const SYS_ENTER_OPEN TraceId = 790
const SYS_EXIT_OPEN TraceId = 789
const SYS_ENTER_OPENAT TraceId = 788
const SYS_EXIT_OPENAT TraceId = 787
const SYS_ENTER_OPENAT2 TraceId = 786
const SYS_EXIT_OPENAT2 TraceId = 785
const SYS_ENTER_CREAT TraceId = 784
const SYS_EXIT_CREAT TraceId = 783
const SYS_ENTER_CLOSE TraceId = 782
const SYS_EXIT_CLOSE TraceId = 781
const SYS_ENTER_MSYNC TraceId = 710
const SYS_EXIT_MSYNC TraceId = 709
const SYS_ENTER_READAHEAD TraceId = 616
const SYS_EXIT_READAHEAD TraceId = 615
const SYS_ENTER_FADVISE64 TraceId = 614
const SYS_EXIT_FADVISE64 TraceId = 613
const SYS_ENTER_CACHESTAT TraceId = 595
const SYS_EXIT_CACHESTAT TraceId = 594
const SYS_ENTER_FINIT_MODULE TraceId = 406
const SYS_EXIT_FINIT_MODULE TraceId = 405
const SYS_ENTER_SYSLOG TraceId = 350
const SYS_EXIT_SYSLOG TraceId = 349
const SYS_ENTER_PIDFD_GETFD TraceId = 271
const SYS_EXIT_PIDFD_GETFD TraceId = 270
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
	New: func() any { return &OpenEvent{} },
}

func NewOpenEvent(raw []byte) *OpenEvent {
	o := poolOfOpenEvents.Get().(*OpenEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, o); err != nil {
		*o = OpenEvent{}
		poolOfOpenEvents.Put(o)
		return nil
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
	New: func() any { return &NullEvent{} },
}

func NewNullEvent(raw []byte) *NullEvent {
	n := poolOfNullEvents.Get().(*NullEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, n); err != nil {
		*n = NullEvent{}
		poolOfNullEvents.Put(n)
		return nil
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
	New: func() any { return &FdEvent{} },
}

func NewFdEvent(raw []byte) *FdEvent {
	f := poolOfFdEvents.Get().(*FdEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, f); err != nil {
		*f = FdEvent{}
		poolOfFdEvents.Put(f)
		return nil
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
	New: func() any { return &RetEvent{} },
}

func NewRetEvent(raw []byte) *RetEvent {
	r := poolOfRetEvents.Get().(*RetEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, r); err != nil {
		*r = RetEvent{}
		poolOfRetEvents.Put(r)
		return nil
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
	New: func() any { return &NameEvent{} },
}

func NewNameEvent(raw []byte) *NameEvent {
	n := poolOfNameEvents.Get().(*NameEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, n); err != nil {
		*n = NameEvent{}
		poolOfNameEvents.Put(n)
		return nil
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
	New: func() any { return &PathEvent{} },
}

func NewPathEvent(raw []byte) *PathEvent {
	p := poolOfPathEvents.Get().(*PathEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, p); err != nil {
		*p = PathEvent{}
		poolOfPathEvents.Put(p)
		return nil
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
	New: func() any { return &FcntlEvent{} },
}

func NewFcntlEvent(raw []byte) *FcntlEvent {
	f := poolOfFcntlEvents.Get().(*FcntlEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, f); err != nil {
		*f = FcntlEvent{}
		poolOfFcntlEvents.Put(f)
		return nil
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
	New: func() any { return &Dup3Event{} },
}

func NewDup3Event(raw []byte) *Dup3Event {
	d := poolOfDup3Events.Get().(*Dup3Event)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, d); err != nil {
		*d = Dup3Event{}
		poolOfDup3Events.Put(d)
		return nil
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
	New: func() any { return &OpenByHandleAtEvent{} },
}

func NewOpenByHandleAtEvent(raw []byte) *OpenByHandleAtEvent {
	o := poolOfOpenByHandleAtEvents.Get().(*OpenByHandleAtEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, o); err != nil {
		*o = OpenByHandleAtEvent{}
		poolOfOpenByHandleAtEvents.Put(o)
		return nil
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
