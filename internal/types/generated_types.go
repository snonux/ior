// Code generated - don't change manually!
package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
)

type EventType uint32
type TraceId uint32

// SyscallFamily is the broad runtime grouping for a syscall tracepoint.
type SyscallFamily string

const (
	FamilyNetwork  SyscallFamily = "Network"
	FamilyMemory   SyscallFamily = "Memory"
	FamilySignals  SyscallFamily = "Signals"
	FamilySched    SyscallFamily = "Sched"
	FamilyIPC      SyscallFamily = "IPC"
	FamilyTime     SyscallFamily = "Time"
	FamilyProcess  SyscallFamily = "Process"
	FamilySecurity SyscallFamily = "Security"
	FamilyFS       SyscallFamily = "FS"
	FamilyPolling  SyscallFamily = "Polling"
	FamilyAIO      SyscallFamily = "AIO"
	FamilyMisc     SyscallFamily = "Misc"
)

var traceId2String = map[TraceId]string{
	1899: "enter_socket", 1898: "exit_socket", 1897: "enter_socketpair", 1896: "exit_socketpair", 1895: "enter_bind", 1894: "exit_bind", 1893: "enter_listen", 1892: "exit_listen", 1891: "enter_accept4", 1890: "exit_accept4", 1889: "enter_accept", 1888: "exit_accept", 1887: "enter_connect", 1886: "exit_connect", 1885: "enter_getsockname", 1884: "exit_getsockname", 1883: "enter_getpeername", 1882: "exit_getpeername", 1881: "enter_sendto", 1880: "exit_sendto", 1879: "enter_recvfrom", 1878: "exit_recvfrom", 1877: "enter_setsockopt", 1876: "exit_setsockopt", 1875: "enter_getsockopt", 1874: "exit_getsockopt", 1873: "enter_shutdown", 1872: "exit_shutdown", 1871: "enter_sendmsg", 1870: "exit_sendmsg", 1869: "enter_sendmmsg", 1868: "exit_sendmmsg", 1867: "enter_recvmsg", 1866: "exit_recvmsg", 1865: "enter_recvmmsg", 1864: "exit_recvmmsg", 1626: "enter_getrandom", 1625: "exit_getrandom", 1578: "enter_io_uring_register", 1577: "exit_io_uring_register", 1559: "enter_io_uring_enter", 1558: "exit_io_uring_enter", 1557: "enter_io_uring_setup", 1556: "exit_io_uring_setup", 1541: "enter_ioprio_set", 1540: "exit_ioprio_set", 1539: "enter_ioprio_get", 1538: "exit_ioprio_get", 1512: "enter_landlock_create_ruleset", 1511: "exit_landlock_create_ruleset", 1510: "enter_landlock_add_rule", 1509: "exit_landlock_add_rule", 1508: "enter_landlock_restrict_self", 1507: "exit_landlock_restrict_self", 1505: "enter_lsm_set_self_attr", 1504: "exit_lsm_set_self_attr", 1503: "enter_lsm_get_self_attr", 1502: "exit_lsm_get_self_attr", 1501: "enter_lsm_list_modules", 1500: "exit_lsm_list_modules", 1498: "enter_add_key", 1497: "exit_add_key", 1496: "enter_request_key", 1495: "exit_request_key", 1494: "enter_keyctl", 1493: "exit_keyctl", 1492: "enter_mq_open", 1491: "exit_mq_open", 1490: "enter_mq_unlink", 1489: "exit_mq_unlink", 1488: "enter_mq_timedsend", 1487: "exit_mq_timedsend", 1486: "enter_mq_timedreceive", 1485: "exit_mq_timedreceive", 1484: "enter_mq_notify", 1483: "exit_mq_notify", 1482: "enter_mq_getsetattr", 1481: "exit_mq_getsetattr", 1480: "enter_shmget", 1479: "exit_shmget", 1478: "enter_shmctl", 1477: "exit_shmctl", 1476: "enter_shmat", 1475: "exit_shmat", 1474: "enter_shmdt", 1473: "exit_shmdt", 1472: "enter_semget", 1471: "exit_semget", 1470: "enter_semctl", 1469: "exit_semctl", 1468: "enter_semtimedop", 1467: "exit_semtimedop", 1466: "enter_semop", 1465: "exit_semop", 1464: "enter_msgget", 1463: "exit_msgget", 1462: "enter_msgctl", 1461: "exit_msgctl", 1460: "enter_msgsnd", 1459: "exit_msgsnd", 1458: "enter_msgrcv", 1457: "exit_msgrcv", 1183: "enter_quotactl", 1182: "exit_quotactl", 1181: "enter_quotactl_fd", 1180: "exit_quotactl_fd", 1165: "enter_name_to_handle_at", 1164: "exit_name_to_handle_at", 1163: "enter_open_by_handle_at", 1162: "exit_open_by_handle_at", 1147: "enter_flock", 1146: "exit_flock", 1128: "enter_io_setup", 1127: "exit_io_setup", 1126: "enter_io_destroy", 1125: "exit_io_destroy", 1124: "enter_io_submit", 1123: "exit_io_submit", 1122: "enter_io_cancel", 1121: "exit_io_cancel", 1120: "enter_io_getevents", 1119: "exit_io_getevents", 1118: "enter_io_pgetevents", 1117: "exit_io_pgetevents", 1116: "enter_eventfd2", 1115: "exit_eventfd2", 1114: "enter_eventfd", 1113: "exit_eventfd", 1112: "enter_timerfd_create", 1111: "exit_timerfd_create", 1110: "enter_timerfd_settime", 1109: "exit_timerfd_settime", 1108: "enter_timerfd_gettime", 1107: "exit_timerfd_gettime", 1106: "enter_signalfd4", 1105: "exit_signalfd4", 1104: "enter_signalfd", 1103: "exit_signalfd", 1102: "enter_epoll_create1", 1101: "exit_epoll_create1", 1100: "enter_epoll_create", 1099: "exit_epoll_create", 1098: "enter_epoll_ctl", 1097: "exit_epoll_ctl", 1096: "enter_epoll_wait", 1095: "exit_epoll_wait", 1094: "enter_epoll_pwait", 1093: "exit_epoll_pwait", 1092: "enter_epoll_pwait2", 1091: "exit_epoll_pwait2", 1090: "enter_fanotify_init", 1089: "exit_fanotify_init", 1088: "enter_fanotify_mark", 1087: "exit_fanotify_mark", 1086: "enter_inotify_init1", 1085: "exit_inotify_init1", 1084: "enter_inotify_init", 1083: "exit_inotify_init", 1082: "enter_inotify_add_watch", 1081: "exit_inotify_add_watch", 1080: "enter_inotify_rm_watch", 1079: "exit_inotify_rm_watch", 1077: "enter_file_getattr", 1076: "exit_file_getattr", 1075: "enter_file_setattr", 1074: "exit_file_setattr", 1073: "enter_fsopen", 1072: "exit_fsopen", 1071: "enter_fspick", 1070: "exit_fspick", 1069: "enter_fsconfig", 1068: "exit_fsconfig", 1067: "enter_statfs", 1066: "exit_statfs", 1065: "enter_fstatfs", 1064: "exit_fstatfs", 1063: "enter_ustat", 1062: "exit_ustat", 1061: "enter_getcwd", 1060: "exit_getcwd", 1059: "enter_utimensat", 1058: "exit_utimensat", 1057: "enter_futimesat", 1056: "exit_futimesat", 1055: "enter_utimes", 1054: "exit_utimes", 1053: "enter_utime", 1052: "exit_utime", 1051: "enter_sync", 1050: "exit_sync", 1049: "enter_syncfs", 1048: "exit_syncfs", 1047: "enter_fsync", 1046: "exit_fsync", 1045: "enter_fdatasync", 1044: "exit_fdatasync", 1043: "enter_sync_file_range", 1042: "exit_sync_file_range", 1041: "enter_vmsplice", 1040: "exit_vmsplice", 1039: "enter_splice", 1038: "exit_splice", 1037: "enter_tee", 1036: "exit_tee", 1003: "enter_setxattrat", 1002: "exit_setxattrat", 1001: "enter_setxattr", 1000: "exit_setxattr", 999: "enter_lsetxattr", 998: "exit_lsetxattr", 997: "enter_fsetxattr", 996: "exit_fsetxattr", 995: "enter_getxattrat", 994: "exit_getxattrat", 993: "enter_getxattr", 992: "exit_getxattr", 991: "enter_lgetxattr", 990: "exit_lgetxattr", 989: "enter_fgetxattr", 988: "exit_fgetxattr", 987: "enter_listxattrat", 986: "exit_listxattrat", 985: "enter_listxattr", 984: "exit_listxattr", 983: "enter_llistxattr", 982: "exit_llistxattr", 981: "enter_flistxattr", 980: "exit_flistxattr", 979: "enter_removexattrat", 978: "exit_removexattrat", 977: "enter_removexattr", 976: "exit_removexattr", 975: "enter_lremovexattr", 974: "exit_lremovexattr", 973: "enter_fremovexattr", 972: "exit_fremovexattr", 971: "enter_umount", 970: "exit_umount", 969: "enter_open_tree", 968: "exit_open_tree", 967: "enter_mount", 966: "exit_mount", 965: "enter_fsmount", 964: "exit_fsmount", 963: "enter_move_mount", 962: "exit_move_mount", 961: "enter_pivot_root", 960: "exit_pivot_root", 959: "enter_mount_setattr", 958: "exit_mount_setattr", 957: "enter_open_tree_attr", 956: "exit_open_tree_attr", 955: "enter_statmount", 954: "exit_statmount", 953: "enter_listmount", 952: "exit_listmount", 951: "enter_sysfs", 950: "exit_sysfs", 949: "enter_close_range", 948: "exit_close_range", 947: "enter_dup3", 946: "exit_dup3", 945: "enter_dup2", 944: "exit_dup2", 943: "enter_dup", 942: "exit_dup", 937: "enter_select", 936: "exit_select", 935: "enter_pselect6", 934: "exit_pselect6", 933: "enter_poll", 932: "exit_poll", 931: "enter_ppoll", 930: "exit_ppoll", 929: "enter_getdents", 928: "exit_getdents", 927: "enter_getdents64", 926: "exit_getdents64", 925: "enter_ioctl", 924: "exit_ioctl", 923: "enter_fcntl", 922: "exit_fcntl", 921: "enter_mknodat", 920: "exit_mknodat", 919: "enter_mknod", 918: "exit_mknod", 917: "enter_mkdirat", 916: "exit_mkdirat", 915: "enter_mkdir", 914: "exit_mkdir", 913: "enter_rmdir", 912: "exit_rmdir", 911: "enter_unlinkat", 910: "exit_unlinkat", 909: "enter_unlink", 908: "exit_unlink", 907: "enter_symlinkat", 906: "exit_symlinkat", 905: "enter_symlink", 904: "exit_symlink", 903: "enter_linkat", 902: "exit_linkat", 901: "enter_link", 900: "exit_link", 899: "enter_renameat2", 898: "exit_renameat2", 897: "enter_renameat", 896: "exit_renameat", 895: "enter_rename", 894: "exit_rename", 893: "enter_pipe2", 892: "exit_pipe2", 891: "enter_pipe", 890: "exit_pipe", 889: "enter_execve", 888: "exit_execve", 887: "enter_execveat", 886: "exit_execveat", 885: "enter_newstat", 884: "exit_newstat", 883: "enter_newlstat", 882: "exit_newlstat", 881: "enter_newfstatat", 880: "exit_newfstatat", 879: "enter_newfstat", 878: "exit_newfstat", 877: "enter_readlinkat", 876: "exit_readlinkat", 875: "enter_readlink", 874: "exit_readlink", 873: "enter_statx", 872: "exit_statx", 871: "enter_lseek", 870: "exit_lseek", 869: "enter_read", 868: "exit_read", 867: "enter_write", 866: "exit_write", 865: "enter_pread64", 864: "exit_pread64", 863: "enter_pwrite64", 862: "exit_pwrite64", 861: "enter_readv", 860: "exit_readv", 859: "enter_writev", 858: "exit_writev", 857: "enter_preadv", 856: "exit_preadv", 855: "enter_preadv2", 854: "exit_preadv2", 853: "enter_pwritev", 852: "exit_pwritev", 851: "enter_pwritev2", 850: "exit_pwritev2", 849: "enter_sendfile64", 848: "exit_sendfile64", 847: "enter_copy_file_range", 846: "exit_copy_file_range", 845: "enter_truncate", 844: "exit_truncate", 843: "enter_ftruncate", 842: "exit_ftruncate", 841: "enter_fallocate", 840: "exit_fallocate", 839: "enter_faccessat", 838: "exit_faccessat", 837: "enter_faccessat2", 836: "exit_faccessat2", 835: "enter_access", 834: "exit_access", 833: "enter_chdir", 832: "exit_chdir", 831: "enter_fchdir", 830: "exit_fchdir", 829: "enter_chroot", 828: "exit_chroot", 827: "enter_fchmod", 826: "exit_fchmod", 825: "enter_fchmodat2", 824: "exit_fchmodat2", 823: "enter_fchmodat", 822: "exit_fchmodat", 821: "enter_chmod", 820: "exit_chmod", 819: "enter_fchownat", 818: "exit_fchownat", 817: "enter_chown", 816: "exit_chown", 815: "enter_lchown", 814: "exit_lchown", 813: "enter_fchown", 812: "exit_fchown", 811: "enter_open", 810: "exit_open", 809: "enter_openat", 808: "exit_openat", 807: "enter_openat2", 806: "exit_openat2", 805: "enter_creat", 804: "exit_creat", 803: "enter_close", 802: "exit_close", 801: "enter_vhangup", 800: "exit_vhangup", 799: "enter_memfd_create", 798: "exit_memfd_create", 791: "enter_userfaultfd", 790: "exit_userfaultfd", 789: "enter_memfd_secret", 788: "exit_memfd_secret", 768: "enter_move_pages", 767: "exit_move_pages", 757: "enter_set_mempolicy_home_node", 756: "exit_set_mempolicy_home_node", 755: "enter_mbind", 754: "exit_mbind", 753: "enter_set_mempolicy", 752: "exit_set_mempolicy", 751: "enter_migrate_pages", 750: "exit_migrate_pages", 749: "enter_get_mempolicy", 748: "exit_get_mempolicy", 747: "enter_swapoff", 746: "exit_swapoff", 745: "enter_swapon", 744: "exit_swapon", 743: "enter_madvise", 742: "exit_madvise", 741: "enter_process_madvise", 740: "exit_process_madvise", 739: "enter_mseal", 738: "exit_mseal", 737: "enter_process_vm_readv", 736: "exit_process_vm_readv", 735: "enter_process_vm_writev", 734: "exit_process_vm_writev", 726: "enter_msync", 725: "exit_msync", 724: "enter_mremap", 723: "exit_mremap", 722: "enter_mprotect", 721: "exit_mprotect", 720: "enter_pkey_mprotect", 719: "exit_pkey_mprotect", 718: "enter_pkey_alloc", 717: "exit_pkey_alloc", 716: "enter_pkey_free", 715: "exit_pkey_free", 712: "enter_brk", 711: "exit_brk", 710: "enter_munmap", 709: "exit_munmap", 708: "enter_remap_file_pages", 707: "exit_remap_file_pages", 706: "enter_mlock", 705: "exit_mlock", 704: "enter_mlock2", 703: "exit_mlock2", 702: "enter_munlock", 701: "exit_munlock", 700: "enter_mlockall", 699: "exit_mlockall", 698: "enter_munlockall", 697: "exit_munlockall", 696: "enter_mincore", 695: "exit_mincore", 628: "enter_readahead", 627: "exit_readahead", 626: "enter_fadvise64", 625: "exit_fadvise64", 616: "enter_process_mrelease", 615: "exit_process_mrelease", 607: "enter_cachestat", 606: "exit_cachestat", 603: "enter_rseq", 602: "exit_rseq", 599: "enter_perf_event_open", 598: "exit_perf_event_open", 597: "enter_bpf", 596: "exit_bpf", 529: "enter_seccomp", 528: "exit_seccomp", 511: "enter_kexec_file_load", 510: "exit_kexec_file_load", 509: "enter_kexec_load", 508: "exit_kexec_load", 507: "enter_acct", 506: "exit_acct", 502: "enter_set_robust_list", 501: "exit_set_robust_list", 500: "enter_get_robust_list", 499: "exit_get_robust_list", 498: "enter_futex", 497: "exit_futex", 496: "enter_futex_waitv", 495: "exit_futex_waitv", 494: "enter_futex_wake", 493: "exit_futex_wake", 492: "enter_futex_wait", 491: "exit_futex_wait", 490: "enter_futex_requeue", 489: "exit_futex_requeue", 474: "enter_getitimer", 473: "exit_getitimer", 472: "enter_alarm", 471: "exit_alarm", 470: "enter_setitimer", 469: "exit_setitimer", 468: "enter_timer_create", 467: "exit_timer_create", 466: "enter_timer_gettime", 465: "exit_timer_gettime", 464: "enter_timer_getoverrun", 463: "exit_timer_getoverrun", 462: "enter_timer_settime", 461: "exit_timer_settime", 460: "enter_timer_delete", 459: "exit_timer_delete", 458: "enter_clock_settime", 457: "exit_clock_settime", 456: "enter_clock_gettime", 455: "exit_clock_gettime", 454: "enter_clock_adjtime", 453: "exit_clock_adjtime", 452: "enter_clock_getres", 451: "exit_clock_getres", 450: "enter_clock_nanosleep", 449: "exit_clock_nanosleep", 444: "enter_nanosleep", 443: "exit_nanosleep", 426: "enter_time", 425: "exit_time", 424: "enter_gettimeofday", 423: "exit_gettimeofday", 422: "enter_settimeofday", 421: "exit_settimeofday", 420: "enter_adjtimex", 419: "exit_adjtimex", 418: "enter_kcmp", 417: "exit_kcmp", 411: "enter_delete_module", 410: "exit_delete_module", 409: "enter_init_module", 408: "exit_init_module", 407: "enter_finit_module", 406: "exit_finit_module", 351: "enter_syslog", 350: "exit_syslog", 346: "enter_membarrier", 345: "exit_membarrier", 341: "enter_sched_setscheduler", 340: "exit_sched_setscheduler", 339: "enter_sched_setparam", 338: "exit_sched_setparam", 337: "enter_sched_setattr", 336: "exit_sched_setattr", 335: "enter_sched_getscheduler", 334: "exit_sched_getscheduler", 333: "enter_sched_getparam", 332: "exit_sched_getparam", 331: "enter_sched_getattr", 330: "exit_sched_getattr", 329: "enter_sched_setaffinity", 328: "exit_sched_setaffinity", 327: "enter_sched_getaffinity", 326: "exit_sched_getaffinity", 325: "enter_sched_yield", 324: "exit_sched_yield", 323: "enter_sched_get_priority_max", 322: "exit_sched_get_priority_max", 321: "enter_sched_get_priority_min", 320: "exit_sched_get_priority_min", 319: "enter_sched_rr_get_interval", 318: "exit_sched_rr_get_interval", 286: "enter_getgroups", 285: "exit_getgroups", 284: "enter_setgroups", 283: "exit_setgroups", 282: "enter_reboot", 281: "exit_reboot", 277: "enter_listns", 276: "exit_listns", 275: "enter_setns", 274: "exit_setns", 273: "enter_pidfd_open", 272: "exit_pidfd_open", 271: "enter_pidfd_getfd", 270: "exit_pidfd_getfd", 265: "enter_setpriority", 264: "exit_setpriority", 263: "enter_getpriority", 262: "exit_getpriority", 261: "enter_setregid", 260: "exit_setregid", 259: "enter_setgid", 258: "exit_setgid", 257: "enter_setreuid", 256: "exit_setreuid", 255: "enter_setuid", 254: "exit_setuid", 253: "enter_setresuid", 252: "exit_setresuid", 251: "enter_getresuid", 250: "exit_getresuid", 249: "enter_setresgid", 248: "exit_setresgid", 247: "enter_getresgid", 246: "exit_getresgid", 245: "enter_setfsuid", 244: "exit_setfsuid", 243: "enter_setfsgid", 242: "exit_setfsgid", 241: "enter_getpid", 240: "exit_getpid", 239: "enter_gettid", 238: "exit_gettid", 237: "enter_getppid", 236: "exit_getppid", 235: "enter_getuid", 234: "exit_getuid", 233: "enter_geteuid", 232: "exit_geteuid", 231: "enter_getgid", 230: "exit_getgid", 229: "enter_getegid", 228: "exit_getegid", 227: "enter_times", 226: "exit_times", 225: "enter_setpgid", 224: "exit_setpgid", 223: "enter_getpgid", 222: "exit_getpgid", 221: "enter_getpgrp", 220: "exit_getpgrp", 219: "enter_getsid", 218: "exit_getsid", 217: "enter_setsid", 216: "exit_setsid", 215: "enter_newuname", 214: "exit_newuname", 213: "enter_sethostname", 212: "exit_sethostname", 211: "enter_setdomainname", 210: "exit_setdomainname", 209: "enter_getrlimit", 208: "exit_getrlimit", 207: "enter_prlimit64", 206: "exit_prlimit64", 205: "enter_setrlimit", 204: "exit_setrlimit", 203: "enter_getrusage", 202: "exit_getrusage", 201: "enter_umask", 200: "exit_umask", 199: "enter_prctl", 198: "exit_prctl", 197: "enter_getcpu", 196: "exit_getcpu", 195: "enter_sysinfo", 194: "exit_sysinfo", 191: "enter_restart_syscall", 190: "exit_restart_syscall", 189: "enter_rt_sigprocmask", 188: "exit_rt_sigprocmask", 187: "enter_rt_sigpending", 186: "exit_rt_sigpending", 185: "enter_rt_sigtimedwait", 184: "exit_rt_sigtimedwait", 183: "enter_kill", 182: "exit_kill", 181: "enter_pidfd_send_signal", 180: "exit_pidfd_send_signal", 179: "enter_tgkill", 178: "exit_tgkill", 177: "enter_tkill", 176: "exit_tkill", 175: "enter_rt_sigqueueinfo", 174: "exit_rt_sigqueueinfo", 173: "enter_rt_tgsigqueueinfo", 172: "exit_rt_tgsigqueueinfo", 171: "enter_sigaltstack", 170: "exit_sigaltstack", 169: "enter_rt_sigaction", 168: "exit_rt_sigaction", 167: "enter_pause", 166: "exit_pause", 165: "enter_rt_sigsuspend", 164: "exit_rt_sigsuspend", 163: "enter_ptrace", 162: "exit_ptrace", 161: "enter_capget", 160: "exit_capget", 159: "enter_capset", 158: "exit_capset", 150: "enter_exit", 148: "enter_exit_group", 146: "enter_waitid", 145: "exit_waitid", 144: "enter_wait4", 143: "exit_wait4", 139: "enter_personality", 138: "exit_personality", 134: "enter_set_tid_address", 133: "exit_set_tid_address", 132: "enter_fork", 131: "exit_fork", 130: "enter_vfork", 129: "exit_vfork", 128: "enter_clone", 127: "exit_clone", 126: "enter_clone3", 125: "exit_clone3", 124: "enter_unshare", 123: "exit_unshare", 119: "enter_map_shadow_stack", 118: "exit_map_shadow_stack", 117: "enter_uretprobe", 116: "exit_uretprobe", 115: "enter_uprobe", 114: "exit_uprobe", 102: "enter_arch_prctl", 101: "exit_arch_prctl", 100: "enter_mmap", 99: "exit_mmap", 98: "enter_modify_ldt", 97: "exit_modify_ldt", 95: "enter_ioperm", 94: "exit_ioperm", 93: "enter_iopl", 92: "exit_iopl", 57: "enter_rt_sigreturn",
}

var traceId2Name = map[TraceId]string{
	1899: "socket", 1898: "socket", 1897: "socketpair", 1896: "socketpair", 1895: "bind", 1894: "bind", 1893: "listen", 1892: "listen", 1891: "accept4", 1890: "accept4", 1889: "accept", 1888: "accept", 1887: "connect", 1886: "connect", 1885: "getsockname", 1884: "getsockname", 1883: "getpeername", 1882: "getpeername", 1881: "sendto", 1880: "sendto", 1879: "recvfrom", 1878: "recvfrom", 1877: "setsockopt", 1876: "setsockopt", 1875: "getsockopt", 1874: "getsockopt", 1873: "shutdown", 1872: "shutdown", 1871: "sendmsg", 1870: "sendmsg", 1869: "sendmmsg", 1868: "sendmmsg", 1867: "recvmsg", 1866: "recvmsg", 1865: "recvmmsg", 1864: "recvmmsg", 1626: "getrandom", 1625: "getrandom", 1578: "io_uring_register", 1577: "io_uring_register", 1559: "io_uring_enter", 1558: "io_uring_enter", 1557: "io_uring_setup", 1556: "io_uring_setup", 1541: "ioprio_set", 1540: "ioprio_set", 1539: "ioprio_get", 1538: "ioprio_get", 1512: "landlock_create_ruleset", 1511: "landlock_create_ruleset", 1510: "landlock_add_rule", 1509: "landlock_add_rule", 1508: "landlock_restrict_self", 1507: "landlock_restrict_self", 1505: "lsm_set_self_attr", 1504: "lsm_set_self_attr", 1503: "lsm_get_self_attr", 1502: "lsm_get_self_attr", 1501: "lsm_list_modules", 1500: "lsm_list_modules", 1498: "add_key", 1497: "add_key", 1496: "request_key", 1495: "request_key", 1494: "keyctl", 1493: "keyctl", 1492: "mq_open", 1491: "mq_open", 1490: "mq_unlink", 1489: "mq_unlink", 1488: "mq_timedsend", 1487: "mq_timedsend", 1486: "mq_timedreceive", 1485: "mq_timedreceive", 1484: "mq_notify", 1483: "mq_notify", 1482: "mq_getsetattr", 1481: "mq_getsetattr", 1480: "shmget", 1479: "shmget", 1478: "shmctl", 1477: "shmctl", 1476: "shmat", 1475: "shmat", 1474: "shmdt", 1473: "shmdt", 1472: "semget", 1471: "semget", 1470: "semctl", 1469: "semctl", 1468: "semtimedop", 1467: "semtimedop", 1466: "semop", 1465: "semop", 1464: "msgget", 1463: "msgget", 1462: "msgctl", 1461: "msgctl", 1460: "msgsnd", 1459: "msgsnd", 1458: "msgrcv", 1457: "msgrcv", 1183: "quotactl", 1182: "quotactl", 1181: "quotactl_fd", 1180: "quotactl_fd", 1165: "name_to_handle_at", 1164: "name_to_handle_at", 1163: "open_by_handle_at", 1162: "open_by_handle_at", 1147: "flock", 1146: "flock", 1128: "io_setup", 1127: "io_setup", 1126: "io_destroy", 1125: "io_destroy", 1124: "io_submit", 1123: "io_submit", 1122: "io_cancel", 1121: "io_cancel", 1120: "io_getevents", 1119: "io_getevents", 1118: "io_pgetevents", 1117: "io_pgetevents", 1116: "eventfd2", 1115: "eventfd2", 1114: "eventfd", 1113: "eventfd", 1112: "timerfd_create", 1111: "timerfd_create", 1110: "timerfd_settime", 1109: "timerfd_settime", 1108: "timerfd_gettime", 1107: "timerfd_gettime", 1106: "signalfd4", 1105: "signalfd4", 1104: "signalfd", 1103: "signalfd", 1102: "epoll_create1", 1101: "epoll_create1", 1100: "epoll_create", 1099: "epoll_create", 1098: "epoll_ctl", 1097: "epoll_ctl", 1096: "epoll_wait", 1095: "epoll_wait", 1094: "epoll_pwait", 1093: "epoll_pwait", 1092: "epoll_pwait2", 1091: "epoll_pwait2", 1090: "fanotify_init", 1089: "fanotify_init", 1088: "fanotify_mark", 1087: "fanotify_mark", 1086: "inotify_init1", 1085: "inotify_init1", 1084: "inotify_init", 1083: "inotify_init", 1082: "inotify_add_watch", 1081: "inotify_add_watch", 1080: "inotify_rm_watch", 1079: "inotify_rm_watch", 1077: "file_getattr", 1076: "file_getattr", 1075: "file_setattr", 1074: "file_setattr", 1073: "fsopen", 1072: "fsopen", 1071: "fspick", 1070: "fspick", 1069: "fsconfig", 1068: "fsconfig", 1067: "statfs", 1066: "statfs", 1065: "fstatfs", 1064: "fstatfs", 1063: "ustat", 1062: "ustat", 1061: "getcwd", 1060: "getcwd", 1059: "utimensat", 1058: "utimensat", 1057: "futimesat", 1056: "futimesat", 1055: "utimes", 1054: "utimes", 1053: "utime", 1052: "utime", 1051: "sync", 1050: "sync", 1049: "syncfs", 1048: "syncfs", 1047: "fsync", 1046: "fsync", 1045: "fdatasync", 1044: "fdatasync", 1043: "sync_file_range", 1042: "sync_file_range", 1041: "vmsplice", 1040: "vmsplice", 1039: "splice", 1038: "splice", 1037: "tee", 1036: "tee", 1003: "setxattrat", 1002: "setxattrat", 1001: "setxattr", 1000: "setxattr", 999: "lsetxattr", 998: "lsetxattr", 997: "fsetxattr", 996: "fsetxattr", 995: "getxattrat", 994: "getxattrat", 993: "getxattr", 992: "getxattr", 991: "lgetxattr", 990: "lgetxattr", 989: "fgetxattr", 988: "fgetxattr", 987: "listxattrat", 986: "listxattrat", 985: "listxattr", 984: "listxattr", 983: "llistxattr", 982: "llistxattr", 981: "flistxattr", 980: "flistxattr", 979: "removexattrat", 978: "removexattrat", 977: "removexattr", 976: "removexattr", 975: "lremovexattr", 974: "lremovexattr", 973: "fremovexattr", 972: "fremovexattr", 971: "umount", 970: "umount", 969: "open_tree", 968: "open_tree", 967: "mount", 966: "mount", 965: "fsmount", 964: "fsmount", 963: "move_mount", 962: "move_mount", 961: "pivot_root", 960: "pivot_root", 959: "mount_setattr", 958: "mount_setattr", 957: "open_tree_attr", 956: "open_tree_attr", 955: "statmount", 954: "statmount", 953: "listmount", 952: "listmount", 951: "sysfs", 950: "sysfs", 949: "close_range", 948: "close_range", 947: "dup3", 946: "dup3", 945: "dup2", 944: "dup2", 943: "dup", 942: "dup", 937: "select", 936: "select", 935: "pselect6", 934: "pselect6", 933: "poll", 932: "poll", 931: "ppoll", 930: "ppoll", 929: "getdents", 928: "getdents", 927: "getdents64", 926: "getdents64", 925: "ioctl", 924: "ioctl", 923: "fcntl", 922: "fcntl", 921: "mknodat", 920: "mknodat", 919: "mknod", 918: "mknod", 917: "mkdirat", 916: "mkdirat", 915: "mkdir", 914: "mkdir", 913: "rmdir", 912: "rmdir", 911: "unlinkat", 910: "unlinkat", 909: "unlink", 908: "unlink", 907: "symlinkat", 906: "symlinkat", 905: "symlink", 904: "symlink", 903: "linkat", 902: "linkat", 901: "link", 900: "link", 899: "renameat2", 898: "renameat2", 897: "renameat", 896: "renameat", 895: "rename", 894: "rename", 893: "pipe2", 892: "pipe2", 891: "pipe", 890: "pipe", 889: "execve", 888: "execve", 887: "execveat", 886: "execveat", 885: "newstat", 884: "newstat", 883: "newlstat", 882: "newlstat", 881: "newfstatat", 880: "newfstatat", 879: "newfstat", 878: "newfstat", 877: "readlinkat", 876: "readlinkat", 875: "readlink", 874: "readlink", 873: "statx", 872: "statx", 871: "lseek", 870: "lseek", 869: "read", 868: "read", 867: "write", 866: "write", 865: "pread64", 864: "pread64", 863: "pwrite64", 862: "pwrite64", 861: "readv", 860: "readv", 859: "writev", 858: "writev", 857: "preadv", 856: "preadv", 855: "preadv2", 854: "preadv2", 853: "pwritev", 852: "pwritev", 851: "pwritev2", 850: "pwritev2", 849: "sendfile64", 848: "sendfile64", 847: "copy_file_range", 846: "copy_file_range", 845: "truncate", 844: "truncate", 843: "ftruncate", 842: "ftruncate", 841: "fallocate", 840: "fallocate", 839: "faccessat", 838: "faccessat", 837: "faccessat2", 836: "faccessat2", 835: "access", 834: "access", 833: "chdir", 832: "chdir", 831: "fchdir", 830: "fchdir", 829: "chroot", 828: "chroot", 827: "fchmod", 826: "fchmod", 825: "fchmodat2", 824: "fchmodat2", 823: "fchmodat", 822: "fchmodat", 821: "chmod", 820: "chmod", 819: "fchownat", 818: "fchownat", 817: "chown", 816: "chown", 815: "lchown", 814: "lchown", 813: "fchown", 812: "fchown", 811: "open", 810: "open", 809: "openat", 808: "openat", 807: "openat2", 806: "openat2", 805: "creat", 804: "creat", 803: "close", 802: "close", 801: "vhangup", 800: "vhangup", 799: "memfd_create", 798: "memfd_create", 791: "userfaultfd", 790: "userfaultfd", 789: "memfd_secret", 788: "memfd_secret", 768: "move_pages", 767: "move_pages", 757: "set_mempolicy_home_node", 756: "set_mempolicy_home_node", 755: "mbind", 754: "mbind", 753: "set_mempolicy", 752: "set_mempolicy", 751: "migrate_pages", 750: "migrate_pages", 749: "get_mempolicy", 748: "get_mempolicy", 747: "swapoff", 746: "swapoff", 745: "swapon", 744: "swapon", 743: "madvise", 742: "madvise", 741: "process_madvise", 740: "process_madvise", 739: "mseal", 738: "mseal", 737: "process_vm_readv", 736: "process_vm_readv", 735: "process_vm_writev", 734: "process_vm_writev", 726: "msync", 725: "msync", 724: "mremap", 723: "mremap", 722: "mprotect", 721: "mprotect", 720: "pkey_mprotect", 719: "pkey_mprotect", 718: "pkey_alloc", 717: "pkey_alloc", 716: "pkey_free", 715: "pkey_free", 712: "brk", 711: "brk", 710: "munmap", 709: "munmap", 708: "remap_file_pages", 707: "remap_file_pages", 706: "mlock", 705: "mlock", 704: "mlock2", 703: "mlock2", 702: "munlock", 701: "munlock", 700: "mlockall", 699: "mlockall", 698: "munlockall", 697: "munlockall", 696: "mincore", 695: "mincore", 628: "readahead", 627: "readahead", 626: "fadvise64", 625: "fadvise64", 616: "process_mrelease", 615: "process_mrelease", 607: "cachestat", 606: "cachestat", 603: "rseq", 602: "rseq", 599: "perf_event_open", 598: "perf_event_open", 597: "bpf", 596: "bpf", 529: "seccomp", 528: "seccomp", 511: "kexec_file_load", 510: "kexec_file_load", 509: "kexec_load", 508: "kexec_load", 507: "acct", 506: "acct", 502: "set_robust_list", 501: "set_robust_list", 500: "get_robust_list", 499: "get_robust_list", 498: "futex", 497: "futex", 496: "futex_waitv", 495: "futex_waitv", 494: "futex_wake", 493: "futex_wake", 492: "futex_wait", 491: "futex_wait", 490: "futex_requeue", 489: "futex_requeue", 474: "getitimer", 473: "getitimer", 472: "alarm", 471: "alarm", 470: "setitimer", 469: "setitimer", 468: "timer_create", 467: "timer_create", 466: "timer_gettime", 465: "timer_gettime", 464: "timer_getoverrun", 463: "timer_getoverrun", 462: "timer_settime", 461: "timer_settime", 460: "timer_delete", 459: "timer_delete", 458: "clock_settime", 457: "clock_settime", 456: "clock_gettime", 455: "clock_gettime", 454: "clock_adjtime", 453: "clock_adjtime", 452: "clock_getres", 451: "clock_getres", 450: "clock_nanosleep", 449: "clock_nanosleep", 444: "nanosleep", 443: "nanosleep", 426: "time", 425: "time", 424: "gettimeofday", 423: "gettimeofday", 422: "settimeofday", 421: "settimeofday", 420: "adjtimex", 419: "adjtimex", 418: "kcmp", 417: "kcmp", 411: "delete_module", 410: "delete_module", 409: "init_module", 408: "init_module", 407: "finit_module", 406: "finit_module", 351: "syslog", 350: "syslog", 346: "membarrier", 345: "membarrier", 341: "sched_setscheduler", 340: "sched_setscheduler", 339: "sched_setparam", 338: "sched_setparam", 337: "sched_setattr", 336: "sched_setattr", 335: "sched_getscheduler", 334: "sched_getscheduler", 333: "sched_getparam", 332: "sched_getparam", 331: "sched_getattr", 330: "sched_getattr", 329: "sched_setaffinity", 328: "sched_setaffinity", 327: "sched_getaffinity", 326: "sched_getaffinity", 325: "sched_yield", 324: "sched_yield", 323: "sched_get_priority_max", 322: "sched_get_priority_max", 321: "sched_get_priority_min", 320: "sched_get_priority_min", 319: "sched_rr_get_interval", 318: "sched_rr_get_interval", 286: "getgroups", 285: "getgroups", 284: "setgroups", 283: "setgroups", 282: "reboot", 281: "reboot", 277: "listns", 276: "listns", 275: "setns", 274: "setns", 273: "pidfd_open", 272: "pidfd_open", 271: "pidfd_getfd", 270: "pidfd_getfd", 265: "setpriority", 264: "setpriority", 263: "getpriority", 262: "getpriority", 261: "setregid", 260: "setregid", 259: "setgid", 258: "setgid", 257: "setreuid", 256: "setreuid", 255: "setuid", 254: "setuid", 253: "setresuid", 252: "setresuid", 251: "getresuid", 250: "getresuid", 249: "setresgid", 248: "setresgid", 247: "getresgid", 246: "getresgid", 245: "setfsuid", 244: "setfsuid", 243: "setfsgid", 242: "setfsgid", 241: "getpid", 240: "getpid", 239: "gettid", 238: "gettid", 237: "getppid", 236: "getppid", 235: "getuid", 234: "getuid", 233: "geteuid", 232: "geteuid", 231: "getgid", 230: "getgid", 229: "getegid", 228: "getegid", 227: "times", 226: "times", 225: "setpgid", 224: "setpgid", 223: "getpgid", 222: "getpgid", 221: "getpgrp", 220: "getpgrp", 219: "getsid", 218: "getsid", 217: "setsid", 216: "setsid", 215: "newuname", 214: "newuname", 213: "sethostname", 212: "sethostname", 211: "setdomainname", 210: "setdomainname", 209: "getrlimit", 208: "getrlimit", 207: "prlimit64", 206: "prlimit64", 205: "setrlimit", 204: "setrlimit", 203: "getrusage", 202: "getrusage", 201: "umask", 200: "umask", 199: "prctl", 198: "prctl", 197: "getcpu", 196: "getcpu", 195: "sysinfo", 194: "sysinfo", 191: "restart_syscall", 190: "restart_syscall", 189: "rt_sigprocmask", 188: "rt_sigprocmask", 187: "rt_sigpending", 186: "rt_sigpending", 185: "rt_sigtimedwait", 184: "rt_sigtimedwait", 183: "kill", 182: "kill", 181: "pidfd_send_signal", 180: "pidfd_send_signal", 179: "tgkill", 178: "tgkill", 177: "tkill", 176: "tkill", 175: "rt_sigqueueinfo", 174: "rt_sigqueueinfo", 173: "rt_tgsigqueueinfo", 172: "rt_tgsigqueueinfo", 171: "sigaltstack", 170: "sigaltstack", 169: "rt_sigaction", 168: "rt_sigaction", 167: "pause", 166: "pause", 165: "rt_sigsuspend", 164: "rt_sigsuspend", 163: "ptrace", 162: "ptrace", 161: "capget", 160: "capget", 159: "capset", 158: "capset", 150: "exit", 148: "exit_group", 146: "waitid", 145: "waitid", 144: "wait4", 143: "wait4", 139: "personality", 138: "personality", 134: "set_tid_address", 133: "set_tid_address", 132: "fork", 131: "fork", 130: "vfork", 129: "vfork", 128: "clone", 127: "clone", 126: "clone3", 125: "clone3", 124: "unshare", 123: "unshare", 119: "map_shadow_stack", 118: "map_shadow_stack", 117: "uretprobe", 116: "uretprobe", 115: "uprobe", 114: "uprobe", 102: "arch_prctl", 101: "arch_prctl", 100: "mmap", 99: "mmap", 98: "modify_ldt", 97: "modify_ldt", 95: "ioperm", 94: "ioperm", 93: "iopl", 92: "iopl", 57: "rt_sigreturn",
}

var traceId2Family = map[TraceId]SyscallFamily{
	1899: FamilyNetwork, 1898: FamilyNetwork, 1897: FamilyNetwork, 1896: FamilyNetwork, 1895: FamilyNetwork, 1894: FamilyNetwork, 1893: FamilyNetwork, 1892: FamilyNetwork, 1891: FamilyNetwork, 1890: FamilyNetwork, 1889: FamilyNetwork, 1888: FamilyNetwork, 1887: FamilyNetwork, 1886: FamilyNetwork, 1885: FamilyNetwork, 1884: FamilyNetwork, 1883: FamilyNetwork, 1882: FamilyNetwork, 1881: FamilyNetwork, 1880: FamilyNetwork, 1879: FamilyNetwork, 1878: FamilyNetwork, 1877: FamilyNetwork, 1876: FamilyNetwork, 1875: FamilyNetwork, 1874: FamilyNetwork, 1873: FamilyNetwork, 1872: FamilyNetwork, 1871: FamilyNetwork, 1870: FamilyNetwork, 1869: FamilyNetwork, 1868: FamilyNetwork, 1867: FamilyNetwork, 1866: FamilyNetwork, 1865: FamilyNetwork, 1864: FamilyNetwork, 1626: FamilySecurity, 1625: FamilySecurity, 1578: FamilyAIO, 1577: FamilyAIO, 1559: FamilyAIO, 1558: FamilyAIO, 1557: FamilyAIO, 1556: FamilyAIO, 1541: FamilyProcess, 1540: FamilyProcess, 1539: FamilyProcess, 1538: FamilyProcess, 1512: FamilySecurity, 1511: FamilySecurity, 1510: FamilySecurity, 1509: FamilySecurity, 1508: FamilySecurity, 1507: FamilySecurity, 1505: FamilySecurity, 1504: FamilySecurity, 1503: FamilySecurity, 1502: FamilySecurity, 1501: FamilySecurity, 1500: FamilySecurity, 1498: FamilySecurity, 1497: FamilySecurity, 1496: FamilySecurity, 1495: FamilySecurity, 1494: FamilySecurity, 1493: FamilySecurity, 1492: FamilyIPC, 1491: FamilyIPC, 1490: FamilyIPC, 1489: FamilyIPC, 1488: FamilyIPC, 1487: FamilyIPC, 1486: FamilyIPC, 1485: FamilyIPC, 1484: FamilyIPC, 1483: FamilyIPC, 1482: FamilyIPC, 1481: FamilyIPC, 1480: FamilyIPC, 1479: FamilyIPC, 1478: FamilyIPC, 1477: FamilyIPC, 1476: FamilyIPC, 1475: FamilyIPC, 1474: FamilyIPC, 1473: FamilyIPC, 1472: FamilyIPC, 1471: FamilyIPC, 1470: FamilyIPC, 1469: FamilyIPC, 1468: FamilyIPC, 1467: FamilyIPC, 1466: FamilyIPC, 1465: FamilyIPC, 1464: FamilyIPC, 1463: FamilyIPC, 1462: FamilyIPC, 1461: FamilyIPC, 1460: FamilyIPC, 1459: FamilyIPC, 1458: FamilyIPC, 1457: FamilyIPC, 1183: FamilyFS, 1182: FamilyFS, 1181: FamilyFS, 1180: FamilyFS, 1165: FamilyFS, 1164: FamilyFS, 1163: FamilyFS, 1162: FamilyFS, 1147: FamilyFS, 1146: FamilyFS, 1128: FamilyAIO, 1127: FamilyAIO, 1126: FamilyAIO, 1125: FamilyAIO, 1124: FamilyAIO, 1123: FamilyAIO, 1122: FamilyAIO, 1121: FamilyAIO, 1120: FamilyAIO, 1119: FamilyAIO, 1118: FamilyAIO, 1117: FamilyAIO, 1116: FamilyIPC, 1115: FamilyIPC, 1114: FamilyIPC, 1113: FamilyIPC, 1112: FamilyIPC, 1111: FamilyIPC, 1110: FamilyIPC, 1109: FamilyIPC, 1108: FamilyIPC, 1107: FamilyIPC, 1106: FamilyIPC, 1105: FamilyIPC, 1104: FamilyIPC, 1103: FamilyIPC, 1102: FamilyPolling, 1101: FamilyPolling, 1100: FamilyPolling, 1099: FamilyPolling, 1098: FamilyPolling, 1097: FamilyPolling, 1096: FamilyPolling, 1095: FamilyPolling, 1094: FamilyPolling, 1093: FamilyPolling, 1092: FamilyPolling, 1091: FamilyPolling, 1090: FamilyIPC, 1089: FamilyIPC, 1088: FamilyIPC, 1087: FamilyIPC, 1086: FamilyIPC, 1085: FamilyIPC, 1084: FamilyIPC, 1083: FamilyIPC, 1082: FamilyIPC, 1081: FamilyIPC, 1080: FamilyIPC, 1079: FamilyIPC, 1077: FamilyFS, 1076: FamilyFS, 1075: FamilyFS, 1074: FamilyFS, 1073: FamilyFS, 1072: FamilyFS, 1071: FamilyFS, 1070: FamilyFS, 1069: FamilyFS, 1068: FamilyFS, 1067: FamilyFS, 1066: FamilyFS, 1065: FamilyFS, 1064: FamilyFS, 1063: FamilyFS, 1062: FamilyFS, 1061: FamilyFS, 1060: FamilyFS, 1059: FamilyFS, 1058: FamilyFS, 1057: FamilyFS, 1056: FamilyFS, 1055: FamilyFS, 1054: FamilyFS, 1053: FamilyFS, 1052: FamilyFS, 1051: FamilyFS, 1050: FamilyFS, 1049: FamilyFS, 1048: FamilyFS, 1047: FamilyFS, 1046: FamilyFS, 1045: FamilyFS, 1044: FamilyFS, 1043: FamilyFS, 1042: FamilyFS, 1041: FamilyNetwork, 1040: FamilyNetwork, 1039: FamilyNetwork, 1038: FamilyNetwork, 1037: FamilyNetwork, 1036: FamilyNetwork, 1003: FamilyFS, 1002: FamilyFS, 1001: FamilyFS, 1000: FamilyFS, 999: FamilyFS, 998: FamilyFS, 997: FamilyFS, 996: FamilyFS, 995: FamilyFS, 994: FamilyFS, 993: FamilyFS, 992: FamilyFS, 991: FamilyFS, 990: FamilyFS, 989: FamilyFS, 988: FamilyFS, 987: FamilyFS, 986: FamilyFS, 985: FamilyFS, 984: FamilyFS, 983: FamilyFS, 982: FamilyFS, 981: FamilyFS, 980: FamilyFS, 979: FamilyFS, 978: FamilyFS, 977: FamilyFS, 976: FamilyFS, 975: FamilyFS, 974: FamilyFS, 973: FamilyFS, 972: FamilyFS, 971: FamilyFS, 970: FamilyFS, 969: FamilyFS, 968: FamilyFS, 967: FamilyFS, 966: FamilyFS, 965: FamilyFS, 964: FamilyFS, 963: FamilyFS, 962: FamilyFS, 961: FamilyProcess, 960: FamilyProcess, 959: FamilyFS, 958: FamilyFS, 957: FamilyFS, 956: FamilyFS, 955: FamilyFS, 954: FamilyFS, 953: FamilyFS, 952: FamilyFS, 951: FamilyMisc, 950: FamilyMisc, 949: FamilyFS, 948: FamilyFS, 947: FamilyFS, 946: FamilyFS, 945: FamilyFS, 944: FamilyFS, 943: FamilyFS, 942: FamilyFS, 937: FamilyPolling, 936: FamilyPolling, 935: FamilyPolling, 934: FamilyPolling, 933: FamilyPolling, 932: FamilyPolling, 931: FamilyPolling, 930: FamilyPolling, 929: FamilyFS, 928: FamilyFS, 927: FamilyFS, 926: FamilyFS, 925: FamilyFS, 924: FamilyFS, 923: FamilyFS, 922: FamilyFS, 921: FamilyFS, 920: FamilyFS, 919: FamilyFS, 918: FamilyFS, 917: FamilyFS, 916: FamilyFS, 915: FamilyFS, 914: FamilyFS, 913: FamilyFS, 912: FamilyFS, 911: FamilyFS, 910: FamilyFS, 909: FamilyFS, 908: FamilyFS, 907: FamilyFS, 906: FamilyFS, 905: FamilyFS, 904: FamilyFS, 903: FamilyFS, 902: FamilyFS, 901: FamilyFS, 900: FamilyFS, 899: FamilyFS, 898: FamilyFS, 897: FamilyFS, 896: FamilyFS, 895: FamilyFS, 894: FamilyFS, 893: FamilyIPC, 892: FamilyIPC, 891: FamilyIPC, 890: FamilyIPC, 889: FamilyProcess, 888: FamilyProcess, 887: FamilyProcess, 886: FamilyProcess, 885: FamilyFS, 884: FamilyFS, 883: FamilyFS, 882: FamilyFS, 881: FamilyFS, 880: FamilyFS, 879: FamilyFS, 878: FamilyFS, 877: FamilyFS, 876: FamilyFS, 875: FamilyFS, 874: FamilyFS, 873: FamilyFS, 872: FamilyFS, 871: FamilyFS, 870: FamilyFS, 869: FamilyFS, 868: FamilyFS, 867: FamilyFS, 866: FamilyFS, 865: FamilyFS, 864: FamilyFS, 863: FamilyFS, 862: FamilyFS, 861: FamilyFS, 860: FamilyFS, 859: FamilyFS, 858: FamilyFS, 857: FamilyFS, 856: FamilyFS, 855: FamilyFS, 854: FamilyFS, 853: FamilyFS, 852: FamilyFS, 851: FamilyFS, 850: FamilyFS, 849: FamilyNetwork, 848: FamilyNetwork, 847: FamilyFS, 846: FamilyFS, 845: FamilyFS, 844: FamilyFS, 843: FamilyFS, 842: FamilyFS, 841: FamilyFS, 840: FamilyFS, 839: FamilyFS, 838: FamilyFS, 837: FamilyFS, 836: FamilyFS, 835: FamilyFS, 834: FamilyFS, 833: FamilyFS, 832: FamilyFS, 831: FamilyFS, 830: FamilyFS, 829: FamilyFS, 828: FamilyFS, 827: FamilyFS, 826: FamilyFS, 825: FamilyFS, 824: FamilyFS, 823: FamilyFS, 822: FamilyFS, 821: FamilyFS, 820: FamilyFS, 819: FamilyFS, 818: FamilyFS, 817: FamilyFS, 816: FamilyFS, 815: FamilyFS, 814: FamilyFS, 813: FamilyFS, 812: FamilyFS, 811: FamilyFS, 810: FamilyFS, 809: FamilyFS, 808: FamilyFS, 807: FamilyFS, 806: FamilyFS, 805: FamilyFS, 804: FamilyFS, 803: FamilyFS, 802: FamilyFS, 801: FamilyProcess, 800: FamilyProcess, 799: FamilyIPC, 798: FamilyIPC, 791: FamilyIPC, 790: FamilyIPC, 789: FamilyIPC, 788: FamilyIPC, 768: FamilyMemory, 767: FamilyMemory, 757: FamilyMemory, 756: FamilyMemory, 755: FamilyMemory, 754: FamilyMemory, 753: FamilyMemory, 752: FamilyMemory, 751: FamilyMemory, 750: FamilyMemory, 749: FamilyMemory, 748: FamilyMemory, 747: FamilyFS, 746: FamilyFS, 745: FamilyFS, 744: FamilyFS, 743: FamilyMemory, 742: FamilyMemory, 741: FamilyMemory, 740: FamilyMemory, 739: FamilyMemory, 738: FamilyMemory, 737: FamilyMemory, 736: FamilyMemory, 735: FamilyMemory, 734: FamilyMemory, 726: FamilyFS, 725: FamilyFS, 724: FamilyMemory, 723: FamilyMemory, 722: FamilyMemory, 721: FamilyMemory, 720: FamilyMemory, 719: FamilyMemory, 718: FamilyMemory, 717: FamilyMemory, 716: FamilyMemory, 715: FamilyMemory, 712: FamilyMemory, 711: FamilyMemory, 710: FamilyMemory, 709: FamilyMemory, 708: FamilyMemory, 707: FamilyMemory, 706: FamilyMemory, 705: FamilyMemory, 704: FamilyMemory, 703: FamilyMemory, 702: FamilyMemory, 701: FamilyMemory, 700: FamilyMemory, 699: FamilyMemory, 698: FamilyMemory, 697: FamilyMemory, 696: FamilyMemory, 695: FamilyMemory, 628: FamilyFS, 627: FamilyFS, 626: FamilyFS, 625: FamilyFS, 616: FamilyMemory, 615: FamilyMemory, 607: FamilyFS, 606: FamilyFS, 603: FamilyMisc, 602: FamilyMisc, 599: FamilySecurity, 598: FamilySecurity, 597: FamilySecurity, 596: FamilySecurity, 529: FamilySecurity, 528: FamilySecurity, 511: FamilySecurity, 510: FamilySecurity, 509: FamilySecurity, 508: FamilySecurity, 507: FamilyMisc, 506: FamilyMisc, 502: FamilyMisc, 501: FamilyMisc, 500: FamilyMisc, 499: FamilyMisc, 498: FamilyIPC, 497: FamilyIPC, 496: FamilyIPC, 495: FamilyIPC, 494: FamilyIPC, 493: FamilyIPC, 492: FamilyIPC, 491: FamilyIPC, 490: FamilyIPC, 489: FamilyIPC, 474: FamilyTime, 473: FamilyTime, 472: FamilyTime, 471: FamilyTime, 470: FamilyTime, 469: FamilyTime, 468: FamilyTime, 467: FamilyTime, 466: FamilyTime, 465: FamilyTime, 464: FamilyTime, 463: FamilyTime, 462: FamilyTime, 461: FamilyTime, 460: FamilyTime, 459: FamilyTime, 458: FamilyTime, 457: FamilyTime, 456: FamilyTime, 455: FamilyTime, 454: FamilyTime, 453: FamilyTime, 452: FamilyTime, 451: FamilyTime, 450: FamilyTime, 449: FamilyTime, 444: FamilyTime, 443: FamilyTime, 426: FamilyTime, 425: FamilyTime, 424: FamilyTime, 423: FamilyTime, 422: FamilyTime, 421: FamilyTime, 420: FamilyTime, 419: FamilyTime, 418: FamilyProcess, 417: FamilyProcess, 411: FamilySecurity, 410: FamilySecurity, 409: FamilySecurity, 408: FamilySecurity, 407: FamilySecurity, 406: FamilySecurity, 351: FamilyMisc, 350: FamilyMisc, 346: FamilyMemory, 345: FamilyMemory, 341: FamilySched, 340: FamilySched, 339: FamilySched, 338: FamilySched, 337: FamilySched, 336: FamilySched, 335: FamilySched, 334: FamilySched, 333: FamilySched, 332: FamilySched, 331: FamilySched, 330: FamilySched, 329: FamilySched, 328: FamilySched, 327: FamilySched, 326: FamilySched, 325: FamilySched, 324: FamilySched, 323: FamilySched, 322: FamilySched, 321: FamilySched, 320: FamilySched, 319: FamilySched, 318: FamilySched, 286: FamilyProcess, 285: FamilyProcess, 284: FamilyProcess, 283: FamilyProcess, 282: FamilyProcess, 281: FamilyProcess, 277: FamilyFS, 276: FamilyFS, 275: FamilyProcess, 274: FamilyProcess, 273: FamilyIPC, 272: FamilyIPC, 271: FamilyIPC, 270: FamilyIPC, 265: FamilyProcess, 264: FamilyProcess, 263: FamilyProcess, 262: FamilyProcess, 261: FamilyProcess, 260: FamilyProcess, 259: FamilyProcess, 258: FamilyProcess, 257: FamilyProcess, 256: FamilyProcess, 255: FamilyProcess, 254: FamilyProcess, 253: FamilyProcess, 252: FamilyProcess, 251: FamilyProcess, 250: FamilyProcess, 249: FamilyProcess, 248: FamilyProcess, 247: FamilyProcess, 246: FamilyProcess, 245: FamilyProcess, 244: FamilyProcess, 243: FamilyProcess, 242: FamilyProcess, 241: FamilyProcess, 240: FamilyProcess, 239: FamilyProcess, 238: FamilyProcess, 237: FamilyProcess, 236: FamilyProcess, 235: FamilyProcess, 234: FamilyProcess, 233: FamilyProcess, 232: FamilyProcess, 231: FamilyProcess, 230: FamilyProcess, 229: FamilyProcess, 228: FamilyProcess, 227: FamilyTime, 226: FamilyTime, 225: FamilyProcess, 224: FamilyProcess, 223: FamilyProcess, 222: FamilyProcess, 221: FamilyProcess, 220: FamilyProcess, 219: FamilyProcess, 218: FamilyProcess, 217: FamilyProcess, 216: FamilyProcess, 215: FamilyMisc, 214: FamilyMisc, 213: FamilyMisc, 212: FamilyMisc, 211: FamilyMisc, 210: FamilyMisc, 209: FamilyProcess, 208: FamilyProcess, 207: FamilyProcess, 206: FamilyProcess, 205: FamilyProcess, 204: FamilyProcess, 203: FamilyProcess, 202: FamilyProcess, 201: FamilyProcess, 200: FamilyProcess, 199: FamilyProcess, 198: FamilyProcess, 197: FamilyMisc, 196: FamilyMisc, 195: FamilyMisc, 194: FamilyMisc, 191: FamilyProcess, 190: FamilyProcess, 189: FamilySignals, 188: FamilySignals, 187: FamilySignals, 186: FamilySignals, 185: FamilySignals, 184: FamilySignals, 183: FamilySignals, 182: FamilySignals, 181: FamilyIPC, 180: FamilyIPC, 179: FamilySignals, 178: FamilySignals, 177: FamilySignals, 176: FamilySignals, 175: FamilySignals, 174: FamilySignals, 173: FamilySignals, 172: FamilySignals, 171: FamilySignals, 170: FamilySignals, 169: FamilySignals, 168: FamilySignals, 167: FamilySignals, 166: FamilySignals, 165: FamilySignals, 164: FamilySignals, 163: FamilySecurity, 162: FamilySecurity, 161: FamilySecurity, 160: FamilySecurity, 159: FamilySecurity, 158: FamilySecurity, 150: FamilyProcess, 148: FamilyProcess, 146: FamilyProcess, 145: FamilyProcess, 144: FamilyProcess, 143: FamilyProcess, 139: FamilyProcess, 138: FamilyProcess, 134: FamilyProcess, 133: FamilyProcess, 132: FamilyProcess, 131: FamilyProcess, 130: FamilyProcess, 129: FamilyProcess, 128: FamilyProcess, 127: FamilyProcess, 126: FamilyProcess, 125: FamilyProcess, 124: FamilyProcess, 123: FamilyProcess, 119: FamilyMemory, 118: FamilyMemory, 117: FamilyMisc, 116: FamilyMisc, 115: FamilyMisc, 114: FamilyMisc, 102: FamilyProcess, 101: FamilyProcess, 100: FamilyMemory, 99: FamilyMemory, 98: FamilyMisc, 97: FamilyMisc, 95: FamilyMisc, 94: FamilyMisc, 93: FamilyMisc, 92: FamilyMisc, 57: FamilySignals,
}

var noReturnTraceIds = map[TraceId]bool{
	150: true,
	148: true,
	57:  true,
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

// Family returns the broad syscall family for this tracepoint.
func (s TraceId) Family() SyscallFamily {
	family, ok := traceId2Family[s]
	if !ok {
		return FamilyMisc
	}
	return family
}

// NoReturn reports whether this is the sys_enter tracepoint of a syscall
// that never returns to its caller (exit, exit_group, rt_sigreturn), whose
// sys_exit tracepoint therefore never fires.
func (s TraceId) NoReturn() bool {
	return noReturnTraceIds[s]
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
const ENTER_SOCKET_EVENT = 19
const EXIT_SOCKET_EVENT = 20
const ENTER_SOCKETPAIR_EVENT = 21
const EXIT_SOCKETPAIR_EVENT = 22
const ENTER_ACCEPT_EVENT = 23
const EXIT_ACCEPT_EVENT = 24
const ENTER_PIPE_EVENT = 25
const EXIT_PIPE_EVENT = 26
const ENTER_EVENTFD_EVENT = 27
const EXIT_EVENTFD_EVENT = 28
const ENTER_EPOLL_CTL_EVENT = 29
const EXIT_EPOLL_CTL_EVENT = 30
const ENTER_POLL_EVENT = 31
const EXIT_POLL_EVENT = 32
const ENTER_MEM_EVENT = 33
const EXIT_MEM_EVENT = 34
const ENTER_SLEEP_EVENT = 35
const EXIT_SLEEP_EVENT = 36
const ENTER_TWO_FD_EVENT = 37
const EXIT_TWO_FD_EVENT = 38
const ENTER_KEYCTL_EVENT = 39
const EXIT_KEYCTL_EVENT = 40
const ENTER_PTRACE_EVENT = 41
const EXIT_PTRACE_EVENT = 42
const ENTER_PERF_OPEN_EVENT = 43
const EXIT_PERF_OPEN_EVENT = 44
const ENTER_EXEC_EVENT = 45
const EXIT_EXEC_EVENT = 46
const PROCESS_EXEC_EVENT = 47
const OPEN_NAME_FIXUP_EVENT = 48
const PROCESS_EXIT_EVENT = 49
const ENTER_MMAP_EVENT = 50
const EXIT_MMAP_EVENT = 51
const ENTER_BPF_EVENT = 52
const EXIT_BPF_EVENT = 53
const ENTER_FD_PATH_EVENT = 54
const EXIT_FD_PATH_EVENT = 55
const ENTER_FD_SIZE_EVENT = 56
const EXIT_FD_SIZE_EVENT = 57
const ENTER_TWO_FD_NAMES_EVENT = 58
const EXIT_TWO_FD_NAMES_EVENT = 59
const ENTER_EVENTFD_NAME_EVENT = 60
const EXIT_EVENTFD_NAME_EVENT = 61
const TASK_NEWTASK_EVENT = 62
const TASK_RENAME_EVENT = 63
const SYSCALL_RESTART_EVENT = 64
const FILE_HANDLE_EVENT = 65
const ENTER_FD_NAME_EVENT = 66
const RING_FDS_EVENT = 67
const UNCLASSIFIED = 0
const READ_CLASSIFIED = 1
const WRITE_CLASSIFIED = 2
const TRANSFER_CLASSIFIED = 3
const PATH_READ_OK = 0
const PATH_READ_NULL = 1
const PATH_READ_FAILED = 2
const PATH_TARGET_REQUIRED = 0
const PATH_TARGET_SKIPPED = 1
const PATH_TARGET_UNKNOWN = 2
const IOR_UTIME_OMIT = 1073741822
const OPEN_EVENT_SCHEMA_VERSION = 3
const FD_SIZE_EVENT_SCHEMA_VERSION = 1
const FD_EVENT_SCHEMA_VERSION = 1
const PATH_EVENT_SCHEMA_VERSION = 4
const NAME_EVENT_SCHEMA_VERSION = 2
const EVENTFD_NAME_EVENT_SCHEMA_VERSION = 2
const EVENTFD_EVENT_SCHEMA_VERSION = 2
const ACCEPT_EVENT_SCHEMA_VERSION = 1
const TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION = 2
const TWO_FD_EVENT_SCHEMA_VERSION = 3
const FD_PATH_EVENT_SCHEMA_VERSION = 1
const POLL_EVENT_SCHEMA_VERSION = 1
const EXEC_EVENT_SCHEMA_VERSION = 1
const POLL_TIMEOUT_INFINITE_NS = -1
const POLL_TIMEOUT_UNKNOWN_NS = -2
const OPEN_NAME_FIXUP_SLOT_FIRST = 0
const OPEN_NAME_FIXUP_SLOT_SECOND = 1
const IOR_MAX_HANDLE_SZ = 128
const FILE_HANDLE_NONE = 0
const FILE_HANDLE_OK = 1
const FILE_HANDLE_NULL = 2
const FILE_HANDLE_READ_FAILED = 3
const FILE_HANDLE_TOO_LARGE = 4
const IOR_REGISTER_RING_FDS = 20
const IOR_UNREGISTER_RING_FDS = 21
const IOR_RING_FDS_MAX = 16
const IOR_RING_FD_UPDATE_SIZE = 16
const IOR_RING_FDS_BYTES = 256
const RING_FDS_OK = 1
const RING_FDS_READ_FAILED = 2
const RING_FDS_TOO_MANY = 3
const IOR_FD_NAME_LENGTH = 68
const RESTART_PHASE_HANDLER = 1
const RESTART_PHASE_RESUME = 2
const SYS_ENTER_SOCKET TraceId = 1899
const SYS_EXIT_SOCKET TraceId = 1898
const SYS_ENTER_SOCKETPAIR TraceId = 1897
const SYS_EXIT_SOCKETPAIR TraceId = 1896
const SYS_ENTER_BIND TraceId = 1895
const SYS_EXIT_BIND TraceId = 1894
const SYS_ENTER_LISTEN TraceId = 1893
const SYS_EXIT_LISTEN TraceId = 1892
const SYS_ENTER_ACCEPT4 TraceId = 1891
const SYS_EXIT_ACCEPT4 TraceId = 1890
const SYS_ENTER_ACCEPT TraceId = 1889
const SYS_EXIT_ACCEPT TraceId = 1888
const SYS_ENTER_CONNECT TraceId = 1887
const SYS_EXIT_CONNECT TraceId = 1886
const SYS_ENTER_GETSOCKNAME TraceId = 1885
const SYS_EXIT_GETSOCKNAME TraceId = 1884
const SYS_ENTER_GETPEERNAME TraceId = 1883
const SYS_EXIT_GETPEERNAME TraceId = 1882
const SYS_ENTER_SENDTO TraceId = 1881
const SYS_EXIT_SENDTO TraceId = 1880
const SYS_ENTER_RECVFROM TraceId = 1879
const SYS_EXIT_RECVFROM TraceId = 1878
const SYS_ENTER_SETSOCKOPT TraceId = 1877
const SYS_EXIT_SETSOCKOPT TraceId = 1876
const SYS_ENTER_GETSOCKOPT TraceId = 1875
const SYS_EXIT_GETSOCKOPT TraceId = 1874
const SYS_ENTER_SHUTDOWN TraceId = 1873
const SYS_EXIT_SHUTDOWN TraceId = 1872
const SYS_ENTER_SENDMSG TraceId = 1871
const SYS_EXIT_SENDMSG TraceId = 1870
const SYS_ENTER_SENDMMSG TraceId = 1869
const SYS_EXIT_SENDMMSG TraceId = 1868
const SYS_ENTER_RECVMSG TraceId = 1867
const SYS_EXIT_RECVMSG TraceId = 1866
const SYS_ENTER_RECVMMSG TraceId = 1865
const SYS_EXIT_RECVMMSG TraceId = 1864
const SYS_ENTER_GETRANDOM TraceId = 1626
const SYS_EXIT_GETRANDOM TraceId = 1625
const SYS_ENTER_IO_URING_REGISTER TraceId = 1578
const SYS_EXIT_IO_URING_REGISTER TraceId = 1577
const SYS_ENTER_IO_URING_ENTER TraceId = 1559
const SYS_EXIT_IO_URING_ENTER TraceId = 1558
const SYS_ENTER_IO_URING_SETUP TraceId = 1557
const SYS_EXIT_IO_URING_SETUP TraceId = 1556
const SYS_ENTER_IOPRIO_SET TraceId = 1541
const SYS_EXIT_IOPRIO_SET TraceId = 1540
const SYS_ENTER_IOPRIO_GET TraceId = 1539
const SYS_EXIT_IOPRIO_GET TraceId = 1538
const SYS_ENTER_LANDLOCK_CREATE_RULESET TraceId = 1512
const SYS_EXIT_LANDLOCK_CREATE_RULESET TraceId = 1511
const SYS_ENTER_LANDLOCK_ADD_RULE TraceId = 1510
const SYS_EXIT_LANDLOCK_ADD_RULE TraceId = 1509
const SYS_ENTER_LANDLOCK_RESTRICT_SELF TraceId = 1508
const SYS_EXIT_LANDLOCK_RESTRICT_SELF TraceId = 1507
const SYS_ENTER_LSM_SET_SELF_ATTR TraceId = 1505
const SYS_EXIT_LSM_SET_SELF_ATTR TraceId = 1504
const SYS_ENTER_LSM_GET_SELF_ATTR TraceId = 1503
const SYS_EXIT_LSM_GET_SELF_ATTR TraceId = 1502
const SYS_ENTER_LSM_LIST_MODULES TraceId = 1501
const SYS_EXIT_LSM_LIST_MODULES TraceId = 1500
const SYS_ENTER_ADD_KEY TraceId = 1498
const SYS_EXIT_ADD_KEY TraceId = 1497
const SYS_ENTER_REQUEST_KEY TraceId = 1496
const SYS_EXIT_REQUEST_KEY TraceId = 1495
const SYS_ENTER_KEYCTL TraceId = 1494
const SYS_EXIT_KEYCTL TraceId = 1493
const SYS_ENTER_MQ_OPEN TraceId = 1492
const SYS_EXIT_MQ_OPEN TraceId = 1491
const SYS_ENTER_MQ_UNLINK TraceId = 1490
const SYS_EXIT_MQ_UNLINK TraceId = 1489
const SYS_ENTER_MQ_TIMEDSEND TraceId = 1488
const SYS_EXIT_MQ_TIMEDSEND TraceId = 1487
const SYS_ENTER_MQ_TIMEDRECEIVE TraceId = 1486
const SYS_EXIT_MQ_TIMEDRECEIVE TraceId = 1485
const SYS_ENTER_MQ_NOTIFY TraceId = 1484
const SYS_EXIT_MQ_NOTIFY TraceId = 1483
const SYS_ENTER_MQ_GETSETATTR TraceId = 1482
const SYS_EXIT_MQ_GETSETATTR TraceId = 1481
const SYS_ENTER_SHMGET TraceId = 1480
const SYS_EXIT_SHMGET TraceId = 1479
const SYS_ENTER_SHMCTL TraceId = 1478
const SYS_EXIT_SHMCTL TraceId = 1477
const SYS_ENTER_SHMAT TraceId = 1476
const SYS_EXIT_SHMAT TraceId = 1475
const SYS_ENTER_SHMDT TraceId = 1474
const SYS_EXIT_SHMDT TraceId = 1473
const SYS_ENTER_SEMGET TraceId = 1472
const SYS_EXIT_SEMGET TraceId = 1471
const SYS_ENTER_SEMCTL TraceId = 1470
const SYS_EXIT_SEMCTL TraceId = 1469
const SYS_ENTER_SEMTIMEDOP TraceId = 1468
const SYS_EXIT_SEMTIMEDOP TraceId = 1467
const SYS_ENTER_SEMOP TraceId = 1466
const SYS_EXIT_SEMOP TraceId = 1465
const SYS_ENTER_MSGGET TraceId = 1464
const SYS_EXIT_MSGGET TraceId = 1463
const SYS_ENTER_MSGCTL TraceId = 1462
const SYS_EXIT_MSGCTL TraceId = 1461
const SYS_ENTER_MSGSND TraceId = 1460
const SYS_EXIT_MSGSND TraceId = 1459
const SYS_ENTER_MSGRCV TraceId = 1458
const SYS_EXIT_MSGRCV TraceId = 1457
const SYS_ENTER_QUOTACTL TraceId = 1183
const SYS_EXIT_QUOTACTL TraceId = 1182
const SYS_ENTER_QUOTACTL_FD TraceId = 1181
const SYS_EXIT_QUOTACTL_FD TraceId = 1180
const SYS_ENTER_NAME_TO_HANDLE_AT TraceId = 1165
const SYS_EXIT_NAME_TO_HANDLE_AT TraceId = 1164
const SYS_ENTER_OPEN_BY_HANDLE_AT TraceId = 1163
const SYS_EXIT_OPEN_BY_HANDLE_AT TraceId = 1162
const SYS_ENTER_FLOCK TraceId = 1147
const SYS_EXIT_FLOCK TraceId = 1146
const SYS_ENTER_IO_SETUP TraceId = 1128
const SYS_EXIT_IO_SETUP TraceId = 1127
const SYS_ENTER_IO_DESTROY TraceId = 1126
const SYS_EXIT_IO_DESTROY TraceId = 1125
const SYS_ENTER_IO_SUBMIT TraceId = 1124
const SYS_EXIT_IO_SUBMIT TraceId = 1123
const SYS_ENTER_IO_CANCEL TraceId = 1122
const SYS_EXIT_IO_CANCEL TraceId = 1121
const SYS_ENTER_IO_GETEVENTS TraceId = 1120
const SYS_EXIT_IO_GETEVENTS TraceId = 1119
const SYS_ENTER_IO_PGETEVENTS TraceId = 1118
const SYS_EXIT_IO_PGETEVENTS TraceId = 1117
const SYS_ENTER_EVENTFD2 TraceId = 1116
const SYS_EXIT_EVENTFD2 TraceId = 1115
const SYS_ENTER_EVENTFD TraceId = 1114
const SYS_EXIT_EVENTFD TraceId = 1113
const SYS_ENTER_TIMERFD_CREATE TraceId = 1112
const SYS_EXIT_TIMERFD_CREATE TraceId = 1111
const SYS_ENTER_TIMERFD_SETTIME TraceId = 1110
const SYS_EXIT_TIMERFD_SETTIME TraceId = 1109
const SYS_ENTER_TIMERFD_GETTIME TraceId = 1108
const SYS_EXIT_TIMERFD_GETTIME TraceId = 1107
const SYS_ENTER_SIGNALFD4 TraceId = 1106
const SYS_EXIT_SIGNALFD4 TraceId = 1105
const SYS_ENTER_SIGNALFD TraceId = 1104
const SYS_EXIT_SIGNALFD TraceId = 1103
const SYS_ENTER_EPOLL_CREATE1 TraceId = 1102
const SYS_EXIT_EPOLL_CREATE1 TraceId = 1101
const SYS_ENTER_EPOLL_CREATE TraceId = 1100
const SYS_EXIT_EPOLL_CREATE TraceId = 1099
const SYS_ENTER_EPOLL_CTL TraceId = 1098
const SYS_EXIT_EPOLL_CTL TraceId = 1097
const SYS_ENTER_EPOLL_WAIT TraceId = 1096
const SYS_EXIT_EPOLL_WAIT TraceId = 1095
const SYS_ENTER_EPOLL_PWAIT TraceId = 1094
const SYS_EXIT_EPOLL_PWAIT TraceId = 1093
const SYS_ENTER_EPOLL_PWAIT2 TraceId = 1092
const SYS_EXIT_EPOLL_PWAIT2 TraceId = 1091
const SYS_ENTER_FANOTIFY_INIT TraceId = 1090
const SYS_EXIT_FANOTIFY_INIT TraceId = 1089
const SYS_ENTER_FANOTIFY_MARK TraceId = 1088
const SYS_EXIT_FANOTIFY_MARK TraceId = 1087
const SYS_ENTER_INOTIFY_INIT1 TraceId = 1086
const SYS_EXIT_INOTIFY_INIT1 TraceId = 1085
const SYS_ENTER_INOTIFY_INIT TraceId = 1084
const SYS_EXIT_INOTIFY_INIT TraceId = 1083
const SYS_ENTER_INOTIFY_ADD_WATCH TraceId = 1082
const SYS_EXIT_INOTIFY_ADD_WATCH TraceId = 1081
const SYS_ENTER_INOTIFY_RM_WATCH TraceId = 1080
const SYS_EXIT_INOTIFY_RM_WATCH TraceId = 1079
const SYS_ENTER_FILE_GETATTR TraceId = 1077
const SYS_EXIT_FILE_GETATTR TraceId = 1076
const SYS_ENTER_FILE_SETATTR TraceId = 1075
const SYS_EXIT_FILE_SETATTR TraceId = 1074
const SYS_ENTER_FSOPEN TraceId = 1073
const SYS_EXIT_FSOPEN TraceId = 1072
const SYS_ENTER_FSPICK TraceId = 1071
const SYS_EXIT_FSPICK TraceId = 1070
const SYS_ENTER_FSCONFIG TraceId = 1069
const SYS_EXIT_FSCONFIG TraceId = 1068
const SYS_ENTER_STATFS TraceId = 1067
const SYS_EXIT_STATFS TraceId = 1066
const SYS_ENTER_FSTATFS TraceId = 1065
const SYS_EXIT_FSTATFS TraceId = 1064
const SYS_ENTER_USTAT TraceId = 1063
const SYS_EXIT_USTAT TraceId = 1062
const SYS_ENTER_GETCWD TraceId = 1061
const SYS_EXIT_GETCWD TraceId = 1060
const SYS_ENTER_UTIMENSAT TraceId = 1059
const SYS_EXIT_UTIMENSAT TraceId = 1058
const SYS_ENTER_FUTIMESAT TraceId = 1057
const SYS_EXIT_FUTIMESAT TraceId = 1056
const SYS_ENTER_UTIMES TraceId = 1055
const SYS_EXIT_UTIMES TraceId = 1054
const SYS_ENTER_UTIME TraceId = 1053
const SYS_EXIT_UTIME TraceId = 1052
const SYS_ENTER_SYNC TraceId = 1051
const SYS_EXIT_SYNC TraceId = 1050
const SYS_ENTER_SYNCFS TraceId = 1049
const SYS_EXIT_SYNCFS TraceId = 1048
const SYS_ENTER_FSYNC TraceId = 1047
const SYS_EXIT_FSYNC TraceId = 1046
const SYS_ENTER_FDATASYNC TraceId = 1045
const SYS_EXIT_FDATASYNC TraceId = 1044
const SYS_ENTER_SYNC_FILE_RANGE TraceId = 1043
const SYS_EXIT_SYNC_FILE_RANGE TraceId = 1042
const SYS_ENTER_VMSPLICE TraceId = 1041
const SYS_EXIT_VMSPLICE TraceId = 1040
const SYS_ENTER_SPLICE TraceId = 1039
const SYS_EXIT_SPLICE TraceId = 1038
const SYS_ENTER_TEE TraceId = 1037
const SYS_EXIT_TEE TraceId = 1036
const SYS_ENTER_SETXATTRAT TraceId = 1003
const SYS_EXIT_SETXATTRAT TraceId = 1002
const SYS_ENTER_SETXATTR TraceId = 1001
const SYS_EXIT_SETXATTR TraceId = 1000
const SYS_ENTER_LSETXATTR TraceId = 999
const SYS_EXIT_LSETXATTR TraceId = 998
const SYS_ENTER_FSETXATTR TraceId = 997
const SYS_EXIT_FSETXATTR TraceId = 996
const SYS_ENTER_GETXATTRAT TraceId = 995
const SYS_EXIT_GETXATTRAT TraceId = 994
const SYS_ENTER_GETXATTR TraceId = 993
const SYS_EXIT_GETXATTR TraceId = 992
const SYS_ENTER_LGETXATTR TraceId = 991
const SYS_EXIT_LGETXATTR TraceId = 990
const SYS_ENTER_FGETXATTR TraceId = 989
const SYS_EXIT_FGETXATTR TraceId = 988
const SYS_ENTER_LISTXATTRAT TraceId = 987
const SYS_EXIT_LISTXATTRAT TraceId = 986
const SYS_ENTER_LISTXATTR TraceId = 985
const SYS_EXIT_LISTXATTR TraceId = 984
const SYS_ENTER_LLISTXATTR TraceId = 983
const SYS_EXIT_LLISTXATTR TraceId = 982
const SYS_ENTER_FLISTXATTR TraceId = 981
const SYS_EXIT_FLISTXATTR TraceId = 980
const SYS_ENTER_REMOVEXATTRAT TraceId = 979
const SYS_EXIT_REMOVEXATTRAT TraceId = 978
const SYS_ENTER_REMOVEXATTR TraceId = 977
const SYS_EXIT_REMOVEXATTR TraceId = 976
const SYS_ENTER_LREMOVEXATTR TraceId = 975
const SYS_EXIT_LREMOVEXATTR TraceId = 974
const SYS_ENTER_FREMOVEXATTR TraceId = 973
const SYS_EXIT_FREMOVEXATTR TraceId = 972
const SYS_ENTER_UMOUNT TraceId = 971
const SYS_EXIT_UMOUNT TraceId = 970
const SYS_ENTER_OPEN_TREE TraceId = 969
const SYS_EXIT_OPEN_TREE TraceId = 968
const SYS_ENTER_MOUNT TraceId = 967
const SYS_EXIT_MOUNT TraceId = 966
const SYS_ENTER_FSMOUNT TraceId = 965
const SYS_EXIT_FSMOUNT TraceId = 964
const SYS_ENTER_MOVE_MOUNT TraceId = 963
const SYS_EXIT_MOVE_MOUNT TraceId = 962
const SYS_ENTER_PIVOT_ROOT TraceId = 961
const SYS_EXIT_PIVOT_ROOT TraceId = 960
const SYS_ENTER_MOUNT_SETATTR TraceId = 959
const SYS_EXIT_MOUNT_SETATTR TraceId = 958
const SYS_ENTER_OPEN_TREE_ATTR TraceId = 957
const SYS_EXIT_OPEN_TREE_ATTR TraceId = 956
const SYS_ENTER_STATMOUNT TraceId = 955
const SYS_EXIT_STATMOUNT TraceId = 954
const SYS_ENTER_LISTMOUNT TraceId = 953
const SYS_EXIT_LISTMOUNT TraceId = 952
const SYS_ENTER_SYSFS TraceId = 951
const SYS_EXIT_SYSFS TraceId = 950
const SYS_ENTER_CLOSE_RANGE TraceId = 949
const SYS_EXIT_CLOSE_RANGE TraceId = 948
const SYS_ENTER_DUP3 TraceId = 947
const SYS_EXIT_DUP3 TraceId = 946
const SYS_ENTER_DUP2 TraceId = 945
const SYS_EXIT_DUP2 TraceId = 944
const SYS_ENTER_DUP TraceId = 943
const SYS_EXIT_DUP TraceId = 942
const SYS_ENTER_SELECT TraceId = 937
const SYS_EXIT_SELECT TraceId = 936
const SYS_ENTER_PSELECT6 TraceId = 935
const SYS_EXIT_PSELECT6 TraceId = 934
const SYS_ENTER_POLL TraceId = 933
const SYS_EXIT_POLL TraceId = 932
const SYS_ENTER_PPOLL TraceId = 931
const SYS_EXIT_PPOLL TraceId = 930
const SYS_ENTER_GETDENTS TraceId = 929
const SYS_EXIT_GETDENTS TraceId = 928
const SYS_ENTER_GETDENTS64 TraceId = 927
const SYS_EXIT_GETDENTS64 TraceId = 926
const SYS_ENTER_IOCTL TraceId = 925
const SYS_EXIT_IOCTL TraceId = 924
const SYS_ENTER_FCNTL TraceId = 923
const SYS_EXIT_FCNTL TraceId = 922
const SYS_ENTER_MKNODAT TraceId = 921
const SYS_EXIT_MKNODAT TraceId = 920
const SYS_ENTER_MKNOD TraceId = 919
const SYS_EXIT_MKNOD TraceId = 918
const SYS_ENTER_MKDIRAT TraceId = 917
const SYS_EXIT_MKDIRAT TraceId = 916
const SYS_ENTER_MKDIR TraceId = 915
const SYS_EXIT_MKDIR TraceId = 914
const SYS_ENTER_RMDIR TraceId = 913
const SYS_EXIT_RMDIR TraceId = 912
const SYS_ENTER_UNLINKAT TraceId = 911
const SYS_EXIT_UNLINKAT TraceId = 910
const SYS_ENTER_UNLINK TraceId = 909
const SYS_EXIT_UNLINK TraceId = 908
const SYS_ENTER_SYMLINKAT TraceId = 907
const SYS_EXIT_SYMLINKAT TraceId = 906
const SYS_ENTER_SYMLINK TraceId = 905
const SYS_EXIT_SYMLINK TraceId = 904
const SYS_ENTER_LINKAT TraceId = 903
const SYS_EXIT_LINKAT TraceId = 902
const SYS_ENTER_LINK TraceId = 901
const SYS_EXIT_LINK TraceId = 900
const SYS_ENTER_RENAMEAT2 TraceId = 899
const SYS_EXIT_RENAMEAT2 TraceId = 898
const SYS_ENTER_RENAMEAT TraceId = 897
const SYS_EXIT_RENAMEAT TraceId = 896
const SYS_ENTER_RENAME TraceId = 895
const SYS_EXIT_RENAME TraceId = 894
const SYS_ENTER_PIPE2 TraceId = 893
const SYS_EXIT_PIPE2 TraceId = 892
const SYS_ENTER_PIPE TraceId = 891
const SYS_EXIT_PIPE TraceId = 890
const SYS_ENTER_EXECVE TraceId = 889
const SYS_EXIT_EXECVE TraceId = 888
const SYS_ENTER_EXECVEAT TraceId = 887
const SYS_EXIT_EXECVEAT TraceId = 886
const SYS_ENTER_NEWSTAT TraceId = 885
const SYS_EXIT_NEWSTAT TraceId = 884
const SYS_ENTER_NEWLSTAT TraceId = 883
const SYS_EXIT_NEWLSTAT TraceId = 882
const SYS_ENTER_NEWFSTATAT TraceId = 881
const SYS_EXIT_NEWFSTATAT TraceId = 880
const SYS_ENTER_NEWFSTAT TraceId = 879
const SYS_EXIT_NEWFSTAT TraceId = 878
const SYS_ENTER_READLINKAT TraceId = 877
const SYS_EXIT_READLINKAT TraceId = 876
const SYS_ENTER_READLINK TraceId = 875
const SYS_EXIT_READLINK TraceId = 874
const SYS_ENTER_STATX TraceId = 873
const SYS_EXIT_STATX TraceId = 872
const SYS_ENTER_LSEEK TraceId = 871
const SYS_EXIT_LSEEK TraceId = 870
const SYS_ENTER_READ TraceId = 869
const SYS_EXIT_READ TraceId = 868
const SYS_ENTER_WRITE TraceId = 867
const SYS_EXIT_WRITE TraceId = 866
const SYS_ENTER_PREAD64 TraceId = 865
const SYS_EXIT_PREAD64 TraceId = 864
const SYS_ENTER_PWRITE64 TraceId = 863
const SYS_EXIT_PWRITE64 TraceId = 862
const SYS_ENTER_READV TraceId = 861
const SYS_EXIT_READV TraceId = 860
const SYS_ENTER_WRITEV TraceId = 859
const SYS_EXIT_WRITEV TraceId = 858
const SYS_ENTER_PREADV TraceId = 857
const SYS_EXIT_PREADV TraceId = 856
const SYS_ENTER_PREADV2 TraceId = 855
const SYS_EXIT_PREADV2 TraceId = 854
const SYS_ENTER_PWRITEV TraceId = 853
const SYS_EXIT_PWRITEV TraceId = 852
const SYS_ENTER_PWRITEV2 TraceId = 851
const SYS_EXIT_PWRITEV2 TraceId = 850
const SYS_ENTER_SENDFILE64 TraceId = 849
const SYS_EXIT_SENDFILE64 TraceId = 848
const SYS_ENTER_COPY_FILE_RANGE TraceId = 847
const SYS_EXIT_COPY_FILE_RANGE TraceId = 846
const SYS_ENTER_TRUNCATE TraceId = 845
const SYS_EXIT_TRUNCATE TraceId = 844
const SYS_ENTER_FTRUNCATE TraceId = 843
const SYS_EXIT_FTRUNCATE TraceId = 842
const SYS_ENTER_FALLOCATE TraceId = 841
const SYS_EXIT_FALLOCATE TraceId = 840
const SYS_ENTER_FACCESSAT TraceId = 839
const SYS_EXIT_FACCESSAT TraceId = 838
const SYS_ENTER_FACCESSAT2 TraceId = 837
const SYS_EXIT_FACCESSAT2 TraceId = 836
const SYS_ENTER_ACCESS TraceId = 835
const SYS_EXIT_ACCESS TraceId = 834
const SYS_ENTER_CHDIR TraceId = 833
const SYS_EXIT_CHDIR TraceId = 832
const SYS_ENTER_FCHDIR TraceId = 831
const SYS_EXIT_FCHDIR TraceId = 830
const SYS_ENTER_CHROOT TraceId = 829
const SYS_EXIT_CHROOT TraceId = 828
const SYS_ENTER_FCHMOD TraceId = 827
const SYS_EXIT_FCHMOD TraceId = 826
const SYS_ENTER_FCHMODAT2 TraceId = 825
const SYS_EXIT_FCHMODAT2 TraceId = 824
const SYS_ENTER_FCHMODAT TraceId = 823
const SYS_EXIT_FCHMODAT TraceId = 822
const SYS_ENTER_CHMOD TraceId = 821
const SYS_EXIT_CHMOD TraceId = 820
const SYS_ENTER_FCHOWNAT TraceId = 819
const SYS_EXIT_FCHOWNAT TraceId = 818
const SYS_ENTER_CHOWN TraceId = 817
const SYS_EXIT_CHOWN TraceId = 816
const SYS_ENTER_LCHOWN TraceId = 815
const SYS_EXIT_LCHOWN TraceId = 814
const SYS_ENTER_FCHOWN TraceId = 813
const SYS_EXIT_FCHOWN TraceId = 812
const SYS_ENTER_OPEN TraceId = 811
const SYS_EXIT_OPEN TraceId = 810
const SYS_ENTER_OPENAT TraceId = 809
const SYS_EXIT_OPENAT TraceId = 808
const SYS_ENTER_OPENAT2 TraceId = 807
const SYS_EXIT_OPENAT2 TraceId = 806
const SYS_ENTER_CREAT TraceId = 805
const SYS_EXIT_CREAT TraceId = 804
const SYS_ENTER_CLOSE TraceId = 803
const SYS_EXIT_CLOSE TraceId = 802
const SYS_ENTER_VHANGUP TraceId = 801
const SYS_EXIT_VHANGUP TraceId = 800
const SYS_ENTER_MEMFD_CREATE TraceId = 799
const SYS_EXIT_MEMFD_CREATE TraceId = 798
const SYS_ENTER_USERFAULTFD TraceId = 791
const SYS_EXIT_USERFAULTFD TraceId = 790
const SYS_ENTER_MEMFD_SECRET TraceId = 789
const SYS_EXIT_MEMFD_SECRET TraceId = 788
const SYS_ENTER_MOVE_PAGES TraceId = 768
const SYS_EXIT_MOVE_PAGES TraceId = 767
const SYS_ENTER_SET_MEMPOLICY_HOME_NODE TraceId = 757
const SYS_EXIT_SET_MEMPOLICY_HOME_NODE TraceId = 756
const SYS_ENTER_MBIND TraceId = 755
const SYS_EXIT_MBIND TraceId = 754
const SYS_ENTER_SET_MEMPOLICY TraceId = 753
const SYS_EXIT_SET_MEMPOLICY TraceId = 752
const SYS_ENTER_MIGRATE_PAGES TraceId = 751
const SYS_EXIT_MIGRATE_PAGES TraceId = 750
const SYS_ENTER_GET_MEMPOLICY TraceId = 749
const SYS_EXIT_GET_MEMPOLICY TraceId = 748
const SYS_ENTER_SWAPOFF TraceId = 747
const SYS_EXIT_SWAPOFF TraceId = 746
const SYS_ENTER_SWAPON TraceId = 745
const SYS_EXIT_SWAPON TraceId = 744
const SYS_ENTER_MADVISE TraceId = 743
const SYS_EXIT_MADVISE TraceId = 742
const SYS_ENTER_PROCESS_MADVISE TraceId = 741
const SYS_EXIT_PROCESS_MADVISE TraceId = 740
const SYS_ENTER_MSEAL TraceId = 739
const SYS_EXIT_MSEAL TraceId = 738
const SYS_ENTER_PROCESS_VM_READV TraceId = 737
const SYS_EXIT_PROCESS_VM_READV TraceId = 736
const SYS_ENTER_PROCESS_VM_WRITEV TraceId = 735
const SYS_EXIT_PROCESS_VM_WRITEV TraceId = 734
const SYS_ENTER_MSYNC TraceId = 726
const SYS_EXIT_MSYNC TraceId = 725
const SYS_ENTER_MREMAP TraceId = 724
const SYS_EXIT_MREMAP TraceId = 723
const SYS_ENTER_MPROTECT TraceId = 722
const SYS_EXIT_MPROTECT TraceId = 721
const SYS_ENTER_PKEY_MPROTECT TraceId = 720
const SYS_EXIT_PKEY_MPROTECT TraceId = 719
const SYS_ENTER_PKEY_ALLOC TraceId = 718
const SYS_EXIT_PKEY_ALLOC TraceId = 717
const SYS_ENTER_PKEY_FREE TraceId = 716
const SYS_EXIT_PKEY_FREE TraceId = 715
const SYS_ENTER_BRK TraceId = 712
const SYS_EXIT_BRK TraceId = 711
const SYS_ENTER_MUNMAP TraceId = 710
const SYS_EXIT_MUNMAP TraceId = 709
const SYS_ENTER_REMAP_FILE_PAGES TraceId = 708
const SYS_EXIT_REMAP_FILE_PAGES TraceId = 707
const SYS_ENTER_MLOCK TraceId = 706
const SYS_EXIT_MLOCK TraceId = 705
const SYS_ENTER_MLOCK2 TraceId = 704
const SYS_EXIT_MLOCK2 TraceId = 703
const SYS_ENTER_MUNLOCK TraceId = 702
const SYS_EXIT_MUNLOCK TraceId = 701
const SYS_ENTER_MLOCKALL TraceId = 700
const SYS_EXIT_MLOCKALL TraceId = 699
const SYS_ENTER_MUNLOCKALL TraceId = 698
const SYS_EXIT_MUNLOCKALL TraceId = 697
const SYS_ENTER_MINCORE TraceId = 696
const SYS_EXIT_MINCORE TraceId = 695
const SYS_ENTER_READAHEAD TraceId = 628
const SYS_EXIT_READAHEAD TraceId = 627
const SYS_ENTER_FADVISE64 TraceId = 626
const SYS_EXIT_FADVISE64 TraceId = 625
const SYS_ENTER_PROCESS_MRELEASE TraceId = 616
const SYS_EXIT_PROCESS_MRELEASE TraceId = 615
const SYS_ENTER_CACHESTAT TraceId = 607
const SYS_EXIT_CACHESTAT TraceId = 606
const SYS_ENTER_RSEQ TraceId = 603
const SYS_EXIT_RSEQ TraceId = 602
const SYS_ENTER_PERF_EVENT_OPEN TraceId = 599
const SYS_EXIT_PERF_EVENT_OPEN TraceId = 598
const SYS_ENTER_BPF TraceId = 597
const SYS_EXIT_BPF TraceId = 596
const SYS_ENTER_SECCOMP TraceId = 529
const SYS_EXIT_SECCOMP TraceId = 528
const SYS_ENTER_KEXEC_FILE_LOAD TraceId = 511
const SYS_EXIT_KEXEC_FILE_LOAD TraceId = 510
const SYS_ENTER_KEXEC_LOAD TraceId = 509
const SYS_EXIT_KEXEC_LOAD TraceId = 508
const SYS_ENTER_ACCT TraceId = 507
const SYS_EXIT_ACCT TraceId = 506
const SYS_ENTER_SET_ROBUST_LIST TraceId = 502
const SYS_EXIT_SET_ROBUST_LIST TraceId = 501
const SYS_ENTER_GET_ROBUST_LIST TraceId = 500
const SYS_EXIT_GET_ROBUST_LIST TraceId = 499
const SYS_ENTER_FUTEX TraceId = 498
const SYS_EXIT_FUTEX TraceId = 497
const SYS_ENTER_FUTEX_WAITV TraceId = 496
const SYS_EXIT_FUTEX_WAITV TraceId = 495
const SYS_ENTER_FUTEX_WAKE TraceId = 494
const SYS_EXIT_FUTEX_WAKE TraceId = 493
const SYS_ENTER_FUTEX_WAIT TraceId = 492
const SYS_EXIT_FUTEX_WAIT TraceId = 491
const SYS_ENTER_FUTEX_REQUEUE TraceId = 490
const SYS_EXIT_FUTEX_REQUEUE TraceId = 489
const SYS_ENTER_GETITIMER TraceId = 474
const SYS_EXIT_GETITIMER TraceId = 473
const SYS_ENTER_ALARM TraceId = 472
const SYS_EXIT_ALARM TraceId = 471
const SYS_ENTER_SETITIMER TraceId = 470
const SYS_EXIT_SETITIMER TraceId = 469
const SYS_ENTER_TIMER_CREATE TraceId = 468
const SYS_EXIT_TIMER_CREATE TraceId = 467
const SYS_ENTER_TIMER_GETTIME TraceId = 466
const SYS_EXIT_TIMER_GETTIME TraceId = 465
const SYS_ENTER_TIMER_GETOVERRUN TraceId = 464
const SYS_EXIT_TIMER_GETOVERRUN TraceId = 463
const SYS_ENTER_TIMER_SETTIME TraceId = 462
const SYS_EXIT_TIMER_SETTIME TraceId = 461
const SYS_ENTER_TIMER_DELETE TraceId = 460
const SYS_EXIT_TIMER_DELETE TraceId = 459
const SYS_ENTER_CLOCK_SETTIME TraceId = 458
const SYS_EXIT_CLOCK_SETTIME TraceId = 457
const SYS_ENTER_CLOCK_GETTIME TraceId = 456
const SYS_EXIT_CLOCK_GETTIME TraceId = 455
const SYS_ENTER_CLOCK_ADJTIME TraceId = 454
const SYS_EXIT_CLOCK_ADJTIME TraceId = 453
const SYS_ENTER_CLOCK_GETRES TraceId = 452
const SYS_EXIT_CLOCK_GETRES TraceId = 451
const SYS_ENTER_CLOCK_NANOSLEEP TraceId = 450
const SYS_EXIT_CLOCK_NANOSLEEP TraceId = 449
const SYS_ENTER_NANOSLEEP TraceId = 444
const SYS_EXIT_NANOSLEEP TraceId = 443
const SYS_ENTER_TIME TraceId = 426
const SYS_EXIT_TIME TraceId = 425
const SYS_ENTER_GETTIMEOFDAY TraceId = 424
const SYS_EXIT_GETTIMEOFDAY TraceId = 423
const SYS_ENTER_SETTIMEOFDAY TraceId = 422
const SYS_EXIT_SETTIMEOFDAY TraceId = 421
const SYS_ENTER_ADJTIMEX TraceId = 420
const SYS_EXIT_ADJTIMEX TraceId = 419
const SYS_ENTER_KCMP TraceId = 418
const SYS_EXIT_KCMP TraceId = 417
const SYS_ENTER_DELETE_MODULE TraceId = 411
const SYS_EXIT_DELETE_MODULE TraceId = 410
const SYS_ENTER_INIT_MODULE TraceId = 409
const SYS_EXIT_INIT_MODULE TraceId = 408
const SYS_ENTER_FINIT_MODULE TraceId = 407
const SYS_EXIT_FINIT_MODULE TraceId = 406
const SYS_ENTER_SYSLOG TraceId = 351
const SYS_EXIT_SYSLOG TraceId = 350
const SYS_ENTER_MEMBARRIER TraceId = 346
const SYS_EXIT_MEMBARRIER TraceId = 345
const SYS_ENTER_SCHED_SETSCHEDULER TraceId = 341
const SYS_EXIT_SCHED_SETSCHEDULER TraceId = 340
const SYS_ENTER_SCHED_SETPARAM TraceId = 339
const SYS_EXIT_SCHED_SETPARAM TraceId = 338
const SYS_ENTER_SCHED_SETATTR TraceId = 337
const SYS_EXIT_SCHED_SETATTR TraceId = 336
const SYS_ENTER_SCHED_GETSCHEDULER TraceId = 335
const SYS_EXIT_SCHED_GETSCHEDULER TraceId = 334
const SYS_ENTER_SCHED_GETPARAM TraceId = 333
const SYS_EXIT_SCHED_GETPARAM TraceId = 332
const SYS_ENTER_SCHED_GETATTR TraceId = 331
const SYS_EXIT_SCHED_GETATTR TraceId = 330
const SYS_ENTER_SCHED_SETAFFINITY TraceId = 329
const SYS_EXIT_SCHED_SETAFFINITY TraceId = 328
const SYS_ENTER_SCHED_GETAFFINITY TraceId = 327
const SYS_EXIT_SCHED_GETAFFINITY TraceId = 326
const SYS_ENTER_SCHED_YIELD TraceId = 325
const SYS_EXIT_SCHED_YIELD TraceId = 324
const SYS_ENTER_SCHED_GET_PRIORITY_MAX TraceId = 323
const SYS_EXIT_SCHED_GET_PRIORITY_MAX TraceId = 322
const SYS_ENTER_SCHED_GET_PRIORITY_MIN TraceId = 321
const SYS_EXIT_SCHED_GET_PRIORITY_MIN TraceId = 320
const SYS_ENTER_SCHED_RR_GET_INTERVAL TraceId = 319
const SYS_EXIT_SCHED_RR_GET_INTERVAL TraceId = 318
const SYS_ENTER_GETGROUPS TraceId = 286
const SYS_EXIT_GETGROUPS TraceId = 285
const SYS_ENTER_SETGROUPS TraceId = 284
const SYS_EXIT_SETGROUPS TraceId = 283
const SYS_ENTER_REBOOT TraceId = 282
const SYS_EXIT_REBOOT TraceId = 281
const SYS_ENTER_LISTNS TraceId = 277
const SYS_EXIT_LISTNS TraceId = 276
const SYS_ENTER_SETNS TraceId = 275
const SYS_EXIT_SETNS TraceId = 274
const SYS_ENTER_PIDFD_OPEN TraceId = 273
const SYS_EXIT_PIDFD_OPEN TraceId = 272
const SYS_ENTER_PIDFD_GETFD TraceId = 271
const SYS_EXIT_PIDFD_GETFD TraceId = 270
const SYS_ENTER_SETPRIORITY TraceId = 265
const SYS_EXIT_SETPRIORITY TraceId = 264
const SYS_ENTER_GETPRIORITY TraceId = 263
const SYS_EXIT_GETPRIORITY TraceId = 262
const SYS_ENTER_SETREGID TraceId = 261
const SYS_EXIT_SETREGID TraceId = 260
const SYS_ENTER_SETGID TraceId = 259
const SYS_EXIT_SETGID TraceId = 258
const SYS_ENTER_SETREUID TraceId = 257
const SYS_EXIT_SETREUID TraceId = 256
const SYS_ENTER_SETUID TraceId = 255
const SYS_EXIT_SETUID TraceId = 254
const SYS_ENTER_SETRESUID TraceId = 253
const SYS_EXIT_SETRESUID TraceId = 252
const SYS_ENTER_GETRESUID TraceId = 251
const SYS_EXIT_GETRESUID TraceId = 250
const SYS_ENTER_SETRESGID TraceId = 249
const SYS_EXIT_SETRESGID TraceId = 248
const SYS_ENTER_GETRESGID TraceId = 247
const SYS_EXIT_GETRESGID TraceId = 246
const SYS_ENTER_SETFSUID TraceId = 245
const SYS_EXIT_SETFSUID TraceId = 244
const SYS_ENTER_SETFSGID TraceId = 243
const SYS_EXIT_SETFSGID TraceId = 242
const SYS_ENTER_GETPID TraceId = 241
const SYS_EXIT_GETPID TraceId = 240
const SYS_ENTER_GETTID TraceId = 239
const SYS_EXIT_GETTID TraceId = 238
const SYS_ENTER_GETPPID TraceId = 237
const SYS_EXIT_GETPPID TraceId = 236
const SYS_ENTER_GETUID TraceId = 235
const SYS_EXIT_GETUID TraceId = 234
const SYS_ENTER_GETEUID TraceId = 233
const SYS_EXIT_GETEUID TraceId = 232
const SYS_ENTER_GETGID TraceId = 231
const SYS_EXIT_GETGID TraceId = 230
const SYS_ENTER_GETEGID TraceId = 229
const SYS_EXIT_GETEGID TraceId = 228
const SYS_ENTER_TIMES TraceId = 227
const SYS_EXIT_TIMES TraceId = 226
const SYS_ENTER_SETPGID TraceId = 225
const SYS_EXIT_SETPGID TraceId = 224
const SYS_ENTER_GETPGID TraceId = 223
const SYS_EXIT_GETPGID TraceId = 222
const SYS_ENTER_GETPGRP TraceId = 221
const SYS_EXIT_GETPGRP TraceId = 220
const SYS_ENTER_GETSID TraceId = 219
const SYS_EXIT_GETSID TraceId = 218
const SYS_ENTER_SETSID TraceId = 217
const SYS_EXIT_SETSID TraceId = 216
const SYS_ENTER_NEWUNAME TraceId = 215
const SYS_EXIT_NEWUNAME TraceId = 214
const SYS_ENTER_SETHOSTNAME TraceId = 213
const SYS_EXIT_SETHOSTNAME TraceId = 212
const SYS_ENTER_SETDOMAINNAME TraceId = 211
const SYS_EXIT_SETDOMAINNAME TraceId = 210
const SYS_ENTER_GETRLIMIT TraceId = 209
const SYS_EXIT_GETRLIMIT TraceId = 208
const SYS_ENTER_PRLIMIT64 TraceId = 207
const SYS_EXIT_PRLIMIT64 TraceId = 206
const SYS_ENTER_SETRLIMIT TraceId = 205
const SYS_EXIT_SETRLIMIT TraceId = 204
const SYS_ENTER_GETRUSAGE TraceId = 203
const SYS_EXIT_GETRUSAGE TraceId = 202
const SYS_ENTER_UMASK TraceId = 201
const SYS_EXIT_UMASK TraceId = 200
const SYS_ENTER_PRCTL TraceId = 199
const SYS_EXIT_PRCTL TraceId = 198
const SYS_ENTER_GETCPU TraceId = 197
const SYS_EXIT_GETCPU TraceId = 196
const SYS_ENTER_SYSINFO TraceId = 195
const SYS_EXIT_SYSINFO TraceId = 194
const SYS_ENTER_RESTART_SYSCALL TraceId = 191
const SYS_EXIT_RESTART_SYSCALL TraceId = 190
const SYS_ENTER_RT_SIGPROCMASK TraceId = 189
const SYS_EXIT_RT_SIGPROCMASK TraceId = 188
const SYS_ENTER_RT_SIGPENDING TraceId = 187
const SYS_EXIT_RT_SIGPENDING TraceId = 186
const SYS_ENTER_RT_SIGTIMEDWAIT TraceId = 185
const SYS_EXIT_RT_SIGTIMEDWAIT TraceId = 184
const SYS_ENTER_KILL TraceId = 183
const SYS_EXIT_KILL TraceId = 182
const SYS_ENTER_PIDFD_SEND_SIGNAL TraceId = 181
const SYS_EXIT_PIDFD_SEND_SIGNAL TraceId = 180
const SYS_ENTER_TGKILL TraceId = 179
const SYS_EXIT_TGKILL TraceId = 178
const SYS_ENTER_TKILL TraceId = 177
const SYS_EXIT_TKILL TraceId = 176
const SYS_ENTER_RT_SIGQUEUEINFO TraceId = 175
const SYS_EXIT_RT_SIGQUEUEINFO TraceId = 174
const SYS_ENTER_RT_TGSIGQUEUEINFO TraceId = 173
const SYS_EXIT_RT_TGSIGQUEUEINFO TraceId = 172
const SYS_ENTER_SIGALTSTACK TraceId = 171
const SYS_EXIT_SIGALTSTACK TraceId = 170
const SYS_ENTER_RT_SIGACTION TraceId = 169
const SYS_EXIT_RT_SIGACTION TraceId = 168
const SYS_ENTER_PAUSE TraceId = 167
const SYS_EXIT_PAUSE TraceId = 166
const SYS_ENTER_RT_SIGSUSPEND TraceId = 165
const SYS_EXIT_RT_SIGSUSPEND TraceId = 164
const SYS_ENTER_PTRACE TraceId = 163
const SYS_EXIT_PTRACE TraceId = 162
const SYS_ENTER_CAPGET TraceId = 161
const SYS_EXIT_CAPGET TraceId = 160
const SYS_ENTER_CAPSET TraceId = 159
const SYS_EXIT_CAPSET TraceId = 158
const SYS_ENTER_EXIT TraceId = 150
const SYS_ENTER_EXIT_GROUP TraceId = 148
const SYS_ENTER_WAITID TraceId = 146
const SYS_EXIT_WAITID TraceId = 145
const SYS_ENTER_WAIT4 TraceId = 144
const SYS_EXIT_WAIT4 TraceId = 143
const SYS_ENTER_PERSONALITY TraceId = 139
const SYS_EXIT_PERSONALITY TraceId = 138
const SYS_ENTER_SET_TID_ADDRESS TraceId = 134
const SYS_EXIT_SET_TID_ADDRESS TraceId = 133
const SYS_ENTER_FORK TraceId = 132
const SYS_EXIT_FORK TraceId = 131
const SYS_ENTER_VFORK TraceId = 130
const SYS_EXIT_VFORK TraceId = 129
const SYS_ENTER_CLONE TraceId = 128
const SYS_EXIT_CLONE TraceId = 127
const SYS_ENTER_CLONE3 TraceId = 126
const SYS_EXIT_CLONE3 TraceId = 125
const SYS_ENTER_UNSHARE TraceId = 124
const SYS_EXIT_UNSHARE TraceId = 123
const SYS_ENTER_MAP_SHADOW_STACK TraceId = 119
const SYS_EXIT_MAP_SHADOW_STACK TraceId = 118
const SYS_ENTER_URETPROBE TraceId = 117
const SYS_EXIT_URETPROBE TraceId = 116
const SYS_ENTER_UPROBE TraceId = 115
const SYS_EXIT_UPROBE TraceId = 114
const SYS_ENTER_ARCH_PRCTL TraceId = 102
const SYS_EXIT_ARCH_PRCTL TraceId = 101
const SYS_ENTER_MMAP TraceId = 100
const SYS_EXIT_MMAP TraceId = 99
const SYS_ENTER_MODIFY_LDT TraceId = 98
const SYS_EXIT_MODIFY_LDT TraceId = 97
const SYS_ENTER_IOPERM TraceId = 95
const SYS_EXIT_IOPERM TraceId = 94
const SYS_ENTER_IOPL TraceId = 93
const SYS_EXIT_IOPL TraceId = 92
const SYS_ENTER_RT_SIGRETURN TraceId = 57

type OpenEvent struct {
	EventType      EventType
	TraceId        TraceId
	Time           uint64
	Pid            uint32
	Tid            uint32
	Flags          int32
	Filename       [MAX_FILENAME_LENGTH]byte
	Comm           [MAX_PROGNAME_LENGTH]byte
	Dirfd          int32
	SchemaVersion  uint32
	FilenameStatus uint32
	SchemaReserved uint32
}

func (o OpenEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Flags:%v Filename:%v Comm:%v Dirfd:%v SchemaVersion:%v FilenameStatus:%v SchemaReserved:%v", o.EventType, o.TraceId, o.Time, o.Pid, o.Tid, o.Flags, StringValue(o.Filename[:]), StringValue(o.Comm[:]), o.Dirfd, o.SchemaVersion, o.FilenameStatus, o.SchemaReserved)
}

func (o OpenEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*OpenEvent)
	if !ok {
		return false
	}
	return o.EventType == otherConcrete.EventType && o.TraceId == otherConcrete.TraceId && o.Time == otherConcrete.Time && o.Pid == otherConcrete.Pid && o.Tid == otherConcrete.Tid && o.Flags == otherConcrete.Flags && o.Filename == otherConcrete.Filename && o.Comm == otherConcrete.Comm && o.Dirfd == otherConcrete.Dirfd && o.SchemaVersion == otherConcrete.SchemaVersion && o.FilenameStatus == otherConcrete.FilenameStatus && o.SchemaReserved == otherConcrete.SchemaReserved
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

type OpenNameFixupEvent struct {
	EventType EventType
	TraceId   TraceId
	Tid       uint32
	Filename  [MAX_FILENAME_LENGTH]byte
	Slot      uint32
}

func (o OpenNameFixupEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Tid:%v Filename:%v Slot:%v", o.EventType, o.TraceId, o.Tid, StringValue(o.Filename[:]), o.Slot)
}

func (o OpenNameFixupEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*OpenNameFixupEvent)
	if !ok {
		return false
	}
	return o.EventType == otherConcrete.EventType && o.TraceId == otherConcrete.TraceId && o.Tid == otherConcrete.Tid && o.Filename == otherConcrete.Filename && o.Slot == otherConcrete.Slot
}

func (o *OpenNameFixupEvent) GetEventType() EventType {
	return o.EventType
}

func (o *OpenNameFixupEvent) GetTraceId() TraceId {
	return o.TraceId
}

func (o *OpenNameFixupEvent) GetTid() uint32 {
	return o.Tid
}

var poolOfOpenNameFixupEvents = sync.Pool{
	New: func() any { return &OpenNameFixupEvent{} },
}

func NewOpenNameFixupEvent(raw []byte) *OpenNameFixupEvent {
	o := poolOfOpenNameFixupEvents.Get().(*OpenNameFixupEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, o); err != nil {
		*o = OpenNameFixupEvent{}
		poolOfOpenNameFixupEvents.Put(o)
		return nil
	}
	return o
}

func (o *OpenNameFixupEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, o)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (o *OpenNameFixupEvent) Recycle() {
	poolOfOpenNameFixupEvents.Put(o)
}

type ExecEvent struct {
	EventType      EventType
	TraceId        TraceId
	Time           uint64
	Pid            uint32
	Tid            uint32
	Dirfd          int32
	Flags          int32
	Filename       [MAX_FILENAME_LENGTH]byte
	Comm           [MAX_PROGNAME_LENGTH]byte
	FilenameStatus uint32
	SchemaVersion  uint32
}

func (e ExecEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Dirfd:%v Flags:%v Filename:%v Comm:%v FilenameStatus:%v SchemaVersion:%v", e.EventType, e.TraceId, e.Time, e.Pid, e.Tid, e.Dirfd, e.Flags, StringValue(e.Filename[:]), StringValue(e.Comm[:]), e.FilenameStatus, e.SchemaVersion)
}

func (e ExecEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*ExecEvent)
	if !ok {
		return false
	}
	return e.EventType == otherConcrete.EventType && e.TraceId == otherConcrete.TraceId && e.Time == otherConcrete.Time && e.Pid == otherConcrete.Pid && e.Tid == otherConcrete.Tid && e.Dirfd == otherConcrete.Dirfd && e.Flags == otherConcrete.Flags && e.Filename == otherConcrete.Filename && e.Comm == otherConcrete.Comm && e.FilenameStatus == otherConcrete.FilenameStatus && e.SchemaVersion == otherConcrete.SchemaVersion
}

func (e *ExecEvent) GetEventType() EventType {
	return e.EventType
}

func (e *ExecEvent) GetTraceId() TraceId {
	return e.TraceId
}

func (e *ExecEvent) GetPid() uint32 {
	return e.Pid
}

func (e *ExecEvent) GetTid() uint32 {
	return e.Tid
}

func (e *ExecEvent) GetTime() uint64 {
	return e.Time
}

var poolOfExecEvents = sync.Pool{
	New: func() any { return &ExecEvent{} },
}

func NewExecEvent(raw []byte) *ExecEvent {
	e := poolOfExecEvents.Get().(*ExecEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, e); err != nil {
		*e = ExecEvent{}
		poolOfExecEvents.Put(e)
		return nil
	}
	return e
}

func (e *ExecEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, e)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *ExecEvent) Recycle() {
	poolOfExecEvents.Put(e)
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
	EventType     EventType
	TraceId       TraceId
	Time          uint64
	Pid           uint32
	Tid           uint32
	Fd            int32
	FileIdent     uint32
	Flags         uint32
	Size          uint64
	SizeValid     uint32
	SchemaVersion uint32
	NameLen       uint32
	Name          [IOR_FD_NAME_LENGTH]byte
}

func (f FdEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v FileIdent:%v Flags:%v Size:%v SizeValid:%v SchemaVersion:%v NameLen:%v Name:%v", f.EventType, f.TraceId, f.Time, f.Pid, f.Tid, f.Fd, f.FileIdent, f.Flags, f.Size, f.SizeValid, f.SchemaVersion, f.NameLen, StringValue(f.Name[:]))
}

func (f FdEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*FdEvent)
	if !ok {
		return false
	}
	return f.EventType == otherConcrete.EventType && f.TraceId == otherConcrete.TraceId && f.Time == otherConcrete.Time && f.Pid == otherConcrete.Pid && f.Tid == otherConcrete.Tid && f.Fd == otherConcrete.Fd && f.FileIdent == otherConcrete.FileIdent && f.Flags == otherConcrete.Flags && f.Size == otherConcrete.Size && f.SizeValid == otherConcrete.SizeValid && f.SchemaVersion == otherConcrete.SchemaVersion && f.NameLen == otherConcrete.NameLen && f.Name == otherConcrete.Name
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

func NewFdEvent(raw []byte) *FdEvent { return NewFdEventFast(raw) }

func (f *FdEvent) Bytes() ([]byte, error) {
	size := 32
	if f.EventType == ENTER_FD_SIZE_EVENT || f.SchemaVersion != 0 {
		size = 48
	}
	raw := make([]byte, size)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(f.EventType))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(f.TraceId))
	binary.LittleEndian.PutUint64(raw[8:16], f.Time)
	binary.LittleEndian.PutUint32(raw[16:20], f.Pid)
	binary.LittleEndian.PutUint32(raw[20:24], f.Tid)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(f.Fd))
	binary.LittleEndian.PutUint32(raw[28:32], f.FileIdent)
	if size == 48 {
		binary.LittleEndian.PutUint32(raw[28:32], f.Flags)
		binary.LittleEndian.PutUint64(raw[32:40], f.Size)
		binary.LittleEndian.PutUint32(raw[40:44], f.SizeValid)
		binary.LittleEndian.PutUint32(raw[44:48], f.SchemaVersion)
	}
	if f.EventType == ENTER_FD_NAME_EVENT {
		raw = append(raw[:32], make([]byte, 4+IOR_FD_NAME_LENGTH)...)
		binary.LittleEndian.PutUint32(raw[28:32], f.FileIdent)
		binary.LittleEndian.PutUint32(raw[32:36], f.NameLen)
		copy(raw[36:], f.Name[:])
	}
	return raw, nil
}

func (f *FdEvent) Recycle() {
	poolOfFdEvents.Put(f)
}

type FdSizeEvent struct {
	EventType     EventType
	TraceId       TraceId
	Time          uint64
	Pid           uint32
	Tid           uint32
	Fd            int32
	Flags         uint32
	Size          uint64
	SizeValid     uint32
	SchemaVersion uint32
}

func (f FdSizeEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v Flags:%v Size:%v SizeValid:%v SchemaVersion:%v", f.EventType, f.TraceId, f.Time, f.Pid, f.Tid, f.Fd, f.Flags, f.Size, f.SizeValid, f.SchemaVersion)
}

func (f FdSizeEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*FdSizeEvent)
	if !ok {
		return false
	}
	return f.EventType == otherConcrete.EventType && f.TraceId == otherConcrete.TraceId && f.Time == otherConcrete.Time && f.Pid == otherConcrete.Pid && f.Tid == otherConcrete.Tid && f.Fd == otherConcrete.Fd && f.Flags == otherConcrete.Flags && f.Size == otherConcrete.Size && f.SizeValid == otherConcrete.SizeValid && f.SchemaVersion == otherConcrete.SchemaVersion
}

func (f *FdSizeEvent) GetEventType() EventType {
	return f.EventType
}

func (f *FdSizeEvent) GetTraceId() TraceId {
	return f.TraceId
}

func (f *FdSizeEvent) GetPid() uint32 {
	return f.Pid
}

func (f *FdSizeEvent) GetTid() uint32 {
	return f.Tid
}

func (f *FdSizeEvent) GetTime() uint64 {
	return f.Time
}

var poolOfFdSizeEvents = sync.Pool{
	New: func() any { return &FdSizeEvent{} },
}

func NewFdSizeEvent(raw []byte) *FdSizeEvent { return NewFdSizeEventFast(raw) }

func (f *FdSizeEvent) Bytes() ([]byte, error) {
	raw := make([]byte, 48)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(f.EventType))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(f.TraceId))
	binary.LittleEndian.PutUint64(raw[8:16], f.Time)
	binary.LittleEndian.PutUint32(raw[16:20], f.Pid)
	binary.LittleEndian.PutUint32(raw[20:24], f.Tid)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(f.Fd))
	binary.LittleEndian.PutUint32(raw[28:32], f.Flags)
	binary.LittleEndian.PutUint64(raw[32:40], f.Size)
	binary.LittleEndian.PutUint32(raw[40:44], f.SizeValid)
	binary.LittleEndian.PutUint32(raw[44:48], f.SchemaVersion)
	return raw, nil
}

func (f *FdSizeEvent) Recycle() {
	poolOfFdSizeEvents.Put(f)
}

type RetEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Ret       int64
	Pid       uint32
	Tid       uint32
	RetType   uint32
	FileIdent uint32
}

func (r RetEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Ret:%v Pid:%v Tid:%v RetType:%v FileIdent:%v", r.EventType, r.TraceId, r.Time, r.Ret, r.Pid, r.Tid, r.RetType, r.FileIdent)
}

func (r RetEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*RetEvent)
	if !ok {
		return false
	}
	return r.EventType == otherConcrete.EventType && r.TraceId == otherConcrete.TraceId && r.Time == otherConcrete.Time && r.Ret == otherConcrete.Ret && r.Pid == otherConcrete.Pid && r.Tid == otherConcrete.Tid && r.RetType == otherConcrete.RetType && r.FileIdent == otherConcrete.FileIdent
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

// GetRet returns the syscall return value carried by this event.
func (r *RetEvent) GetRet() int64 {
	return r.Ret
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
	EventType     EventType
	TraceId       TraceId
	Time          uint64
	Pid           uint32
	Tid           uint32
	Oldname       [MAX_FILENAME_LENGTH]byte
	Newname       [MAX_FILENAME_LENGTH]byte
	Olddirfd      int32
	Newdirfd      int32
	OldnameStatus uint32
	NewnameStatus uint32
	Flags         uint32
	SchemaVersion uint32
}

func (n NameEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Oldname:%v Newname:%v Olddirfd:%v Newdirfd:%v OldnameStatus:%v NewnameStatus:%v Flags:%v SchemaVersion:%v", n.EventType, n.TraceId, n.Time, n.Pid, n.Tid, StringValue(n.Oldname[:]), StringValue(n.Newname[:]), n.Olddirfd, n.Newdirfd, n.OldnameStatus, n.NewnameStatus, n.Flags, n.SchemaVersion)
}

func (n NameEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*NameEvent)
	if !ok {
		return false
	}
	return n.EventType == otherConcrete.EventType && n.TraceId == otherConcrete.TraceId && n.Time == otherConcrete.Time && n.Pid == otherConcrete.Pid && n.Tid == otherConcrete.Tid && n.Oldname == otherConcrete.Oldname && n.Newname == otherConcrete.Newname && n.Olddirfd == otherConcrete.Olddirfd && n.Newdirfd == otherConcrete.Newdirfd && n.OldnameStatus == otherConcrete.OldnameStatus && n.NewnameStatus == otherConcrete.NewnameStatus && n.Flags == otherConcrete.Flags && n.SchemaVersion == otherConcrete.SchemaVersion
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
	EventType      EventType
	TraceId        TraceId
	Time           uint64
	Pid            uint32
	Tid            uint32
	Pathname       [MAX_FILENAME_LENGTH]byte
	Dirfd          int32
	PathnameStatus uint32
	Flags          uint32
	SchemaVersion  uint32
	TargetStatus   uint32
	SizeValid      uint32
	Size           uint64
}

func (p PathEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Pathname:%v Dirfd:%v PathnameStatus:%v Flags:%v SchemaVersion:%v TargetStatus:%v SizeValid:%v Size:%v", p.EventType, p.TraceId, p.Time, p.Pid, p.Tid, StringValue(p.Pathname[:]), p.Dirfd, p.PathnameStatus, p.Flags, p.SchemaVersion, p.TargetStatus, p.SizeValid, p.Size)
}

func (p PathEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*PathEvent)
	if !ok {
		return false
	}
	return p.EventType == otherConcrete.EventType && p.TraceId == otherConcrete.TraceId && p.Time == otherConcrete.Time && p.Pid == otherConcrete.Pid && p.Tid == otherConcrete.Tid && p.Pathname == otherConcrete.Pathname && p.Dirfd == otherConcrete.Dirfd && p.PathnameStatus == otherConcrete.PathnameStatus && p.Flags == otherConcrete.Flags && p.SchemaVersion == otherConcrete.SchemaVersion && p.TargetStatus == otherConcrete.TargetStatus && p.SizeValid == otherConcrete.SizeValid && p.Size == otherConcrete.Size
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

type FdPathEvent struct {
	EventType      EventType
	TraceId        TraceId
	Time           uint64
	Pid            uint32
	Tid            uint32
	Fd             int32
	Dirfd          int32
	Pathname       [MAX_FILENAME_LENGTH]byte
	PathnameStatus uint32
	Flags          uint32
	SchemaVersion  uint32
}

func (f FdPathEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v Dirfd:%v Pathname:%v PathnameStatus:%v Flags:%v SchemaVersion:%v", f.EventType, f.TraceId, f.Time, f.Pid, f.Tid, f.Fd, f.Dirfd, StringValue(f.Pathname[:]), f.PathnameStatus, f.Flags, f.SchemaVersion)
}

func (f FdPathEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*FdPathEvent)
	if !ok {
		return false
	}
	return f.EventType == otherConcrete.EventType && f.TraceId == otherConcrete.TraceId && f.Time == otherConcrete.Time && f.Pid == otherConcrete.Pid && f.Tid == otherConcrete.Tid && f.Fd == otherConcrete.Fd && f.Dirfd == otherConcrete.Dirfd && f.Pathname == otherConcrete.Pathname && f.PathnameStatus == otherConcrete.PathnameStatus && f.Flags == otherConcrete.Flags && f.SchemaVersion == otherConcrete.SchemaVersion
}

func (f *FdPathEvent) GetEventType() EventType {
	return f.EventType
}

func (f *FdPathEvent) GetTraceId() TraceId {
	return f.TraceId
}

func (f *FdPathEvent) GetPid() uint32 {
	return f.Pid
}

func (f *FdPathEvent) GetTid() uint32 {
	return f.Tid
}

func (f *FdPathEvent) GetTime() uint64 {
	return f.Time
}

var poolOfFdPathEvents = sync.Pool{
	New: func() any { return &FdPathEvent{} },
}

func NewFdPathEvent(raw []byte) *FdPathEvent {
	if len(raw) != 300 && len(raw) != 304 {
		return nil
	}
	if binary.LittleEndian.Uint32(raw[296:300]) != FD_PATH_EVENT_SCHEMA_VERSION {
		return nil
	}
	f := poolOfFdPathEvents.Get().(*FdPathEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, f); err != nil {
		*f = FdPathEvent{}
		poolOfFdPathEvents.Put(f)
		return nil
	}
	return f
}

func (f *FdPathEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, f)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (f *FdPathEvent) Recycle() {
	poolOfFdPathEvents.Put(f)
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
	FileIdent uint32
}

func (d Dup3Event) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v Flags:%v FileIdent:%v", d.EventType, d.TraceId, d.Time, d.Pid, d.Tid, d.Fd, d.Flags, d.FileIdent)
}

func (d Dup3Event) Equals(other any) bool {
	otherConcrete, ok := other.(*Dup3Event)
	if !ok {
		return false
	}
	return d.EventType == otherConcrete.EventType && d.TraceId == otherConcrete.TraceId && d.Time == otherConcrete.Time && d.Pid == otherConcrete.Pid && d.Tid == otherConcrete.Tid && d.Fd == otherConcrete.Fd && d.Flags == otherConcrete.Flags && d.FileIdent == otherConcrete.FileIdent
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
	EventType    EventType
	TraceId      TraceId
	Time         uint64
	Pid          uint32
	Tid          uint32
	Flags        int32
	HandleStatus uint32
	HandleBytes  uint32
	HandleType   int32
	FHandle      [IOR_MAX_HANDLE_SZ]byte
}

func (o OpenByHandleAtEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Flags:%v HandleStatus:%v HandleBytes:%v HandleType:%v FHandle:%v", o.EventType, o.TraceId, o.Time, o.Pid, o.Tid, o.Flags, o.HandleStatus, o.HandleBytes, o.HandleType, hex.EncodeToString(o.FHandle[:]))
}

func (o OpenByHandleAtEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*OpenByHandleAtEvent)
	if !ok {
		return false
	}
	return o.EventType == otherConcrete.EventType && o.TraceId == otherConcrete.TraceId && o.Time == otherConcrete.Time && o.Pid == otherConcrete.Pid && o.Tid == otherConcrete.Tid && o.Flags == otherConcrete.Flags && o.HandleStatus == otherConcrete.HandleStatus && o.HandleBytes == otherConcrete.HandleBytes && o.HandleType == otherConcrete.HandleType && o.FHandle == otherConcrete.FHandle
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

type FileHandleEvent struct {
	EventType    EventType
	TraceId      TraceId
	Time         uint64
	Pid          uint32
	Tid          uint32
	Reserved     uint32
	HandleStatus uint32
	HandleBytes  uint32
	HandleType   int32
	FHandle      [IOR_MAX_HANDLE_SZ]byte
	EnterTime    uint64
}

func (f FileHandleEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Reserved:%v HandleStatus:%v HandleBytes:%v HandleType:%v FHandle:%v EnterTime:%v", f.EventType, f.TraceId, f.Time, f.Pid, f.Tid, f.Reserved, f.HandleStatus, f.HandleBytes, f.HandleType, hex.EncodeToString(f.FHandle[:]), f.EnterTime)
}

func (f FileHandleEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*FileHandleEvent)
	if !ok {
		return false
	}
	return f.EventType == otherConcrete.EventType && f.TraceId == otherConcrete.TraceId && f.Time == otherConcrete.Time && f.Pid == otherConcrete.Pid && f.Tid == otherConcrete.Tid && f.Reserved == otherConcrete.Reserved && f.HandleStatus == otherConcrete.HandleStatus && f.HandleBytes == otherConcrete.HandleBytes && f.HandleType == otherConcrete.HandleType && f.FHandle == otherConcrete.FHandle && f.EnterTime == otherConcrete.EnterTime
}

func (f *FileHandleEvent) GetEventType() EventType {
	return f.EventType
}

func (f *FileHandleEvent) GetTraceId() TraceId {
	return f.TraceId
}

func (f *FileHandleEvent) GetPid() uint32 {
	return f.Pid
}

func (f *FileHandleEvent) GetTid() uint32 {
	return f.Tid
}

func (f *FileHandleEvent) GetTime() uint64 {
	return f.Time
}

var poolOfFileHandleEvents = sync.Pool{
	New: func() any { return &FileHandleEvent{} },
}

func NewFileHandleEvent(raw []byte) *FileHandleEvent {
	f := poolOfFileHandleEvents.Get().(*FileHandleEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, f); err != nil {
		*f = FileHandleEvent{}
		poolOfFileHandleEvents.Put(f)
		return nil
	}
	return f
}

func (f *FileHandleEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, f)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (f *FileHandleEvent) Recycle() {
	poolOfFileHandleEvents.Put(f)
}

type RingFdsEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Opcode    uint32
	Status    uint32
	Count     uint32
	Reserved  uint32
	Updates   [IOR_RING_FDS_BYTES]byte
}

func (r RingFdsEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Opcode:%v Status:%v Count:%v Reserved:%v Updates:%v", r.EventType, r.TraceId, r.Time, r.Pid, r.Tid, r.Opcode, r.Status, r.Count, r.Reserved, hex.EncodeToString(r.Updates[:]))
}

func (r RingFdsEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*RingFdsEvent)
	if !ok {
		return false
	}
	return r.EventType == otherConcrete.EventType && r.TraceId == otherConcrete.TraceId && r.Time == otherConcrete.Time && r.Pid == otherConcrete.Pid && r.Tid == otherConcrete.Tid && r.Opcode == otherConcrete.Opcode && r.Status == otherConcrete.Status && r.Count == otherConcrete.Count && r.Reserved == otherConcrete.Reserved && r.Updates == otherConcrete.Updates
}

func (r *RingFdsEvent) GetEventType() EventType {
	return r.EventType
}

func (r *RingFdsEvent) GetTraceId() TraceId {
	return r.TraceId
}

func (r *RingFdsEvent) GetPid() uint32 {
	return r.Pid
}

func (r *RingFdsEvent) GetTid() uint32 {
	return r.Tid
}

func (r *RingFdsEvent) GetTime() uint64 {
	return r.Time
}

var poolOfRingFdsEvents = sync.Pool{
	New: func() any { return &RingFdsEvent{} },
}

func NewRingFdsEvent(raw []byte) *RingFdsEvent {
	r := poolOfRingFdsEvents.Get().(*RingFdsEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, r); err != nil {
		*r = RingFdsEvent{}
		poolOfRingFdsEvents.Put(r)
		return nil
	}
	return r
}

func (r *RingFdsEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, r)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *RingFdsEvent) Recycle() {
	poolOfRingFdsEvents.Put(r)
}

type FdNameEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Fd        int32
	FileIdent uint32
	NameLen   uint32
	Name      [IOR_FD_NAME_LENGTH]byte
}

func (f FdNameEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v FileIdent:%v NameLen:%v Name:%v", f.EventType, f.TraceId, f.Time, f.Pid, f.Tid, f.Fd, f.FileIdent, f.NameLen, StringValue(f.Name[:]))
}

func (f FdNameEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*FdNameEvent)
	if !ok {
		return false
	}
	return f.EventType == otherConcrete.EventType && f.TraceId == otherConcrete.TraceId && f.Time == otherConcrete.Time && f.Pid == otherConcrete.Pid && f.Tid == otherConcrete.Tid && f.Fd == otherConcrete.Fd && f.FileIdent == otherConcrete.FileIdent && f.NameLen == otherConcrete.NameLen && f.Name == otherConcrete.Name
}

func (f *FdNameEvent) GetEventType() EventType {
	return f.EventType
}

func (f *FdNameEvent) GetTraceId() TraceId {
	return f.TraceId
}

func (f *FdNameEvent) GetPid() uint32 {
	return f.Pid
}

func (f *FdNameEvent) GetTid() uint32 {
	return f.Tid
}

func (f *FdNameEvent) GetTime() uint64 {
	return f.Time
}

var poolOfFdNameEvents = sync.Pool{
	New: func() any { return &FdNameEvent{} },
}

func NewFdNameEvent(raw []byte) *FdNameEvent {
	f := poolOfFdNameEvents.Get().(*FdNameEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, f); err != nil {
		*f = FdNameEvent{}
		poolOfFdNameEvents.Put(f)
		return nil
	}
	return f
}

func (f *FdNameEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, f)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (f *FdNameEvent) Recycle() {
	poolOfFdNameEvents.Put(f)
}

type SocketEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Family    int32
	Type      int32
	Protocol  int32
}

func (s SocketEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Family:%v Type:%v Protocol:%v", s.EventType, s.TraceId, s.Time, s.Pid, s.Tid, s.Family, s.Type, s.Protocol)
}

func (s SocketEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*SocketEvent)
	if !ok {
		return false
	}
	return s.EventType == otherConcrete.EventType && s.TraceId == otherConcrete.TraceId && s.Time == otherConcrete.Time && s.Pid == otherConcrete.Pid && s.Tid == otherConcrete.Tid && s.Family == otherConcrete.Family && s.Type == otherConcrete.Type && s.Protocol == otherConcrete.Protocol
}

func (s *SocketEvent) GetEventType() EventType {
	return s.EventType
}

func (s *SocketEvent) GetTraceId() TraceId {
	return s.TraceId
}

func (s *SocketEvent) GetPid() uint32 {
	return s.Pid
}

func (s *SocketEvent) GetTid() uint32 {
	return s.Tid
}

func (s *SocketEvent) GetTime() uint64 {
	return s.Time
}

var poolOfSocketEvents = sync.Pool{
	New: func() any { return &SocketEvent{} },
}

func NewSocketEvent(raw []byte) *SocketEvent {
	s := poolOfSocketEvents.Get().(*SocketEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, s); err != nil {
		*s = SocketEvent{}
		poolOfSocketEvents.Put(s)
		return nil
	}
	return s
}

func (s *SocketEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, s)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *SocketEvent) Recycle() {
	poolOfSocketEvents.Put(s)
}

type SocketpairEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Family    int32
	Type      int32
	Protocol  int32
	Sv0       int32
	Sv1       int32
	Ret       int64
}

func (s SocketpairEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Family:%v Type:%v Protocol:%v Sv0:%v Sv1:%v Ret:%v", s.EventType, s.TraceId, s.Time, s.Pid, s.Tid, s.Family, s.Type, s.Protocol, s.Sv0, s.Sv1, s.Ret)
}

func (s SocketpairEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*SocketpairEvent)
	if !ok {
		return false
	}
	return s.EventType == otherConcrete.EventType && s.TraceId == otherConcrete.TraceId && s.Time == otherConcrete.Time && s.Pid == otherConcrete.Pid && s.Tid == otherConcrete.Tid && s.Family == otherConcrete.Family && s.Type == otherConcrete.Type && s.Protocol == otherConcrete.Protocol && s.Sv0 == otherConcrete.Sv0 && s.Sv1 == otherConcrete.Sv1 && s.Ret == otherConcrete.Ret
}

func (s *SocketpairEvent) GetEventType() EventType {
	return s.EventType
}

func (s *SocketpairEvent) GetTraceId() TraceId {
	return s.TraceId
}

func (s *SocketpairEvent) GetPid() uint32 {
	return s.Pid
}

func (s *SocketpairEvent) GetTid() uint32 {
	return s.Tid
}

func (s *SocketpairEvent) GetTime() uint64 {
	return s.Time
}

// GetRet returns the syscall return value carried by this event.
func (s *SocketpairEvent) GetRet() int64 {
	return s.Ret
}

var poolOfSocketpairEvents = sync.Pool{
	New: func() any { return &SocketpairEvent{} },
}

func NewSocketpairEvent(raw []byte) *SocketpairEvent {
	s := poolOfSocketpairEvents.Get().(*SocketpairEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, s); err != nil {
		*s = SocketpairEvent{}
		poolOfSocketpairEvents.Put(s)
		return nil
	}
	return s
}

func (s *SocketpairEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, s)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *SocketpairEvent) Recycle() {
	poolOfSocketpairEvents.Put(s)
}

type AcceptEvent struct {
	EventType     EventType
	TraceId       TraceId
	Time          uint64
	Pid           uint32
	Tid           uint32
	Fd            int32
	Ret           int64
	Flags         int32
	SchemaVersion uint32
}

func (a AcceptEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v Ret:%v Flags:%v SchemaVersion:%v", a.EventType, a.TraceId, a.Time, a.Pid, a.Tid, a.Fd, a.Ret, a.Flags, a.SchemaVersion)
}

func (a AcceptEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*AcceptEvent)
	if !ok {
		return false
	}
	return a.EventType == otherConcrete.EventType && a.TraceId == otherConcrete.TraceId && a.Time == otherConcrete.Time && a.Pid == otherConcrete.Pid && a.Tid == otherConcrete.Tid && a.Fd == otherConcrete.Fd && a.Ret == otherConcrete.Ret && a.Flags == otherConcrete.Flags && a.SchemaVersion == otherConcrete.SchemaVersion
}

func (a *AcceptEvent) GetEventType() EventType {
	return a.EventType
}

func (a *AcceptEvent) GetTraceId() TraceId {
	return a.TraceId
}

func (a *AcceptEvent) GetPid() uint32 {
	return a.Pid
}

func (a *AcceptEvent) GetTid() uint32 {
	return a.Tid
}

func (a *AcceptEvent) GetTime() uint64 {
	return a.Time
}

// GetRet returns the syscall return value carried by this event.
func (a *AcceptEvent) GetRet() int64 {
	return a.Ret
}

var poolOfAcceptEvents = sync.Pool{
	New: func() any { return &AcceptEvent{} },
}

func NewAcceptEvent(raw []byte) *AcceptEvent {
	a := poolOfAcceptEvents.Get().(*AcceptEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, a); err != nil {
		*a = AcceptEvent{}
		poolOfAcceptEvents.Put(a)
		return nil
	}
	return a
}

func (a *AcceptEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, a)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (a *AcceptEvent) Recycle() {
	poolOfAcceptEvents.Put(a)
}

type PipeEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Flags     int32
	Fd0       int32
	Fd1       int32
	Ret       int64
}

func (p PipeEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Flags:%v Fd0:%v Fd1:%v Ret:%v", p.EventType, p.TraceId, p.Time, p.Pid, p.Tid, p.Flags, p.Fd0, p.Fd1, p.Ret)
}

func (p PipeEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*PipeEvent)
	if !ok {
		return false
	}
	return p.EventType == otherConcrete.EventType && p.TraceId == otherConcrete.TraceId && p.Time == otherConcrete.Time && p.Pid == otherConcrete.Pid && p.Tid == otherConcrete.Tid && p.Flags == otherConcrete.Flags && p.Fd0 == otherConcrete.Fd0 && p.Fd1 == otherConcrete.Fd1 && p.Ret == otherConcrete.Ret
}

func (p *PipeEvent) GetEventType() EventType {
	return p.EventType
}

func (p *PipeEvent) GetTraceId() TraceId {
	return p.TraceId
}

func (p *PipeEvent) GetPid() uint32 {
	return p.Pid
}

func (p *PipeEvent) GetTid() uint32 {
	return p.Tid
}

func (p *PipeEvent) GetTime() uint64 {
	return p.Time
}

// GetRet returns the syscall return value carried by this event.
func (p *PipeEvent) GetRet() int64 {
	return p.Ret
}

var poolOfPipeEvents = sync.Pool{
	New: func() any { return &PipeEvent{} },
}

func NewPipeEvent(raw []byte) *PipeEvent {
	p := poolOfPipeEvents.Get().(*PipeEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, p); err != nil {
		*p = PipeEvent{}
		poolOfPipeEvents.Put(p)
		return nil
	}
	return p
}

func (p *PipeEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *PipeEvent) Recycle() {
	poolOfPipeEvents.Put(p)
}

type EventfdEvent struct {
	EventType      EventType
	TraceId        TraceId
	Time           uint64
	Pid            uint32
	Tid            uint32
	Flags          int32
	Ret            int64
	Fd             int32
	Filename       [MAX_FILENAME_LENGTH]byte
	FilenameStatus uint32
	SchemaVersion  uint32
}

func (e EventfdEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Flags:%v Ret:%v Fd:%v Filename:%v FilenameStatus:%v SchemaVersion:%v", e.EventType, e.TraceId, e.Time, e.Pid, e.Tid, e.Flags, e.Ret, e.Fd, StringValue(e.Filename[:]), e.FilenameStatus, e.SchemaVersion)
}

func (e EventfdEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*EventfdEvent)
	if !ok {
		return false
	}
	return e.EventType == otherConcrete.EventType && e.TraceId == otherConcrete.TraceId && e.Time == otherConcrete.Time && e.Pid == otherConcrete.Pid && e.Tid == otherConcrete.Tid && e.Flags == otherConcrete.Flags && e.Ret == otherConcrete.Ret && e.Fd == otherConcrete.Fd && e.Filename == otherConcrete.Filename && e.FilenameStatus == otherConcrete.FilenameStatus && e.SchemaVersion == otherConcrete.SchemaVersion
}

func (e *EventfdEvent) GetEventType() EventType {
	return e.EventType
}

func (e *EventfdEvent) GetTraceId() TraceId {
	return e.TraceId
}

func (e *EventfdEvent) GetPid() uint32 {
	return e.Pid
}

func (e *EventfdEvent) GetTid() uint32 {
	return e.Tid
}

func (e *EventfdEvent) GetTime() uint64 {
	return e.Time
}

// GetRet returns the syscall return value carried by this event.
func (e *EventfdEvent) GetRet() int64 {
	return e.Ret
}

var poolOfEventfdEvents = sync.Pool{
	New: func() any { return &EventfdEvent{} },
}

func NewEventfdEvent(raw []byte) *EventfdEvent {
	if len(raw) != 312 && len(raw) != 48 && len(raw) != 40 && len(raw) != 36 {
		return nil
	}
	e := poolOfEventfdEvents.Get().(*EventfdEvent)
	e.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	e.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	e.Time = binary.LittleEndian.Uint64(raw[8:16])
	e.Pid = binary.LittleEndian.Uint32(raw[16:20])
	e.Tid = binary.LittleEndian.Uint32(raw[20:24])
	e.Flags = int32(binary.LittleEndian.Uint32(raw[24:28]))
	e.Fd = -1
	e.Filename = [MAX_FILENAME_LENGTH]byte{}
	e.FilenameStatus = PATH_READ_NULL
	e.SchemaVersion = 0
	retOffset := 28
	if len(raw) >= 40 {
		retOffset = 32
	}
	e.Ret = int64(binary.LittleEndian.Uint64(raw[retOffset : retOffset+8]))
	if len(raw) == 48 || len(raw) == 312 {
		e.Fd = int32(binary.LittleEndian.Uint32(raw[40:44]))
	}
	if len(raw) == 312 {
		copy(e.Filename[:], raw[44:300])
		e.FilenameStatus = binary.LittleEndian.Uint32(raw[300:304])
		e.SchemaVersion = binary.LittleEndian.Uint32(raw[304:308])
		if e.SchemaVersion != EVENTFD_EVENT_SCHEMA_VERSION {
			e.Recycle()
			return nil
		}
	}
	return e
}

func (e *EventfdEvent) Bytes() ([]byte, error) {
	size := 48
	if e.EventType == ENTER_EVENTFD_NAME_EVENT || e.SchemaVersion != 0 {
		size = 312
	}
	raw := make([]byte, size)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(e.EventType))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(e.TraceId))
	binary.LittleEndian.PutUint64(raw[8:16], e.Time)
	binary.LittleEndian.PutUint32(raw[16:20], e.Pid)
	binary.LittleEndian.PutUint32(raw[20:24], e.Tid)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(e.Flags))
	binary.LittleEndian.PutUint64(raw[32:40], uint64(e.Ret))
	binary.LittleEndian.PutUint32(raw[40:44], uint32(e.Fd))
	if len(raw) == 312 {
		copy(raw[44:300], e.Filename[:])
		binary.LittleEndian.PutUint32(raw[300:304], e.FilenameStatus)
		binary.LittleEndian.PutUint32(raw[304:308], e.SchemaVersion)
	}
	return raw, nil
}

func (e *EventfdEvent) Recycle() {
	poolOfEventfdEvents.Put(e)
}

type EventfdNameEvent struct {
	EventType      EventType
	TraceId        TraceId
	Time           uint64
	Pid            uint32
	Tid            uint32
	Flags          int32
	Ret            int64
	Fd             int32
	Filename       [MAX_FILENAME_LENGTH]byte
	FilenameStatus uint32
	SchemaVersion  uint32
}

func (e EventfdNameEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Flags:%v Ret:%v Fd:%v Filename:%v FilenameStatus:%v SchemaVersion:%v", e.EventType, e.TraceId, e.Time, e.Pid, e.Tid, e.Flags, e.Ret, e.Fd, StringValue(e.Filename[:]), e.FilenameStatus, e.SchemaVersion)
}

func (e EventfdNameEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*EventfdNameEvent)
	if !ok {
		return false
	}
	return e.EventType == otherConcrete.EventType && e.TraceId == otherConcrete.TraceId && e.Time == otherConcrete.Time && e.Pid == otherConcrete.Pid && e.Tid == otherConcrete.Tid && e.Flags == otherConcrete.Flags && e.Ret == otherConcrete.Ret && e.Fd == otherConcrete.Fd && e.Filename == otherConcrete.Filename && e.FilenameStatus == otherConcrete.FilenameStatus && e.SchemaVersion == otherConcrete.SchemaVersion
}

func (e *EventfdNameEvent) GetEventType() EventType {
	return e.EventType
}

func (e *EventfdNameEvent) GetTraceId() TraceId {
	return e.TraceId
}

func (e *EventfdNameEvent) GetPid() uint32 {
	return e.Pid
}

func (e *EventfdNameEvent) GetTid() uint32 {
	return e.Tid
}

func (e *EventfdNameEvent) GetTime() uint64 {
	return e.Time
}

// GetRet returns the syscall return value carried by this event.
func (e *EventfdNameEvent) GetRet() int64 {
	return e.Ret
}

var poolOfEventfdNameEvents = sync.Pool{
	New: func() any { return &EventfdNameEvent{} },
}

func NewEventfdNameEvent(raw []byte) *EventfdNameEvent {
	if len(raw) != 312 {
		return nil
	}
	e := poolOfEventfdNameEvents.Get().(*EventfdNameEvent)
	e.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	e.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	e.Time = binary.LittleEndian.Uint64(raw[8:16])
	e.Pid = binary.LittleEndian.Uint32(raw[16:20])
	e.Tid = binary.LittleEndian.Uint32(raw[20:24])
	e.Flags = int32(binary.LittleEndian.Uint32(raw[24:28]))
	e.Ret = int64(binary.LittleEndian.Uint64(raw[32:40]))
	e.Fd = int32(binary.LittleEndian.Uint32(raw[40:44]))
	copy(e.Filename[:], raw[44:300])
	e.FilenameStatus = binary.LittleEndian.Uint32(raw[300:304])
	e.SchemaVersion = binary.LittleEndian.Uint32(raw[304:308])
	if e.SchemaVersion != EVENTFD_NAME_EVENT_SCHEMA_VERSION {
		e.Recycle()
		return nil
	}
	return e
}

func (e *EventfdNameEvent) Bytes() ([]byte, error) {
	raw := make([]byte, 312)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(e.EventType))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(e.TraceId))
	binary.LittleEndian.PutUint64(raw[8:16], e.Time)
	binary.LittleEndian.PutUint32(raw[16:20], e.Pid)
	binary.LittleEndian.PutUint32(raw[20:24], e.Tid)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(e.Flags))
	binary.LittleEndian.PutUint64(raw[32:40], uint64(e.Ret))
	binary.LittleEndian.PutUint32(raw[40:44], uint32(e.Fd))
	copy(raw[44:300], e.Filename[:])
	binary.LittleEndian.PutUint32(raw[300:304], e.FilenameStatus)
	binary.LittleEndian.PutUint32(raw[304:308], e.SchemaVersion)
	return raw, nil
}

func (e *EventfdNameEvent) Recycle() {
	poolOfEventfdNameEvents.Put(e)
}

type EpollCtlEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Epfd      int32
	Op        int32
	Fd        int32
	Events    uint32
}

func (e EpollCtlEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Epfd:%v Op:%v Fd:%v Events:%v", e.EventType, e.TraceId, e.Time, e.Pid, e.Tid, e.Epfd, e.Op, e.Fd, e.Events)
}

func (e EpollCtlEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*EpollCtlEvent)
	if !ok {
		return false
	}
	return e.EventType == otherConcrete.EventType && e.TraceId == otherConcrete.TraceId && e.Time == otherConcrete.Time && e.Pid == otherConcrete.Pid && e.Tid == otherConcrete.Tid && e.Epfd == otherConcrete.Epfd && e.Op == otherConcrete.Op && e.Fd == otherConcrete.Fd && e.Events == otherConcrete.Events
}

func (e *EpollCtlEvent) GetEventType() EventType {
	return e.EventType
}

func (e *EpollCtlEvent) GetTraceId() TraceId {
	return e.TraceId
}

func (e *EpollCtlEvent) GetPid() uint32 {
	return e.Pid
}

func (e *EpollCtlEvent) GetTid() uint32 {
	return e.Tid
}

func (e *EpollCtlEvent) GetTime() uint64 {
	return e.Time
}

var poolOfEpollCtlEvents = sync.Pool{
	New: func() any { return &EpollCtlEvent{} },
}

func NewEpollCtlEvent(raw []byte) *EpollCtlEvent {
	e := poolOfEpollCtlEvents.Get().(*EpollCtlEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, e); err != nil {
		*e = EpollCtlEvent{}
		poolOfEpollCtlEvents.Put(e)
		return nil
	}
	return e
}

func (e *EpollCtlEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, e)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *EpollCtlEvent) Recycle() {
	poolOfEpollCtlEvents.Put(e)
}

type PollEvent struct {
	EventType     EventType
	TraceId       TraceId
	Time          uint64
	Pid           uint32
	Tid           uint32
	Nfds          int32
	TimeoutNs     int64
	Fd            int32
	SchemaVersion uint32
}

func (p PollEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Nfds:%v TimeoutNs:%v Fd:%v SchemaVersion:%v", p.EventType, p.TraceId, p.Time, p.Pid, p.Tid, p.Nfds, p.TimeoutNs, p.Fd, p.SchemaVersion)
}

func (p PollEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*PollEvent)
	if !ok {
		return false
	}
	return p.EventType == otherConcrete.EventType && p.TraceId == otherConcrete.TraceId && p.Time == otherConcrete.Time && p.Pid == otherConcrete.Pid && p.Tid == otherConcrete.Tid && p.Nfds == otherConcrete.Nfds && p.TimeoutNs == otherConcrete.TimeoutNs && p.Fd == otherConcrete.Fd && p.SchemaVersion == otherConcrete.SchemaVersion
}

func (p *PollEvent) GetEventType() EventType {
	return p.EventType
}

func (p *PollEvent) GetTraceId() TraceId {
	return p.TraceId
}

func (p *PollEvent) GetPid() uint32 {
	return p.Pid
}

func (p *PollEvent) GetTid() uint32 {
	return p.Tid
}

func (p *PollEvent) GetTime() uint64 {
	return p.Time
}

var poolOfPollEvents = sync.Pool{
	New: func() any { return &PollEvent{} },
}

func NewPollEvent(raw []byte) *PollEvent {
	p := poolOfPollEvents.Get().(*PollEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, p); err != nil {
		*p = PollEvent{}
		poolOfPollEvents.Put(p)
		return nil
	}
	return p
}

func (p *PollEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *PollEvent) Recycle() {
	poolOfPollEvents.Put(p)
}

type MemEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Addr      uint64
	Length    uint64
	Length2   uint64
	Flags     uint64
}

func (m MemEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Addr:%v Length:%v Length2:%v Flags:%v", m.EventType, m.TraceId, m.Time, m.Pid, m.Tid, m.Addr, m.Length, m.Length2, m.Flags)
}

func (m MemEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*MemEvent)
	if !ok {
		return false
	}
	return m.EventType == otherConcrete.EventType && m.TraceId == otherConcrete.TraceId && m.Time == otherConcrete.Time && m.Pid == otherConcrete.Pid && m.Tid == otherConcrete.Tid && m.Addr == otherConcrete.Addr && m.Length == otherConcrete.Length && m.Length2 == otherConcrete.Length2 && m.Flags == otherConcrete.Flags
}

func (m *MemEvent) GetEventType() EventType {
	return m.EventType
}

func (m *MemEvent) GetTraceId() TraceId {
	return m.TraceId
}

func (m *MemEvent) GetPid() uint32 {
	return m.Pid
}

func (m *MemEvent) GetTid() uint32 {
	return m.Tid
}

func (m *MemEvent) GetTime() uint64 {
	return m.Time
}

var poolOfMemEvents = sync.Pool{
	New: func() any { return &MemEvent{} },
}

func NewMemEvent(raw []byte) *MemEvent {
	m := poolOfMemEvents.Get().(*MemEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, m); err != nil {
		*m = MemEvent{}
		poolOfMemEvents.Put(m)
		return nil
	}
	return m
}

func (m *MemEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, m)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *MemEvent) Recycle() {
	poolOfMemEvents.Put(m)
}

type MmapEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Addr      uint64
	Length    uint64
	Prot      uint64
	Flags     uint64
	Fd        int32
}

func (m MmapEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Addr:%v Length:%v Prot:%v Flags:%v Fd:%v", m.EventType, m.TraceId, m.Time, m.Pid, m.Tid, m.Addr, m.Length, m.Prot, m.Flags, m.Fd)
}

func (m MmapEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*MmapEvent)
	if !ok {
		return false
	}
	return m.EventType == otherConcrete.EventType && m.TraceId == otherConcrete.TraceId && m.Time == otherConcrete.Time && m.Pid == otherConcrete.Pid && m.Tid == otherConcrete.Tid && m.Addr == otherConcrete.Addr && m.Length == otherConcrete.Length && m.Prot == otherConcrete.Prot && m.Flags == otherConcrete.Flags && m.Fd == otherConcrete.Fd
}

func (m *MmapEvent) GetEventType() EventType {
	return m.EventType
}

func (m *MmapEvent) GetTraceId() TraceId {
	return m.TraceId
}

func (m *MmapEvent) GetPid() uint32 {
	return m.Pid
}

func (m *MmapEvent) GetTid() uint32 {
	return m.Tid
}

func (m *MmapEvent) GetTime() uint64 {
	return m.Time
}

var poolOfMmapEvents = sync.Pool{
	New: func() any { return &MmapEvent{} },
}

func NewMmapEvent(raw []byte) *MmapEvent {
	m := poolOfMmapEvents.Get().(*MmapEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, m); err != nil {
		*m = MmapEvent{}
		poolOfMmapEvents.Put(m)
		return nil
	}
	return m
}

func (m *MmapEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, m)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *MmapEvent) Recycle() {
	poolOfMmapEvents.Put(m)
}

type SleepEvent struct {
	EventType   EventType
	TraceId     TraceId
	Time        uint64
	Pid         uint32
	Tid         uint32
	RequestedNs int64
}

func (s SleepEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v RequestedNs:%v", s.EventType, s.TraceId, s.Time, s.Pid, s.Tid, s.RequestedNs)
}

func (s SleepEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*SleepEvent)
	if !ok {
		return false
	}
	return s.EventType == otherConcrete.EventType && s.TraceId == otherConcrete.TraceId && s.Time == otherConcrete.Time && s.Pid == otherConcrete.Pid && s.Tid == otherConcrete.Tid && s.RequestedNs == otherConcrete.RequestedNs
}

func (s *SleepEvent) GetEventType() EventType {
	return s.EventType
}

func (s *SleepEvent) GetTraceId() TraceId {
	return s.TraceId
}

func (s *SleepEvent) GetPid() uint32 {
	return s.Pid
}

func (s *SleepEvent) GetTid() uint32 {
	return s.Tid
}

func (s *SleepEvent) GetTime() uint64 {
	return s.Time
}

var poolOfSleepEvents = sync.Pool{
	New: func() any { return &SleepEvent{} },
}

func NewSleepEvent(raw []byte) *SleepEvent {
	s := poolOfSleepEvents.Get().(*SleepEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, s); err != nil {
		*s = SleepEvent{}
		poolOfSleepEvents.Put(s)
		return nil
	}
	return s
}

func (s *SleepEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, s)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *SleepEvent) Recycle() {
	poolOfSleepEvents.Put(s)
}

type TwoFdEvent struct {
	EventType     EventType
	TraceId       TraceId
	Time          uint64
	Pid           uint32
	Tid           uint32
	FdA           int32
	FdB           int32
	Extra         uint64
	SchemaVersion uint32
	Oldname       [MAX_FILENAME_LENGTH]byte
	Newname       [MAX_FILENAME_LENGTH]byte
	OldnameStatus uint32
	NewnameStatus uint32
}

func (t TwoFdEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v FdA:%v FdB:%v Extra:%v SchemaVersion:%v Oldname:%v Newname:%v OldnameStatus:%v NewnameStatus:%v", t.EventType, t.TraceId, t.Time, t.Pid, t.Tid, t.FdA, t.FdB, t.Extra, t.SchemaVersion, StringValue(t.Oldname[:]), StringValue(t.Newname[:]), t.OldnameStatus, t.NewnameStatus)
}

func (t TwoFdEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*TwoFdEvent)
	if !ok {
		return false
	}
	return t.EventType == otherConcrete.EventType && t.TraceId == otherConcrete.TraceId && t.Time == otherConcrete.Time && t.Pid == otherConcrete.Pid && t.Tid == otherConcrete.Tid && t.FdA == otherConcrete.FdA && t.FdB == otherConcrete.FdB && t.Extra == otherConcrete.Extra && t.SchemaVersion == otherConcrete.SchemaVersion && t.Oldname == otherConcrete.Oldname && t.Newname == otherConcrete.Newname && t.OldnameStatus == otherConcrete.OldnameStatus && t.NewnameStatus == otherConcrete.NewnameStatus
}

func (t *TwoFdEvent) GetEventType() EventType {
	return t.EventType
}

func (t *TwoFdEvent) GetTraceId() TraceId {
	return t.TraceId
}

func (t *TwoFdEvent) GetPid() uint32 {
	return t.Pid
}

func (t *TwoFdEvent) GetTid() uint32 {
	return t.Tid
}

func (t *TwoFdEvent) GetTime() uint64 {
	return t.Time
}

var poolOfTwoFdEvents = sync.Pool{
	New: func() any { return &TwoFdEvent{} },
}

func NewTwoFdEvent(raw []byte) *TwoFdEvent {
	if len(raw) != 568 && len(raw) != 564 && len(raw) != 48 && len(raw) != 44 && len(raw) != 40 {
		return nil
	}
	t := poolOfTwoFdEvents.Get().(*TwoFdEvent)
	t.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	t.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	t.Time = binary.LittleEndian.Uint64(raw[8:16])
	t.Pid = binary.LittleEndian.Uint32(raw[16:20])
	t.Tid = binary.LittleEndian.Uint32(raw[20:24])
	t.FdA = int32(binary.LittleEndian.Uint32(raw[24:28]))
	t.FdB = int32(binary.LittleEndian.Uint32(raw[28:32]))
	t.Extra = binary.LittleEndian.Uint64(raw[32:40])
	t.Oldname = [MAX_FILENAME_LENGTH]byte{}
	t.Newname = [MAX_FILENAME_LENGTH]byte{}
	t.OldnameStatus = PATH_READ_NULL
	t.NewnameStatus = PATH_READ_NULL
	t.SchemaVersion = 0
	if len(raw) != 40 {
		if len(raw) >= 564 {
			copy(t.Oldname[:], raw[40:296])
			copy(t.Newname[:], raw[296:552])
			t.OldnameStatus = binary.LittleEndian.Uint32(raw[552:556])
			t.NewnameStatus = binary.LittleEndian.Uint32(raw[556:560])
			t.SchemaVersion = binary.LittleEndian.Uint32(raw[560:564])
		} else {
			t.SchemaVersion = binary.LittleEndian.Uint32(raw[40:44])
		}
		if t.SchemaVersion != TWO_FD_EVENT_SCHEMA_VERSION && !(len(raw) >= 564 && t.SchemaVersion == TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION) {
			t.Recycle()
			return nil
		}
	}
	return t
}

func (t *TwoFdEvent) Bytes() ([]byte, error) {
	size := 48
	if t.EventType == ENTER_TWO_FD_NAMES_EVENT || t.SchemaVersion == TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION || t.OldnameStatus != PATH_READ_NULL || t.NewnameStatus != PATH_READ_NULL || t.Oldname != [MAX_FILENAME_LENGTH]byte{} || t.Newname != [MAX_FILENAME_LENGTH]byte{} {
		size = 568
	}
	raw := make([]byte, size)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(t.EventType))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(t.TraceId))
	binary.LittleEndian.PutUint64(raw[8:16], t.Time)
	binary.LittleEndian.PutUint32(raw[16:20], t.Pid)
	binary.LittleEndian.PutUint32(raw[20:24], t.Tid)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(t.FdA))
	binary.LittleEndian.PutUint32(raw[28:32], uint32(t.FdB))
	binary.LittleEndian.PutUint64(raw[32:40], t.Extra)
	if len(raw) == 568 {
		copy(raw[40:296], t.Oldname[:])
		copy(raw[296:552], t.Newname[:])
		binary.LittleEndian.PutUint32(raw[552:556], t.OldnameStatus)
		binary.LittleEndian.PutUint32(raw[556:560], t.NewnameStatus)
		binary.LittleEndian.PutUint32(raw[560:564], t.SchemaVersion)
	} else {
		binary.LittleEndian.PutUint32(raw[40:44], t.SchemaVersion)
	}
	return raw, nil
}

func (t *TwoFdEvent) Recycle() {
	poolOfTwoFdEvents.Put(t)
}

type TwoFdNamesEvent struct {
	EventType     EventType
	TraceId       TraceId
	Time          uint64
	Pid           uint32
	Tid           uint32
	FdA           int32
	FdB           int32
	Extra         uint64
	Oldname       [MAX_FILENAME_LENGTH]byte
	Newname       [MAX_FILENAME_LENGTH]byte
	OldnameStatus uint32
	NewnameStatus uint32
	SchemaVersion uint32
}

func (t TwoFdNamesEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v FdA:%v FdB:%v Extra:%v Oldname:%v Newname:%v OldnameStatus:%v NewnameStatus:%v SchemaVersion:%v", t.EventType, t.TraceId, t.Time, t.Pid, t.Tid, t.FdA, t.FdB, t.Extra, StringValue(t.Oldname[:]), StringValue(t.Newname[:]), t.OldnameStatus, t.NewnameStatus, t.SchemaVersion)
}

func (t TwoFdNamesEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*TwoFdNamesEvent)
	if !ok {
		return false
	}
	return t.EventType == otherConcrete.EventType && t.TraceId == otherConcrete.TraceId && t.Time == otherConcrete.Time && t.Pid == otherConcrete.Pid && t.Tid == otherConcrete.Tid && t.FdA == otherConcrete.FdA && t.FdB == otherConcrete.FdB && t.Extra == otherConcrete.Extra && t.Oldname == otherConcrete.Oldname && t.Newname == otherConcrete.Newname && t.OldnameStatus == otherConcrete.OldnameStatus && t.NewnameStatus == otherConcrete.NewnameStatus && t.SchemaVersion == otherConcrete.SchemaVersion
}

func (t *TwoFdNamesEvent) GetEventType() EventType {
	return t.EventType
}

func (t *TwoFdNamesEvent) GetTraceId() TraceId {
	return t.TraceId
}

func (t *TwoFdNamesEvent) GetPid() uint32 {
	return t.Pid
}

func (t *TwoFdNamesEvent) GetTid() uint32 {
	return t.Tid
}

func (t *TwoFdNamesEvent) GetTime() uint64 {
	return t.Time
}

var poolOfTwoFdNamesEvents = sync.Pool{
	New: func() any { return &TwoFdNamesEvent{} },
}

func NewTwoFdNamesEvent(raw []byte) *TwoFdNamesEvent {
	if len(raw) != 568 && len(raw) != 564 {
		return nil
	}
	t := poolOfTwoFdNamesEvents.Get().(*TwoFdNamesEvent)
	t.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	t.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	t.Time = binary.LittleEndian.Uint64(raw[8:16])
	t.Pid = binary.LittleEndian.Uint32(raw[16:20])
	t.Tid = binary.LittleEndian.Uint32(raw[20:24])
	t.FdA = int32(binary.LittleEndian.Uint32(raw[24:28]))
	t.FdB = int32(binary.LittleEndian.Uint32(raw[28:32]))
	t.Extra = binary.LittleEndian.Uint64(raw[32:40])
	copy(t.Oldname[:], raw[40:296])
	copy(t.Newname[:], raw[296:552])
	t.OldnameStatus = binary.LittleEndian.Uint32(raw[552:556])
	t.NewnameStatus = binary.LittleEndian.Uint32(raw[556:560])
	t.SchemaVersion = binary.LittleEndian.Uint32(raw[560:564])
	if t.SchemaVersion != TWO_FD_EVENT_SCHEMA_VERSION && t.SchemaVersion != TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION {
		t.Recycle()
		return nil
	}
	return t
}

func (t *TwoFdNamesEvent) Bytes() ([]byte, error) {
	raw := make([]byte, 568)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(t.EventType))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(t.TraceId))
	binary.LittleEndian.PutUint64(raw[8:16], t.Time)
	binary.LittleEndian.PutUint32(raw[16:20], t.Pid)
	binary.LittleEndian.PutUint32(raw[20:24], t.Tid)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(t.FdA))
	binary.LittleEndian.PutUint32(raw[28:32], uint32(t.FdB))
	binary.LittleEndian.PutUint64(raw[32:40], t.Extra)
	copy(raw[40:296], t.Oldname[:])
	copy(raw[296:552], t.Newname[:])
	binary.LittleEndian.PutUint32(raw[552:556], t.OldnameStatus)
	binary.LittleEndian.PutUint32(raw[556:560], t.NewnameStatus)
	binary.LittleEndian.PutUint32(raw[560:564], t.SchemaVersion)
	return raw, nil
}

func (t *TwoFdNamesEvent) Recycle() {
	poolOfTwoFdNamesEvents.Put(t)
}

type BpfEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Cmd       uint32
}

func (b BpfEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Cmd:%v", b.EventType, b.TraceId, b.Time, b.Pid, b.Tid, b.Cmd)
}

func (b BpfEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*BpfEvent)
	if !ok {
		return false
	}
	return b.EventType == otherConcrete.EventType && b.TraceId == otherConcrete.TraceId && b.Time == otherConcrete.Time && b.Pid == otherConcrete.Pid && b.Tid == otherConcrete.Tid && b.Cmd == otherConcrete.Cmd
}

func (b *BpfEvent) GetEventType() EventType {
	return b.EventType
}

func (b *BpfEvent) GetTraceId() TraceId {
	return b.TraceId
}

func (b *BpfEvent) GetPid() uint32 {
	return b.Pid
}

func (b *BpfEvent) GetTid() uint32 {
	return b.Tid
}

func (b *BpfEvent) GetTime() uint64 {
	return b.Time
}

var poolOfBpfEvents = sync.Pool{
	New: func() any { return &BpfEvent{} },
}

func NewBpfEvent(raw []byte) *BpfEvent {
	b := poolOfBpfEvents.Get().(*BpfEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, b); err != nil {
		*b = BpfEvent{}
		poolOfBpfEvents.Put(b)
		return nil
	}
	return b
}

func (b *BpfEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, b)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *BpfEvent) Recycle() {
	poolOfBpfEvents.Put(b)
}

type KeyctlEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Option    int32
	KeySerial int32
	Value     uint64
}

func (k KeyctlEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Option:%v KeySerial:%v Value:%v", k.EventType, k.TraceId, k.Time, k.Pid, k.Tid, k.Option, k.KeySerial, k.Value)
}

func (k KeyctlEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*KeyctlEvent)
	if !ok {
		return false
	}
	return k.EventType == otherConcrete.EventType && k.TraceId == otherConcrete.TraceId && k.Time == otherConcrete.Time && k.Pid == otherConcrete.Pid && k.Tid == otherConcrete.Tid && k.Option == otherConcrete.Option && k.KeySerial == otherConcrete.KeySerial && k.Value == otherConcrete.Value
}

func (k *KeyctlEvent) GetEventType() EventType {
	return k.EventType
}

func (k *KeyctlEvent) GetTraceId() TraceId {
	return k.TraceId
}

func (k *KeyctlEvent) GetPid() uint32 {
	return k.Pid
}

func (k *KeyctlEvent) GetTid() uint32 {
	return k.Tid
}

func (k *KeyctlEvent) GetTime() uint64 {
	return k.Time
}

var poolOfKeyctlEvents = sync.Pool{
	New: func() any { return &KeyctlEvent{} },
}

func NewKeyctlEvent(raw []byte) *KeyctlEvent {
	k := poolOfKeyctlEvents.Get().(*KeyctlEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, k); err != nil {
		*k = KeyctlEvent{}
		poolOfKeyctlEvents.Put(k)
		return nil
	}
	return k
}

func (k *KeyctlEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, k)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (k *KeyctlEvent) Recycle() {
	poolOfKeyctlEvents.Put(k)
}

type PtraceEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Request   int64
	TargetPid int32
	Pad       int32
	Data      uint64
}

func (p PtraceEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Request:%v TargetPid:%v Pad:%v Data:%v", p.EventType, p.TraceId, p.Time, p.Pid, p.Tid, p.Request, p.TargetPid, p.Pad, p.Data)
}

func (p PtraceEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*PtraceEvent)
	if !ok {
		return false
	}
	return p.EventType == otherConcrete.EventType && p.TraceId == otherConcrete.TraceId && p.Time == otherConcrete.Time && p.Pid == otherConcrete.Pid && p.Tid == otherConcrete.Tid && p.Request == otherConcrete.Request && p.TargetPid == otherConcrete.TargetPid && p.Pad == otherConcrete.Pad && p.Data == otherConcrete.Data
}

func (p *PtraceEvent) GetEventType() EventType {
	return p.EventType
}

func (p *PtraceEvent) GetTraceId() TraceId {
	return p.TraceId
}

func (p *PtraceEvent) GetPid() uint32 {
	return p.Pid
}

func (p *PtraceEvent) GetTid() uint32 {
	return p.Tid
}

func (p *PtraceEvent) GetTime() uint64 {
	return p.Time
}

var poolOfPtraceEvents = sync.Pool{
	New: func() any { return &PtraceEvent{} },
}

func NewPtraceEvent(raw []byte) *PtraceEvent {
	p := poolOfPtraceEvents.Get().(*PtraceEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, p); err != nil {
		*p = PtraceEvent{}
		poolOfPtraceEvents.Put(p)
		return nil
	}
	return p
}

func (p *PtraceEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *PtraceEvent) Recycle() {
	poolOfPtraceEvents.Put(p)
}

type PerfOpenEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	AttrType  uint32
	AttrSize  uint32
	Config    uint64
	TargetPid int32
	Cpu       int32
	GroupFd   int32
	Flags     uint32
}

func (p PerfOpenEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v AttrType:%v AttrSize:%v Config:%v TargetPid:%v Cpu:%v GroupFd:%v Flags:%v", p.EventType, p.TraceId, p.Time, p.Pid, p.Tid, p.AttrType, p.AttrSize, p.Config, p.TargetPid, p.Cpu, p.GroupFd, p.Flags)
}

func (p PerfOpenEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*PerfOpenEvent)
	if !ok {
		return false
	}
	return p.EventType == otherConcrete.EventType && p.TraceId == otherConcrete.TraceId && p.Time == otherConcrete.Time && p.Pid == otherConcrete.Pid && p.Tid == otherConcrete.Tid && p.AttrType == otherConcrete.AttrType && p.AttrSize == otherConcrete.AttrSize && p.Config == otherConcrete.Config && p.TargetPid == otherConcrete.TargetPid && p.Cpu == otherConcrete.Cpu && p.GroupFd == otherConcrete.GroupFd && p.Flags == otherConcrete.Flags
}

func (p *PerfOpenEvent) GetEventType() EventType {
	return p.EventType
}

func (p *PerfOpenEvent) GetTraceId() TraceId {
	return p.TraceId
}

func (p *PerfOpenEvent) GetPid() uint32 {
	return p.Pid
}

func (p *PerfOpenEvent) GetTid() uint32 {
	return p.Tid
}

func (p *PerfOpenEvent) GetTime() uint64 {
	return p.Time
}

var poolOfPerfOpenEvents = sync.Pool{
	New: func() any { return &PerfOpenEvent{} },
}

func NewPerfOpenEvent(raw []byte) *PerfOpenEvent {
	p := poolOfPerfOpenEvents.Get().(*PerfOpenEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, p); err != nil {
		*p = PerfOpenEvent{}
		poolOfPerfOpenEvents.Put(p)
		return nil
	}
	return p
}

func (p *PerfOpenEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *PerfOpenEvent) Recycle() {
	poolOfPerfOpenEvents.Put(p)
}

type ProcessExecEvent struct {
	EventType    EventType
	TraceId      TraceId
	Time         uint64
	Pid          uint32
	Tid          uint32
	Comm         [MAX_PROGNAME_LENGTH]byte
	OldTid       uint32
	ExitUntraced uint32
}

func (p ProcessExecEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Comm:%v OldTid:%v ExitUntraced:%v", p.EventType, p.TraceId, p.Time, p.Pid, p.Tid, StringValue(p.Comm[:]), p.OldTid, p.ExitUntraced)
}

func (p ProcessExecEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*ProcessExecEvent)
	if !ok {
		return false
	}
	return p.EventType == otherConcrete.EventType && p.TraceId == otherConcrete.TraceId && p.Time == otherConcrete.Time && p.Pid == otherConcrete.Pid && p.Tid == otherConcrete.Tid && p.Comm == otherConcrete.Comm && p.OldTid == otherConcrete.OldTid && p.ExitUntraced == otherConcrete.ExitUntraced
}

func (p *ProcessExecEvent) GetEventType() EventType {
	return p.EventType
}

func (p *ProcessExecEvent) GetTraceId() TraceId {
	return p.TraceId
}

func (p *ProcessExecEvent) GetPid() uint32 {
	return p.Pid
}

func (p *ProcessExecEvent) GetTid() uint32 {
	return p.Tid
}

func (p *ProcessExecEvent) GetTime() uint64 {
	return p.Time
}

var poolOfProcessExecEvents = sync.Pool{
	New: func() any { return &ProcessExecEvent{} },
}

func NewProcessExecEvent(raw []byte) *ProcessExecEvent {
	p := poolOfProcessExecEvents.Get().(*ProcessExecEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, p); err != nil {
		*p = ProcessExecEvent{}
		poolOfProcessExecEvents.Put(p)
		return nil
	}
	return p
}

func (p *ProcessExecEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *ProcessExecEvent) Recycle() {
	poolOfProcessExecEvents.Put(p)
}

type ProcessExitEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	GroupDead uint32
	ExitFlags uint32
}

func (p ProcessExitEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v GroupDead:%v ExitFlags:%v", p.EventType, p.TraceId, p.Time, p.Pid, p.Tid, p.GroupDead, p.ExitFlags)
}

func (p ProcessExitEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*ProcessExitEvent)
	if !ok {
		return false
	}
	return p.EventType == otherConcrete.EventType && p.TraceId == otherConcrete.TraceId && p.Time == otherConcrete.Time && p.Pid == otherConcrete.Pid && p.Tid == otherConcrete.Tid && p.GroupDead == otherConcrete.GroupDead && p.ExitFlags == otherConcrete.ExitFlags
}

func (p *ProcessExitEvent) GetEventType() EventType {
	return p.EventType
}

func (p *ProcessExitEvent) GetTraceId() TraceId {
	return p.TraceId
}

func (p *ProcessExitEvent) GetPid() uint32 {
	return p.Pid
}

func (p *ProcessExitEvent) GetTid() uint32 {
	return p.Tid
}

func (p *ProcessExitEvent) GetTime() uint64 {
	return p.Time
}

var poolOfProcessExitEvents = sync.Pool{
	New: func() any { return &ProcessExitEvent{} },
}

func NewProcessExitEvent(raw []byte) *ProcessExitEvent {
	p := poolOfProcessExitEvents.Get().(*ProcessExitEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, p); err != nil {
		*p = ProcessExitEvent{}
		poolOfProcessExitEvents.Put(p)
		return nil
	}
	return p
}

func (p *ProcessExitEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *ProcessExitEvent) Recycle() {
	poolOfProcessExitEvents.Put(p)
}

type TaskNewtaskEvent struct {
	EventType  EventType
	TraceId    TraceId
	Time       uint64
	Pid        uint32
	Tid        uint32
	Comm       [MAX_PROGNAME_LENGTH]byte
	CloneFlags uint64
	CreatorPid uint32
	ScopeFlags uint32
}

func (t TaskNewtaskEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Comm:%v CloneFlags:%v CreatorPid:%v ScopeFlags:%v", t.EventType, t.TraceId, t.Time, t.Pid, t.Tid, StringValue(t.Comm[:]), t.CloneFlags, t.CreatorPid, t.ScopeFlags)
}

func (t TaskNewtaskEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*TaskNewtaskEvent)
	if !ok {
		return false
	}
	return t.EventType == otherConcrete.EventType && t.TraceId == otherConcrete.TraceId && t.Time == otherConcrete.Time && t.Pid == otherConcrete.Pid && t.Tid == otherConcrete.Tid && t.Comm == otherConcrete.Comm && t.CloneFlags == otherConcrete.CloneFlags && t.CreatorPid == otherConcrete.CreatorPid && t.ScopeFlags == otherConcrete.ScopeFlags
}

func (t *TaskNewtaskEvent) GetEventType() EventType {
	return t.EventType
}

func (t *TaskNewtaskEvent) GetTraceId() TraceId {
	return t.TraceId
}

func (t *TaskNewtaskEvent) GetPid() uint32 {
	return t.Pid
}

func (t *TaskNewtaskEvent) GetTid() uint32 {
	return t.Tid
}

func (t *TaskNewtaskEvent) GetTime() uint64 {
	return t.Time
}

var poolOfTaskNewtaskEvents = sync.Pool{
	New: func() any { return &TaskNewtaskEvent{} },
}

func NewTaskNewtaskEvent(raw []byte) *TaskNewtaskEvent {
	t := poolOfTaskNewtaskEvents.Get().(*TaskNewtaskEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, t); err != nil {
		*t = TaskNewtaskEvent{}
		poolOfTaskNewtaskEvents.Put(t)
		return nil
	}
	return t
}

func (t *TaskNewtaskEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, t)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (t *TaskNewtaskEvent) Recycle() {
	poolOfTaskNewtaskEvents.Put(t)
}

type TaskRenameEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Comm      [MAX_PROGNAME_LENGTH]byte
}

func (t TaskRenameEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Comm:%v", t.EventType, t.TraceId, t.Time, t.Pid, t.Tid, StringValue(t.Comm[:]))
}

func (t TaskRenameEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*TaskRenameEvent)
	if !ok {
		return false
	}
	return t.EventType == otherConcrete.EventType && t.TraceId == otherConcrete.TraceId && t.Time == otherConcrete.Time && t.Pid == otherConcrete.Pid && t.Tid == otherConcrete.Tid && t.Comm == otherConcrete.Comm
}

func (t *TaskRenameEvent) GetEventType() EventType {
	return t.EventType
}

func (t *TaskRenameEvent) GetTraceId() TraceId {
	return t.TraceId
}

func (t *TaskRenameEvent) GetPid() uint32 {
	return t.Pid
}

func (t *TaskRenameEvent) GetTid() uint32 {
	return t.Tid
}

func (t *TaskRenameEvent) GetTime() uint64 {
	return t.Time
}

var poolOfTaskRenameEvents = sync.Pool{
	New: func() any { return &TaskRenameEvent{} },
}

func NewTaskRenameEvent(raw []byte) *TaskRenameEvent {
	t := poolOfTaskRenameEvents.Get().(*TaskRenameEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, t); err != nil {
		*t = TaskRenameEvent{}
		poolOfTaskRenameEvents.Put(t)
		return nil
	}
	return t
}

func (t *TaskRenameEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, t)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (t *TaskRenameEvent) Recycle() {
	poolOfTaskRenameEvents.Put(t)
}

type SyscallRestartEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Phase     uint32
	SaRestart uint32
}

func (s SyscallRestartEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Phase:%v SaRestart:%v", s.EventType, s.TraceId, s.Time, s.Pid, s.Tid, s.Phase, s.SaRestart)
}

func (s SyscallRestartEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*SyscallRestartEvent)
	if !ok {
		return false
	}
	return s.EventType == otherConcrete.EventType && s.TraceId == otherConcrete.TraceId && s.Time == otherConcrete.Time && s.Pid == otherConcrete.Pid && s.Tid == otherConcrete.Tid && s.Phase == otherConcrete.Phase && s.SaRestart == otherConcrete.SaRestart
}

func (s *SyscallRestartEvent) GetEventType() EventType {
	return s.EventType
}

func (s *SyscallRestartEvent) GetTraceId() TraceId {
	return s.TraceId
}

func (s *SyscallRestartEvent) GetPid() uint32 {
	return s.Pid
}

func (s *SyscallRestartEvent) GetTid() uint32 {
	return s.Tid
}

func (s *SyscallRestartEvent) GetTime() uint64 {
	return s.Time
}

var poolOfSyscallRestartEvents = sync.Pool{
	New: func() any { return &SyscallRestartEvent{} },
}

func NewSyscallRestartEvent(raw []byte) *SyscallRestartEvent {
	s := poolOfSyscallRestartEvents.Get().(*SyscallRestartEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, s); err != nil {
		*s = SyscallRestartEvent{}
		poolOfSyscallRestartEvents.Put(s)
		return nil
	}
	return s
}

func (s *SyscallRestartEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, s)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *SyscallRestartEvent) Recycle() {
	poolOfSyscallRestartEvents.Put(s)
}
