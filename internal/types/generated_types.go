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
	1847: "enter_socket", 1846: "exit_socket", 1845: "enter_socketpair", 1844: "exit_socketpair", 1843: "enter_bind", 1842: "exit_bind", 1841: "enter_listen", 1840: "exit_listen", 1839: "enter_accept4", 1838: "exit_accept4", 1837: "enter_accept", 1836: "exit_accept", 1835: "enter_connect", 1834: "exit_connect", 1833: "enter_getsockname", 1832: "exit_getsockname", 1831: "enter_getpeername", 1830: "exit_getpeername", 1829: "enter_sendto", 1828: "exit_sendto", 1827: "enter_recvfrom", 1826: "exit_recvfrom", 1825: "enter_setsockopt", 1824: "exit_setsockopt", 1823: "enter_getsockopt", 1822: "exit_getsockopt", 1821: "enter_shutdown", 1820: "exit_shutdown", 1819: "enter_sendmsg", 1818: "exit_sendmsg", 1817: "enter_sendmmsg", 1816: "exit_sendmmsg", 1815: "enter_recvmsg", 1814: "exit_recvmsg", 1813: "enter_recvmmsg", 1812: "exit_recvmmsg", 1575: "enter_getrandom", 1574: "exit_getrandom", 1528: "enter_io_uring_register", 1527: "exit_io_uring_register", 1509: "enter_io_uring_enter", 1508: "exit_io_uring_enter", 1507: "enter_io_uring_setup", 1506: "exit_io_uring_setup", 1491: "enter_ioprio_set", 1490: "exit_ioprio_set", 1489: "enter_ioprio_get", 1488: "exit_ioprio_get", 1463: "enter_landlock_create_ruleset", 1462: "exit_landlock_create_ruleset", 1461: "enter_landlock_add_rule", 1460: "exit_landlock_add_rule", 1459: "enter_landlock_restrict_self", 1458: "exit_landlock_restrict_self", 1456: "enter_lsm_set_self_attr", 1455: "exit_lsm_set_self_attr", 1454: "enter_lsm_get_self_attr", 1453: "exit_lsm_get_self_attr", 1452: "enter_lsm_list_modules", 1451: "exit_lsm_list_modules", 1449: "enter_add_key", 1448: "exit_add_key", 1447: "enter_request_key", 1446: "exit_request_key", 1445: "enter_keyctl", 1444: "exit_keyctl", 1443: "enter_mq_open", 1442: "exit_mq_open", 1441: "enter_mq_unlink", 1440: "exit_mq_unlink", 1439: "enter_mq_timedsend", 1438: "exit_mq_timedsend", 1437: "enter_mq_timedreceive", 1436: "exit_mq_timedreceive", 1435: "enter_mq_notify", 1434: "exit_mq_notify", 1433: "enter_mq_getsetattr", 1432: "exit_mq_getsetattr", 1431: "enter_shmget", 1430: "exit_shmget", 1429: "enter_shmctl", 1428: "exit_shmctl", 1427: "enter_shmat", 1426: "exit_shmat", 1425: "enter_shmdt", 1424: "exit_shmdt", 1423: "enter_semget", 1422: "exit_semget", 1421: "enter_semctl", 1420: "exit_semctl", 1419: "enter_semtimedop", 1418: "exit_semtimedop", 1417: "enter_semop", 1416: "exit_semop", 1415: "enter_msgget", 1414: "exit_msgget", 1413: "enter_msgctl", 1412: "exit_msgctl", 1411: "enter_msgsnd", 1410: "exit_msgsnd", 1409: "enter_msgrcv", 1408: "exit_msgrcv", 1164: "enter_quotactl", 1163: "exit_quotactl", 1162: "enter_quotactl_fd", 1161: "exit_quotactl_fd", 1146: "enter_name_to_handle_at", 1145: "exit_name_to_handle_at", 1144: "enter_open_by_handle_at", 1143: "exit_open_by_handle_at", 1130: "enter_flock", 1129: "exit_flock", 1111: "enter_io_setup", 1110: "exit_io_setup", 1109: "enter_io_destroy", 1108: "exit_io_destroy", 1107: "enter_io_submit", 1106: "exit_io_submit", 1105: "enter_io_cancel", 1104: "exit_io_cancel", 1103: "enter_io_getevents", 1102: "exit_io_getevents", 1101: "enter_io_pgetevents", 1100: "exit_io_pgetevents", 1099: "enter_userfaultfd", 1098: "exit_userfaultfd", 1097: "enter_eventfd2", 1096: "exit_eventfd2", 1095: "enter_eventfd", 1094: "exit_eventfd", 1093: "enter_timerfd_create", 1092: "exit_timerfd_create", 1091: "enter_timerfd_settime", 1090: "exit_timerfd_settime", 1089: "enter_timerfd_gettime", 1088: "exit_timerfd_gettime", 1087: "enter_signalfd4", 1086: "exit_signalfd4", 1085: "enter_signalfd", 1084: "exit_signalfd", 1083: "enter_epoll_create1", 1082: "exit_epoll_create1", 1081: "enter_epoll_create", 1080: "exit_epoll_create", 1079: "enter_epoll_ctl", 1078: "exit_epoll_ctl", 1077: "enter_epoll_wait", 1076: "exit_epoll_wait", 1075: "enter_epoll_pwait", 1074: "exit_epoll_pwait", 1073: "enter_epoll_pwait2", 1072: "exit_epoll_pwait2", 1071: "enter_fanotify_init", 1070: "exit_fanotify_init", 1069: "enter_fanotify_mark", 1068: "exit_fanotify_mark", 1067: "enter_inotify_init1", 1066: "exit_inotify_init1", 1065: "enter_inotify_init", 1064: "exit_inotify_init", 1063: "enter_inotify_add_watch", 1062: "exit_inotify_add_watch", 1061: "enter_inotify_rm_watch", 1060: "exit_inotify_rm_watch", 1059: "enter_file_getattr", 1058: "exit_file_getattr", 1057: "enter_file_setattr", 1056: "exit_file_setattr", 1055: "enter_fsopen", 1054: "exit_fsopen", 1053: "enter_fspick", 1052: "exit_fspick", 1051: "enter_fsconfig", 1050: "exit_fsconfig", 1049: "enter_statfs", 1048: "exit_statfs", 1047: "enter_fstatfs", 1046: "exit_fstatfs", 1045: "enter_ustat", 1044: "exit_ustat", 1043: "enter_getcwd", 1042: "exit_getcwd", 1041: "enter_utimensat", 1040: "exit_utimensat", 1039: "enter_futimesat", 1038: "exit_futimesat", 1037: "enter_utimes", 1036: "exit_utimes", 1035: "enter_utime", 1034: "exit_utime", 1033: "enter_sync", 1032: "exit_sync", 1031: "enter_syncfs", 1030: "exit_syncfs", 1029: "enter_fsync", 1028: "exit_fsync", 1027: "enter_fdatasync", 1026: "exit_fdatasync", 1025: "enter_sync_file_range", 1024: "exit_sync_file_range", 1023: "enter_vmsplice", 1022: "exit_vmsplice", 1021: "enter_splice", 1020: "exit_splice", 1019: "enter_tee", 1018: "exit_tee", 985: "enter_setxattrat", 984: "exit_setxattrat", 983: "enter_setxattr", 982: "exit_setxattr", 981: "enter_lsetxattr", 980: "exit_lsetxattr", 979: "enter_fsetxattr", 978: "exit_fsetxattr", 977: "enter_getxattrat", 976: "exit_getxattrat", 975: "enter_getxattr", 974: "exit_getxattr", 973: "enter_lgetxattr", 972: "exit_lgetxattr", 971: "enter_fgetxattr", 970: "exit_fgetxattr", 969: "enter_listxattrat", 968: "exit_listxattrat", 967: "enter_listxattr", 966: "exit_listxattr", 965: "enter_llistxattr", 964: "exit_llistxattr", 963: "enter_flistxattr", 962: "exit_flistxattr", 961: "enter_removexattrat", 960: "exit_removexattrat", 959: "enter_removexattr", 958: "exit_removexattr", 957: "enter_lremovexattr", 956: "exit_lremovexattr", 955: "enter_fremovexattr", 954: "exit_fremovexattr", 953: "enter_umount", 952: "exit_umount", 951: "enter_open_tree", 950: "exit_open_tree", 949: "enter_mount", 948: "exit_mount", 947: "enter_fsmount", 946: "exit_fsmount", 945: "enter_move_mount", 944: "exit_move_mount", 943: "enter_pivot_root", 942: "exit_pivot_root", 941: "enter_mount_setattr", 940: "exit_mount_setattr", 939: "enter_open_tree_attr", 938: "exit_open_tree_attr", 937: "enter_statmount", 936: "exit_statmount", 935: "enter_listmount", 934: "exit_listmount", 933: "enter_sysfs", 932: "exit_sysfs", 931: "enter_close_range", 930: "exit_close_range", 929: "enter_dup3", 928: "exit_dup3", 927: "enter_dup2", 926: "exit_dup2", 925: "enter_dup", 924: "exit_dup", 919: "enter_select", 918: "exit_select", 917: "enter_pselect6", 916: "exit_pselect6", 915: "enter_poll", 914: "exit_poll", 913: "enter_ppoll", 912: "exit_ppoll", 911: "enter_getdents", 910: "exit_getdents", 909: "enter_getdents64", 908: "exit_getdents64", 907: "enter_ioctl", 906: "exit_ioctl", 905: "enter_fcntl", 904: "exit_fcntl", 903: "enter_mknodat", 902: "exit_mknodat", 901: "enter_mknod", 900: "exit_mknod", 899: "enter_mkdirat", 898: "exit_mkdirat", 897: "enter_mkdir", 896: "exit_mkdir", 895: "enter_rmdir", 894: "exit_rmdir", 893: "enter_unlinkat", 892: "exit_unlinkat", 891: "enter_unlink", 890: "exit_unlink", 889: "enter_symlinkat", 888: "exit_symlinkat", 887: "enter_symlink", 886: "exit_symlink", 885: "enter_linkat", 884: "exit_linkat", 883: "enter_link", 882: "exit_link", 881: "enter_renameat2", 880: "exit_renameat2", 879: "enter_renameat", 878: "exit_renameat", 877: "enter_rename", 876: "exit_rename", 875: "enter_pipe2", 874: "exit_pipe2", 873: "enter_pipe", 872: "exit_pipe", 871: "enter_execve", 870: "exit_execve", 869: "enter_execveat", 868: "exit_execveat", 867: "enter_newstat", 866: "exit_newstat", 865: "enter_newlstat", 864: "exit_newlstat", 863: "enter_newfstatat", 862: "exit_newfstatat", 861: "enter_newfstat", 860: "exit_newfstat", 859: "enter_readlinkat", 858: "exit_readlinkat", 857: "enter_readlink", 856: "exit_readlink", 855: "enter_statx", 854: "exit_statx", 853: "enter_lseek", 852: "exit_lseek", 851: "enter_read", 850: "exit_read", 849: "enter_write", 848: "exit_write", 847: "enter_pread64", 846: "exit_pread64", 845: "enter_pwrite64", 844: "exit_pwrite64", 843: "enter_readv", 842: "exit_readv", 841: "enter_writev", 840: "exit_writev", 839: "enter_preadv", 838: "exit_preadv", 837: "enter_preadv2", 836: "exit_preadv2", 835: "enter_pwritev", 834: "exit_pwritev", 833: "enter_pwritev2", 832: "exit_pwritev2", 831: "enter_sendfile64", 830: "exit_sendfile64", 829: "enter_copy_file_range", 828: "exit_copy_file_range", 827: "enter_truncate", 826: "exit_truncate", 825: "enter_ftruncate", 824: "exit_ftruncate", 823: "enter_fallocate", 822: "exit_fallocate", 821: "enter_faccessat", 820: "exit_faccessat", 819: "enter_faccessat2", 818: "exit_faccessat2", 817: "enter_access", 816: "exit_access", 815: "enter_chdir", 814: "exit_chdir", 813: "enter_fchdir", 812: "exit_fchdir", 811: "enter_chroot", 810: "exit_chroot", 809: "enter_fchmod", 808: "exit_fchmod", 807: "enter_fchmodat2", 806: "exit_fchmodat2", 805: "enter_fchmodat", 804: "exit_fchmodat", 803: "enter_chmod", 802: "exit_chmod", 801: "enter_fchownat", 800: "exit_fchownat", 799: "enter_chown", 798: "exit_chown", 797: "enter_lchown", 796: "exit_lchown", 795: "enter_fchown", 794: "exit_fchown", 793: "enter_open", 792: "exit_open", 791: "enter_openat", 790: "exit_openat", 789: "enter_openat2", 788: "exit_openat2", 787: "enter_creat", 786: "exit_creat", 785: "enter_close", 784: "exit_close", 783: "enter_vhangup", 782: "exit_vhangup", 781: "enter_memfd_create", 780: "exit_memfd_create", 774: "enter_memfd_secret", 773: "exit_memfd_secret", 754: "enter_move_pages", 753: "exit_move_pages", 743: "enter_set_mempolicy_home_node", 742: "exit_set_mempolicy_home_node", 741: "enter_mbind", 740: "exit_mbind", 739: "enter_set_mempolicy", 738: "exit_set_mempolicy", 737: "enter_migrate_pages", 736: "exit_migrate_pages", 735: "enter_get_mempolicy", 734: "exit_get_mempolicy", 733: "enter_swapoff", 732: "exit_swapoff", 731: "enter_swapon", 730: "exit_swapon", 729: "enter_madvise", 728: "exit_madvise", 727: "enter_process_madvise", 726: "exit_process_madvise", 725: "enter_mseal", 724: "exit_mseal", 723: "enter_process_vm_readv", 722: "exit_process_vm_readv", 721: "enter_process_vm_writev", 720: "exit_process_vm_writev", 712: "enter_msync", 711: "exit_msync", 710: "enter_mremap", 709: "exit_mremap", 708: "enter_mprotect", 707: "exit_mprotect", 706: "enter_pkey_mprotect", 705: "exit_pkey_mprotect", 704: "enter_pkey_alloc", 703: "exit_pkey_alloc", 702: "enter_pkey_free", 701: "exit_pkey_free", 698: "enter_brk", 697: "exit_brk", 696: "enter_munmap", 695: "exit_munmap", 694: "enter_remap_file_pages", 693: "exit_remap_file_pages", 692: "enter_mlock", 691: "exit_mlock", 690: "enter_mlock2", 689: "exit_mlock2", 688: "enter_munlock", 687: "exit_munlock", 686: "enter_mlockall", 685: "exit_mlockall", 684: "enter_munlockall", 683: "exit_munlockall", 682: "enter_mincore", 681: "exit_mincore", 616: "enter_readahead", 615: "exit_readahead", 614: "enter_fadvise64", 613: "exit_fadvise64", 604: "enter_process_mrelease", 603: "exit_process_mrelease", 595: "enter_cachestat", 594: "exit_cachestat", 591: "enter_rseq", 590: "exit_rseq", 587: "enter_perf_event_open", 586: "exit_perf_event_open", 585: "enter_bpf", 584: "exit_bpf", 526: "enter_seccomp", 525: "exit_seccomp", 508: "enter_kexec_file_load", 507: "exit_kexec_file_load", 506: "enter_kexec_load", 505: "exit_kexec_load", 504: "enter_acct", 503: "exit_acct", 499: "enter_set_robust_list", 498: "exit_set_robust_list", 497: "enter_get_robust_list", 496: "exit_get_robust_list", 495: "enter_futex", 494: "exit_futex", 493: "enter_futex_waitv", 492: "exit_futex_waitv", 491: "enter_futex_wake", 490: "exit_futex_wake", 489: "enter_futex_wait", 488: "exit_futex_wait", 487: "enter_futex_requeue", 486: "exit_futex_requeue", 471: "enter_getitimer", 470: "exit_getitimer", 469: "enter_alarm", 468: "exit_alarm", 467: "enter_setitimer", 466: "exit_setitimer", 465: "enter_timer_create", 464: "exit_timer_create", 463: "enter_timer_gettime", 462: "exit_timer_gettime", 461: "enter_timer_getoverrun", 460: "exit_timer_getoverrun", 459: "enter_timer_settime", 458: "exit_timer_settime", 457: "enter_timer_delete", 456: "exit_timer_delete", 455: "enter_clock_settime", 454: "exit_clock_settime", 453: "enter_clock_gettime", 452: "exit_clock_gettime", 451: "enter_clock_adjtime", 450: "exit_clock_adjtime", 449: "enter_clock_getres", 448: "exit_clock_getres", 447: "enter_clock_nanosleep", 446: "exit_clock_nanosleep", 441: "enter_nanosleep", 440: "exit_nanosleep", 425: "enter_time", 424: "exit_time", 423: "enter_gettimeofday", 422: "exit_gettimeofday", 421: "enter_settimeofday", 420: "exit_settimeofday", 419: "enter_adjtimex", 418: "exit_adjtimex", 417: "enter_kcmp", 416: "exit_kcmp", 410: "enter_delete_module", 409: "exit_delete_module", 408: "enter_init_module", 407: "exit_init_module", 406: "enter_finit_module", 405: "exit_finit_module", 350: "enter_syslog", 349: "exit_syslog", 346: "enter_membarrier", 345: "exit_membarrier", 341: "enter_sched_setscheduler", 340: "exit_sched_setscheduler", 339: "enter_sched_setparam", 338: "exit_sched_setparam", 337: "enter_sched_setattr", 336: "exit_sched_setattr", 335: "enter_sched_getscheduler", 334: "exit_sched_getscheduler", 333: "enter_sched_getparam", 332: "exit_sched_getparam", 331: "enter_sched_getattr", 330: "exit_sched_getattr", 329: "enter_sched_setaffinity", 328: "exit_sched_setaffinity", 327: "enter_sched_getaffinity", 326: "exit_sched_getaffinity", 325: "enter_sched_yield", 324: "exit_sched_yield", 323: "enter_sched_get_priority_max", 322: "exit_sched_get_priority_max", 321: "enter_sched_get_priority_min", 320: "exit_sched_get_priority_min", 319: "enter_sched_rr_get_interval", 318: "exit_sched_rr_get_interval", 286: "enter_getgroups", 285: "exit_getgroups", 284: "enter_setgroups", 283: "exit_setgroups", 282: "enter_reboot", 281: "exit_reboot", 277: "enter_listns", 276: "exit_listns", 275: "enter_setns", 274: "exit_setns", 273: "enter_pidfd_open", 272: "exit_pidfd_open", 271: "enter_pidfd_getfd", 270: "exit_pidfd_getfd", 265: "enter_setpriority", 264: "exit_setpriority", 263: "enter_getpriority", 262: "exit_getpriority", 261: "enter_setregid", 260: "exit_setregid", 259: "enter_setgid", 258: "exit_setgid", 257: "enter_setreuid", 256: "exit_setreuid", 255: "enter_setuid", 254: "exit_setuid", 253: "enter_setresuid", 252: "exit_setresuid", 251: "enter_getresuid", 250: "exit_getresuid", 249: "enter_setresgid", 248: "exit_setresgid", 247: "enter_getresgid", 246: "exit_getresgid", 245: "enter_setfsuid", 244: "exit_setfsuid", 243: "enter_setfsgid", 242: "exit_setfsgid", 241: "enter_getpid", 240: "exit_getpid", 239: "enter_gettid", 238: "exit_gettid", 237: "enter_getppid", 236: "exit_getppid", 235: "enter_getuid", 234: "exit_getuid", 233: "enter_geteuid", 232: "exit_geteuid", 231: "enter_getgid", 230: "exit_getgid", 229: "enter_getegid", 228: "exit_getegid", 227: "enter_times", 226: "exit_times", 225: "enter_setpgid", 224: "exit_setpgid", 223: "enter_getpgid", 222: "exit_getpgid", 221: "enter_getpgrp", 220: "exit_getpgrp", 219: "enter_getsid", 218: "exit_getsid", 217: "enter_setsid", 216: "exit_setsid", 215: "enter_newuname", 214: "exit_newuname", 213: "enter_sethostname", 212: "exit_sethostname", 211: "enter_setdomainname", 210: "exit_setdomainname", 209: "enter_getrlimit", 208: "exit_getrlimit", 207: "enter_prlimit64", 206: "exit_prlimit64", 205: "enter_setrlimit", 204: "exit_setrlimit", 203: "enter_getrusage", 202: "exit_getrusage", 201: "enter_umask", 200: "exit_umask", 199: "enter_prctl", 198: "exit_prctl", 197: "enter_getcpu", 196: "exit_getcpu", 195: "enter_sysinfo", 194: "exit_sysinfo", 191: "enter_restart_syscall", 190: "exit_restart_syscall", 189: "enter_rt_sigprocmask", 188: "exit_rt_sigprocmask", 187: "enter_rt_sigpending", 186: "exit_rt_sigpending", 185: "enter_rt_sigtimedwait", 184: "exit_rt_sigtimedwait", 183: "enter_kill", 182: "exit_kill", 181: "enter_pidfd_send_signal", 180: "exit_pidfd_send_signal", 179: "enter_tgkill", 178: "exit_tgkill", 177: "enter_tkill", 176: "exit_tkill", 175: "enter_rt_sigqueueinfo", 174: "exit_rt_sigqueueinfo", 173: "enter_rt_tgsigqueueinfo", 172: "exit_rt_tgsigqueueinfo", 171: "enter_sigaltstack", 170: "exit_sigaltstack", 169: "enter_rt_sigaction", 168: "exit_rt_sigaction", 167: "enter_pause", 166: "exit_pause", 165: "enter_rt_sigsuspend", 164: "exit_rt_sigsuspend", 163: "enter_ptrace", 162: "exit_ptrace", 161: "enter_capget", 160: "exit_capget", 159: "enter_capset", 158: "exit_capset", 150: "enter_exit", 148: "enter_exit_group", 146: "enter_waitid", 145: "exit_waitid", 144: "enter_wait4", 143: "exit_wait4", 139: "enter_personality", 138: "exit_personality", 134: "enter_set_tid_address", 133: "exit_set_tid_address", 132: "enter_fork", 131: "exit_fork", 130: "enter_vfork", 129: "exit_vfork", 128: "enter_clone", 127: "exit_clone", 126: "enter_clone3", 125: "exit_clone3", 124: "enter_unshare", 123: "exit_unshare", 119: "enter_map_shadow_stack", 118: "exit_map_shadow_stack", 117: "enter_uretprobe", 116: "exit_uretprobe", 115: "enter_uprobe", 114: "exit_uprobe", 102: "enter_arch_prctl", 101: "exit_arch_prctl", 100: "enter_mmap", 99: "exit_mmap", 98: "enter_modify_ldt", 97: "exit_modify_ldt", 95: "enter_ioperm", 94: "exit_ioperm", 93: "enter_iopl", 92: "exit_iopl", 57: "enter_rt_sigreturn", 56: "exit_rt_sigreturn",
}

var traceId2Name = map[TraceId]string{
	1847: "socket", 1846: "socket", 1845: "socketpair", 1844: "socketpair", 1843: "bind", 1842: "bind", 1841: "listen", 1840: "listen", 1839: "accept4", 1838: "accept4", 1837: "accept", 1836: "accept", 1835: "connect", 1834: "connect", 1833: "getsockname", 1832: "getsockname", 1831: "getpeername", 1830: "getpeername", 1829: "sendto", 1828: "sendto", 1827: "recvfrom", 1826: "recvfrom", 1825: "setsockopt", 1824: "setsockopt", 1823: "getsockopt", 1822: "getsockopt", 1821: "shutdown", 1820: "shutdown", 1819: "sendmsg", 1818: "sendmsg", 1817: "sendmmsg", 1816: "sendmmsg", 1815: "recvmsg", 1814: "recvmsg", 1813: "recvmmsg", 1812: "recvmmsg", 1575: "getrandom", 1574: "getrandom", 1528: "io_uring_register", 1527: "io_uring_register", 1509: "io_uring_enter", 1508: "io_uring_enter", 1507: "io_uring_setup", 1506: "io_uring_setup", 1491: "ioprio_set", 1490: "ioprio_set", 1489: "ioprio_get", 1488: "ioprio_get", 1463: "landlock_create_ruleset", 1462: "landlock_create_ruleset", 1461: "landlock_add_rule", 1460: "landlock_add_rule", 1459: "landlock_restrict_self", 1458: "landlock_restrict_self", 1456: "lsm_set_self_attr", 1455: "lsm_set_self_attr", 1454: "lsm_get_self_attr", 1453: "lsm_get_self_attr", 1452: "lsm_list_modules", 1451: "lsm_list_modules", 1449: "add_key", 1448: "add_key", 1447: "request_key", 1446: "request_key", 1445: "keyctl", 1444: "keyctl", 1443: "mq_open", 1442: "mq_open", 1441: "mq_unlink", 1440: "mq_unlink", 1439: "mq_timedsend", 1438: "mq_timedsend", 1437: "mq_timedreceive", 1436: "mq_timedreceive", 1435: "mq_notify", 1434: "mq_notify", 1433: "mq_getsetattr", 1432: "mq_getsetattr", 1431: "shmget", 1430: "shmget", 1429: "shmctl", 1428: "shmctl", 1427: "shmat", 1426: "shmat", 1425: "shmdt", 1424: "shmdt", 1423: "semget", 1422: "semget", 1421: "semctl", 1420: "semctl", 1419: "semtimedop", 1418: "semtimedop", 1417: "semop", 1416: "semop", 1415: "msgget", 1414: "msgget", 1413: "msgctl", 1412: "msgctl", 1411: "msgsnd", 1410: "msgsnd", 1409: "msgrcv", 1408: "msgrcv", 1164: "quotactl", 1163: "quotactl", 1162: "quotactl_fd", 1161: "quotactl_fd", 1146: "name_to_handle_at", 1145: "name_to_handle_at", 1144: "open_by_handle_at", 1143: "open_by_handle_at", 1130: "flock", 1129: "flock", 1111: "io_setup", 1110: "io_setup", 1109: "io_destroy", 1108: "io_destroy", 1107: "io_submit", 1106: "io_submit", 1105: "io_cancel", 1104: "io_cancel", 1103: "io_getevents", 1102: "io_getevents", 1101: "io_pgetevents", 1100: "io_pgetevents", 1099: "userfaultfd", 1098: "userfaultfd", 1097: "eventfd2", 1096: "eventfd2", 1095: "eventfd", 1094: "eventfd", 1093: "timerfd_create", 1092: "timerfd_create", 1091: "timerfd_settime", 1090: "timerfd_settime", 1089: "timerfd_gettime", 1088: "timerfd_gettime", 1087: "signalfd4", 1086: "signalfd4", 1085: "signalfd", 1084: "signalfd", 1083: "epoll_create1", 1082: "epoll_create1", 1081: "epoll_create", 1080: "epoll_create", 1079: "epoll_ctl", 1078: "epoll_ctl", 1077: "epoll_wait", 1076: "epoll_wait", 1075: "epoll_pwait", 1074: "epoll_pwait", 1073: "epoll_pwait2", 1072: "epoll_pwait2", 1071: "fanotify_init", 1070: "fanotify_init", 1069: "fanotify_mark", 1068: "fanotify_mark", 1067: "inotify_init1", 1066: "inotify_init1", 1065: "inotify_init", 1064: "inotify_init", 1063: "inotify_add_watch", 1062: "inotify_add_watch", 1061: "inotify_rm_watch", 1060: "inotify_rm_watch", 1059: "file_getattr", 1058: "file_getattr", 1057: "file_setattr", 1056: "file_setattr", 1055: "fsopen", 1054: "fsopen", 1053: "fspick", 1052: "fspick", 1051: "fsconfig", 1050: "fsconfig", 1049: "statfs", 1048: "statfs", 1047: "fstatfs", 1046: "fstatfs", 1045: "ustat", 1044: "ustat", 1043: "getcwd", 1042: "getcwd", 1041: "utimensat", 1040: "utimensat", 1039: "futimesat", 1038: "futimesat", 1037: "utimes", 1036: "utimes", 1035: "utime", 1034: "utime", 1033: "sync", 1032: "sync", 1031: "syncfs", 1030: "syncfs", 1029: "fsync", 1028: "fsync", 1027: "fdatasync", 1026: "fdatasync", 1025: "sync_file_range", 1024: "sync_file_range", 1023: "vmsplice", 1022: "vmsplice", 1021: "splice", 1020: "splice", 1019: "tee", 1018: "tee", 985: "setxattrat", 984: "setxattrat", 983: "setxattr", 982: "setxattr", 981: "lsetxattr", 980: "lsetxattr", 979: "fsetxattr", 978: "fsetxattr", 977: "getxattrat", 976: "getxattrat", 975: "getxattr", 974: "getxattr", 973: "lgetxattr", 972: "lgetxattr", 971: "fgetxattr", 970: "fgetxattr", 969: "listxattrat", 968: "listxattrat", 967: "listxattr", 966: "listxattr", 965: "llistxattr", 964: "llistxattr", 963: "flistxattr", 962: "flistxattr", 961: "removexattrat", 960: "removexattrat", 959: "removexattr", 958: "removexattr", 957: "lremovexattr", 956: "lremovexattr", 955: "fremovexattr", 954: "fremovexattr", 953: "umount", 952: "umount", 951: "open_tree", 950: "open_tree", 949: "mount", 948: "mount", 947: "fsmount", 946: "fsmount", 945: "move_mount", 944: "move_mount", 943: "pivot_root", 942: "pivot_root", 941: "mount_setattr", 940: "mount_setattr", 939: "open_tree_attr", 938: "open_tree_attr", 937: "statmount", 936: "statmount", 935: "listmount", 934: "listmount", 933: "sysfs", 932: "sysfs", 931: "close_range", 930: "close_range", 929: "dup3", 928: "dup3", 927: "dup2", 926: "dup2", 925: "dup", 924: "dup", 919: "select", 918: "select", 917: "pselect6", 916: "pselect6", 915: "poll", 914: "poll", 913: "ppoll", 912: "ppoll", 911: "getdents", 910: "getdents", 909: "getdents64", 908: "getdents64", 907: "ioctl", 906: "ioctl", 905: "fcntl", 904: "fcntl", 903: "mknodat", 902: "mknodat", 901: "mknod", 900: "mknod", 899: "mkdirat", 898: "mkdirat", 897: "mkdir", 896: "mkdir", 895: "rmdir", 894: "rmdir", 893: "unlinkat", 892: "unlinkat", 891: "unlink", 890: "unlink", 889: "symlinkat", 888: "symlinkat", 887: "symlink", 886: "symlink", 885: "linkat", 884: "linkat", 883: "link", 882: "link", 881: "renameat2", 880: "renameat2", 879: "renameat", 878: "renameat", 877: "rename", 876: "rename", 875: "pipe2", 874: "pipe2", 873: "pipe", 872: "pipe", 871: "execve", 870: "execve", 869: "execveat", 868: "execveat", 867: "newstat", 866: "newstat", 865: "newlstat", 864: "newlstat", 863: "newfstatat", 862: "newfstatat", 861: "newfstat", 860: "newfstat", 859: "readlinkat", 858: "readlinkat", 857: "readlink", 856: "readlink", 855: "statx", 854: "statx", 853: "lseek", 852: "lseek", 851: "read", 850: "read", 849: "write", 848: "write", 847: "pread64", 846: "pread64", 845: "pwrite64", 844: "pwrite64", 843: "readv", 842: "readv", 841: "writev", 840: "writev", 839: "preadv", 838: "preadv", 837: "preadv2", 836: "preadv2", 835: "pwritev", 834: "pwritev", 833: "pwritev2", 832: "pwritev2", 831: "sendfile64", 830: "sendfile64", 829: "copy_file_range", 828: "copy_file_range", 827: "truncate", 826: "truncate", 825: "ftruncate", 824: "ftruncate", 823: "fallocate", 822: "fallocate", 821: "faccessat", 820: "faccessat", 819: "faccessat2", 818: "faccessat2", 817: "access", 816: "access", 815: "chdir", 814: "chdir", 813: "fchdir", 812: "fchdir", 811: "chroot", 810: "chroot", 809: "fchmod", 808: "fchmod", 807: "fchmodat2", 806: "fchmodat2", 805: "fchmodat", 804: "fchmodat", 803: "chmod", 802: "chmod", 801: "fchownat", 800: "fchownat", 799: "chown", 798: "chown", 797: "lchown", 796: "lchown", 795: "fchown", 794: "fchown", 793: "open", 792: "open", 791: "openat", 790: "openat", 789: "openat2", 788: "openat2", 787: "creat", 786: "creat", 785: "close", 784: "close", 783: "vhangup", 782: "vhangup", 781: "memfd_create", 780: "memfd_create", 774: "memfd_secret", 773: "memfd_secret", 754: "move_pages", 753: "move_pages", 743: "set_mempolicy_home_node", 742: "set_mempolicy_home_node", 741: "mbind", 740: "mbind", 739: "set_mempolicy", 738: "set_mempolicy", 737: "migrate_pages", 736: "migrate_pages", 735: "get_mempolicy", 734: "get_mempolicy", 733: "swapoff", 732: "swapoff", 731: "swapon", 730: "swapon", 729: "madvise", 728: "madvise", 727: "process_madvise", 726: "process_madvise", 725: "mseal", 724: "mseal", 723: "process_vm_readv", 722: "process_vm_readv", 721: "process_vm_writev", 720: "process_vm_writev", 712: "msync", 711: "msync", 710: "mremap", 709: "mremap", 708: "mprotect", 707: "mprotect", 706: "pkey_mprotect", 705: "pkey_mprotect", 704: "pkey_alloc", 703: "pkey_alloc", 702: "pkey_free", 701: "pkey_free", 698: "brk", 697: "brk", 696: "munmap", 695: "munmap", 694: "remap_file_pages", 693: "remap_file_pages", 692: "mlock", 691: "mlock", 690: "mlock2", 689: "mlock2", 688: "munlock", 687: "munlock", 686: "mlockall", 685: "mlockall", 684: "munlockall", 683: "munlockall", 682: "mincore", 681: "mincore", 616: "readahead", 615: "readahead", 614: "fadvise64", 613: "fadvise64", 604: "process_mrelease", 603: "process_mrelease", 595: "cachestat", 594: "cachestat", 591: "rseq", 590: "rseq", 587: "perf_event_open", 586: "perf_event_open", 585: "bpf", 584: "bpf", 526: "seccomp", 525: "seccomp", 508: "kexec_file_load", 507: "kexec_file_load", 506: "kexec_load", 505: "kexec_load", 504: "acct", 503: "acct", 499: "set_robust_list", 498: "set_robust_list", 497: "get_robust_list", 496: "get_robust_list", 495: "futex", 494: "futex", 493: "futex_waitv", 492: "futex_waitv", 491: "futex_wake", 490: "futex_wake", 489: "futex_wait", 488: "futex_wait", 487: "futex_requeue", 486: "futex_requeue", 471: "getitimer", 470: "getitimer", 469: "alarm", 468: "alarm", 467: "setitimer", 466: "setitimer", 465: "timer_create", 464: "timer_create", 463: "timer_gettime", 462: "timer_gettime", 461: "timer_getoverrun", 460: "timer_getoverrun", 459: "timer_settime", 458: "timer_settime", 457: "timer_delete", 456: "timer_delete", 455: "clock_settime", 454: "clock_settime", 453: "clock_gettime", 452: "clock_gettime", 451: "clock_adjtime", 450: "clock_adjtime", 449: "clock_getres", 448: "clock_getres", 447: "clock_nanosleep", 446: "clock_nanosleep", 441: "nanosleep", 440: "nanosleep", 425: "time", 424: "time", 423: "gettimeofday", 422: "gettimeofday", 421: "settimeofday", 420: "settimeofday", 419: "adjtimex", 418: "adjtimex", 417: "kcmp", 416: "kcmp", 410: "delete_module", 409: "delete_module", 408: "init_module", 407: "init_module", 406: "finit_module", 405: "finit_module", 350: "syslog", 349: "syslog", 346: "membarrier", 345: "membarrier", 341: "sched_setscheduler", 340: "sched_setscheduler", 339: "sched_setparam", 338: "sched_setparam", 337: "sched_setattr", 336: "sched_setattr", 335: "sched_getscheduler", 334: "sched_getscheduler", 333: "sched_getparam", 332: "sched_getparam", 331: "sched_getattr", 330: "sched_getattr", 329: "sched_setaffinity", 328: "sched_setaffinity", 327: "sched_getaffinity", 326: "sched_getaffinity", 325: "sched_yield", 324: "sched_yield", 323: "sched_get_priority_max", 322: "sched_get_priority_max", 321: "sched_get_priority_min", 320: "sched_get_priority_min", 319: "sched_rr_get_interval", 318: "sched_rr_get_interval", 286: "getgroups", 285: "getgroups", 284: "setgroups", 283: "setgroups", 282: "reboot", 281: "reboot", 277: "listns", 276: "listns", 275: "setns", 274: "setns", 273: "pidfd_open", 272: "pidfd_open", 271: "pidfd_getfd", 270: "pidfd_getfd", 265: "setpriority", 264: "setpriority", 263: "getpriority", 262: "getpriority", 261: "setregid", 260: "setregid", 259: "setgid", 258: "setgid", 257: "setreuid", 256: "setreuid", 255: "setuid", 254: "setuid", 253: "setresuid", 252: "setresuid", 251: "getresuid", 250: "getresuid", 249: "setresgid", 248: "setresgid", 247: "getresgid", 246: "getresgid", 245: "setfsuid", 244: "setfsuid", 243: "setfsgid", 242: "setfsgid", 241: "getpid", 240: "getpid", 239: "gettid", 238: "gettid", 237: "getppid", 236: "getppid", 235: "getuid", 234: "getuid", 233: "geteuid", 232: "geteuid", 231: "getgid", 230: "getgid", 229: "getegid", 228: "getegid", 227: "times", 226: "times", 225: "setpgid", 224: "setpgid", 223: "getpgid", 222: "getpgid", 221: "getpgrp", 220: "getpgrp", 219: "getsid", 218: "getsid", 217: "setsid", 216: "setsid", 215: "newuname", 214: "newuname", 213: "sethostname", 212: "sethostname", 211: "setdomainname", 210: "setdomainname", 209: "getrlimit", 208: "getrlimit", 207: "prlimit64", 206: "prlimit64", 205: "setrlimit", 204: "setrlimit", 203: "getrusage", 202: "getrusage", 201: "umask", 200: "umask", 199: "prctl", 198: "prctl", 197: "getcpu", 196: "getcpu", 195: "sysinfo", 194: "sysinfo", 191: "restart_syscall", 190: "restart_syscall", 189: "rt_sigprocmask", 188: "rt_sigprocmask", 187: "rt_sigpending", 186: "rt_sigpending", 185: "rt_sigtimedwait", 184: "rt_sigtimedwait", 183: "kill", 182: "kill", 181: "pidfd_send_signal", 180: "pidfd_send_signal", 179: "tgkill", 178: "tgkill", 177: "tkill", 176: "tkill", 175: "rt_sigqueueinfo", 174: "rt_sigqueueinfo", 173: "rt_tgsigqueueinfo", 172: "rt_tgsigqueueinfo", 171: "sigaltstack", 170: "sigaltstack", 169: "rt_sigaction", 168: "rt_sigaction", 167: "pause", 166: "pause", 165: "rt_sigsuspend", 164: "rt_sigsuspend", 163: "ptrace", 162: "ptrace", 161: "capget", 160: "capget", 159: "capset", 158: "capset", 150: "exit", 148: "exit_group", 146: "waitid", 145: "waitid", 144: "wait4", 143: "wait4", 139: "personality", 138: "personality", 134: "set_tid_address", 133: "set_tid_address", 132: "fork", 131: "fork", 130: "vfork", 129: "vfork", 128: "clone", 127: "clone", 126: "clone3", 125: "clone3", 124: "unshare", 123: "unshare", 119: "map_shadow_stack", 118: "map_shadow_stack", 117: "uretprobe", 116: "uretprobe", 115: "uprobe", 114: "uprobe", 102: "arch_prctl", 101: "arch_prctl", 100: "mmap", 99: "mmap", 98: "modify_ldt", 97: "modify_ldt", 95: "ioperm", 94: "ioperm", 93: "iopl", 92: "iopl", 57: "rt_sigreturn", 56: "rt_sigreturn",
}

var traceId2Family = map[TraceId]SyscallFamily{
	1847: FamilyNetwork, 1846: FamilyNetwork, 1845: FamilyNetwork, 1844: FamilyNetwork, 1843: FamilyNetwork, 1842: FamilyNetwork, 1841: FamilyNetwork, 1840: FamilyNetwork, 1839: FamilyNetwork, 1838: FamilyNetwork, 1837: FamilyNetwork, 1836: FamilyNetwork, 1835: FamilyNetwork, 1834: FamilyNetwork, 1833: FamilyNetwork, 1832: FamilyNetwork, 1831: FamilyNetwork, 1830: FamilyNetwork, 1829: FamilyNetwork, 1828: FamilyNetwork, 1827: FamilyNetwork, 1826: FamilyNetwork, 1825: FamilyNetwork, 1824: FamilyNetwork, 1823: FamilyNetwork, 1822: FamilyNetwork, 1821: FamilyNetwork, 1820: FamilyNetwork, 1819: FamilyNetwork, 1818: FamilyNetwork, 1817: FamilyNetwork, 1816: FamilyNetwork, 1815: FamilyNetwork, 1814: FamilyNetwork, 1813: FamilyNetwork, 1812: FamilyNetwork, 1575: FamilySecurity, 1574: FamilySecurity, 1528: FamilyAIO, 1527: FamilyAIO, 1509: FamilyAIO, 1508: FamilyAIO, 1507: FamilyAIO, 1506: FamilyAIO, 1491: FamilyMisc, 1490: FamilyMisc, 1489: FamilyMisc, 1488: FamilyMisc, 1463: FamilySecurity, 1462: FamilySecurity, 1461: FamilySecurity, 1460: FamilySecurity, 1459: FamilySecurity, 1458: FamilySecurity, 1456: FamilySecurity, 1455: FamilySecurity, 1454: FamilySecurity, 1453: FamilySecurity, 1452: FamilySecurity, 1451: FamilySecurity, 1449: FamilySecurity, 1448: FamilySecurity, 1447: FamilySecurity, 1446: FamilySecurity, 1445: FamilySecurity, 1444: FamilySecurity, 1443: FamilyIPC, 1442: FamilyIPC, 1441: FamilyIPC, 1440: FamilyIPC, 1439: FamilyIPC, 1438: FamilyIPC, 1437: FamilyIPC, 1436: FamilyIPC, 1435: FamilyIPC, 1434: FamilyIPC, 1433: FamilyIPC, 1432: FamilyIPC, 1431: FamilyIPC, 1430: FamilyIPC, 1429: FamilyIPC, 1428: FamilyIPC, 1427: FamilyIPC, 1426: FamilyIPC, 1425: FamilyIPC, 1424: FamilyIPC, 1423: FamilyIPC, 1422: FamilyIPC, 1421: FamilyIPC, 1420: FamilyIPC, 1419: FamilyIPC, 1418: FamilyIPC, 1417: FamilyIPC, 1416: FamilyIPC, 1415: FamilyIPC, 1414: FamilyIPC, 1413: FamilyIPC, 1412: FamilyIPC, 1411: FamilyIPC, 1410: FamilyIPC, 1409: FamilyIPC, 1408: FamilyIPC, 1164: FamilyFS, 1163: FamilyFS, 1162: FamilyFS, 1161: FamilyFS, 1146: FamilyFS, 1145: FamilyFS, 1144: FamilyFS, 1143: FamilyFS, 1130: FamilyFS, 1129: FamilyFS, 1111: FamilyAIO, 1110: FamilyAIO, 1109: FamilyAIO, 1108: FamilyAIO, 1107: FamilyAIO, 1106: FamilyAIO, 1105: FamilyAIO, 1104: FamilyAIO, 1103: FamilyAIO, 1102: FamilyAIO, 1101: FamilyAIO, 1100: FamilyAIO, 1099: FamilyIPC, 1098: FamilyIPC, 1097: FamilyIPC, 1096: FamilyIPC, 1095: FamilyIPC, 1094: FamilyIPC, 1093: FamilyIPC, 1092: FamilyIPC, 1091: FamilyIPC, 1090: FamilyIPC, 1089: FamilyIPC, 1088: FamilyIPC, 1087: FamilyIPC, 1086: FamilyIPC, 1085: FamilyIPC, 1084: FamilyIPC, 1083: FamilyPolling, 1082: FamilyPolling, 1081: FamilyPolling, 1080: FamilyPolling, 1079: FamilyPolling, 1078: FamilyPolling, 1077: FamilyPolling, 1076: FamilyPolling, 1075: FamilyPolling, 1074: FamilyPolling, 1073: FamilyPolling, 1072: FamilyPolling, 1071: FamilyMisc, 1070: FamilyMisc, 1069: FamilyMisc, 1068: FamilyMisc, 1067: FamilyIPC, 1066: FamilyIPC, 1065: FamilyIPC, 1064: FamilyIPC, 1063: FamilyIPC, 1062: FamilyIPC, 1061: FamilyIPC, 1060: FamilyIPC, 1059: FamilyMisc, 1058: FamilyMisc, 1057: FamilyMisc, 1056: FamilyMisc, 1055: FamilyFS, 1054: FamilyFS, 1053: FamilyFS, 1052: FamilyFS, 1051: FamilyFS, 1050: FamilyFS, 1049: FamilyFS, 1048: FamilyFS, 1047: FamilyFS, 1046: FamilyFS, 1045: FamilyFS, 1044: FamilyFS, 1043: FamilyFS, 1042: FamilyFS, 1041: FamilyFS, 1040: FamilyFS, 1039: FamilyFS, 1038: FamilyFS, 1037: FamilyFS, 1036: FamilyFS, 1035: FamilyFS, 1034: FamilyFS, 1033: FamilyFS, 1032: FamilyFS, 1031: FamilyFS, 1030: FamilyFS, 1029: FamilyFS, 1028: FamilyFS, 1027: FamilyFS, 1026: FamilyFS, 1025: FamilyFS, 1024: FamilyFS, 1023: FamilyMisc, 1022: FamilyMisc, 1021: FamilyNetwork, 1020: FamilyNetwork, 1019: FamilyNetwork, 1018: FamilyNetwork, 985: FamilyFS, 984: FamilyFS, 983: FamilyFS, 982: FamilyFS, 981: FamilyFS, 980: FamilyFS, 979: FamilyFS, 978: FamilyFS, 977: FamilyFS, 976: FamilyFS, 975: FamilyFS, 974: FamilyFS, 973: FamilyFS, 972: FamilyFS, 971: FamilyFS, 970: FamilyFS, 969: FamilyFS, 968: FamilyFS, 967: FamilyFS, 966: FamilyFS, 965: FamilyFS, 964: FamilyFS, 963: FamilyFS, 962: FamilyFS, 961: FamilyFS, 960: FamilyFS, 959: FamilyFS, 958: FamilyFS, 957: FamilyFS, 956: FamilyFS, 955: FamilyFS, 954: FamilyFS, 953: FamilyFS, 952: FamilyFS, 951: FamilyFS, 950: FamilyFS, 949: FamilyFS, 948: FamilyFS, 947: FamilyFS, 946: FamilyFS, 945: FamilyFS, 944: FamilyFS, 943: FamilyProcess, 942: FamilyProcess, 941: FamilyFS, 940: FamilyFS, 939: FamilyFS, 938: FamilyFS, 937: FamilyFS, 936: FamilyFS, 935: FamilyFS, 934: FamilyFS, 933: FamilyMisc, 932: FamilyMisc, 931: FamilyFS, 930: FamilyFS, 929: FamilyFS, 928: FamilyFS, 927: FamilyFS, 926: FamilyFS, 925: FamilyFS, 924: FamilyFS, 919: FamilyPolling, 918: FamilyPolling, 917: FamilyPolling, 916: FamilyPolling, 915: FamilyPolling, 914: FamilyPolling, 913: FamilyPolling, 912: FamilyPolling, 911: FamilyFS, 910: FamilyFS, 909: FamilyFS, 908: FamilyFS, 907: FamilyFS, 906: FamilyFS, 905: FamilyFS, 904: FamilyFS, 903: FamilyFS, 902: FamilyFS, 901: FamilyFS, 900: FamilyFS, 899: FamilyFS, 898: FamilyFS, 897: FamilyFS, 896: FamilyFS, 895: FamilyFS, 894: FamilyFS, 893: FamilyFS, 892: FamilyFS, 891: FamilyFS, 890: FamilyFS, 889: FamilyFS, 888: FamilyFS, 887: FamilyFS, 886: FamilyFS, 885: FamilyFS, 884: FamilyFS, 883: FamilyFS, 882: FamilyFS, 881: FamilyFS, 880: FamilyFS, 879: FamilyFS, 878: FamilyFS, 877: FamilyFS, 876: FamilyFS, 875: FamilyIPC, 874: FamilyIPC, 873: FamilyIPC, 872: FamilyIPC, 871: FamilyProcess, 870: FamilyProcess, 869: FamilyProcess, 868: FamilyProcess, 867: FamilyFS, 866: FamilyFS, 865: FamilyFS, 864: FamilyFS, 863: FamilyFS, 862: FamilyFS, 861: FamilyFS, 860: FamilyFS, 859: FamilyFS, 858: FamilyFS, 857: FamilyFS, 856: FamilyFS, 855: FamilyFS, 854: FamilyFS, 853: FamilyFS, 852: FamilyFS, 851: FamilyFS, 850: FamilyFS, 849: FamilyFS, 848: FamilyFS, 847: FamilyFS, 846: FamilyFS, 845: FamilyFS, 844: FamilyFS, 843: FamilyFS, 842: FamilyFS, 841: FamilyFS, 840: FamilyFS, 839: FamilyFS, 838: FamilyFS, 837: FamilyFS, 836: FamilyFS, 835: FamilyFS, 834: FamilyFS, 833: FamilyFS, 832: FamilyFS, 831: FamilyNetwork, 830: FamilyNetwork, 829: FamilyFS, 828: FamilyFS, 827: FamilyFS, 826: FamilyFS, 825: FamilyFS, 824: FamilyFS, 823: FamilyFS, 822: FamilyFS, 821: FamilyFS, 820: FamilyFS, 819: FamilyFS, 818: FamilyFS, 817: FamilyFS, 816: FamilyFS, 815: FamilyFS, 814: FamilyFS, 813: FamilyFS, 812: FamilyFS, 811: FamilyFS, 810: FamilyFS, 809: FamilyFS, 808: FamilyFS, 807: FamilyFS, 806: FamilyFS, 805: FamilyFS, 804: FamilyFS, 803: FamilyFS, 802: FamilyFS, 801: FamilyFS, 800: FamilyFS, 799: FamilyFS, 798: FamilyFS, 797: FamilyFS, 796: FamilyFS, 795: FamilyFS, 794: FamilyFS, 793: FamilyFS, 792: FamilyFS, 791: FamilyFS, 790: FamilyFS, 789: FamilyFS, 788: FamilyFS, 787: FamilyFS, 786: FamilyFS, 785: FamilyFS, 784: FamilyFS, 783: FamilyProcess, 782: FamilyProcess, 781: FamilyIPC, 780: FamilyIPC, 774: FamilyIPC, 773: FamilyIPC, 754: FamilyMemory, 753: FamilyMemory, 743: FamilyMemory, 742: FamilyMemory, 741: FamilyMemory, 740: FamilyMemory, 739: FamilyMemory, 738: FamilyMemory, 737: FamilyMemory, 736: FamilyMemory, 735: FamilySecurity, 734: FamilySecurity, 733: FamilyFS, 732: FamilyFS, 731: FamilyFS, 730: FamilyFS, 729: FamilyMemory, 728: FamilyMemory, 727: FamilyMemory, 726: FamilyMemory, 725: FamilyMemory, 724: FamilyMemory, 723: FamilyMemory, 722: FamilyMemory, 721: FamilyMemory, 720: FamilyMemory, 712: FamilyFS, 711: FamilyFS, 710: FamilyMemory, 709: FamilyMemory, 708: FamilyMemory, 707: FamilyMemory, 706: FamilyMemory, 705: FamilyMemory, 704: FamilyMemory, 703: FamilyMemory, 702: FamilyMemory, 701: FamilyMemory, 698: FamilyMemory, 697: FamilyMemory, 696: FamilyMemory, 695: FamilyMemory, 694: FamilyMemory, 693: FamilyMemory, 692: FamilyMemory, 691: FamilyMemory, 690: FamilyMemory, 689: FamilyMemory, 688: FamilyMemory, 687: FamilyMemory, 686: FamilyMemory, 685: FamilyMemory, 684: FamilyMemory, 683: FamilyMemory, 682: FamilyMemory, 681: FamilyMemory, 616: FamilyFS, 615: FamilyFS, 614: FamilyFS, 613: FamilyFS, 604: FamilyMemory, 603: FamilyMemory, 595: FamilyFS, 594: FamilyFS, 591: FamilyMisc, 590: FamilyMisc, 587: FamilySecurity, 586: FamilySecurity, 585: FamilySecurity, 584: FamilySecurity, 526: FamilySecurity, 525: FamilySecurity, 508: FamilySecurity, 507: FamilySecurity, 506: FamilyMisc, 505: FamilyMisc, 504: FamilyMisc, 503: FamilyMisc, 499: FamilyMisc, 498: FamilyMisc, 497: FamilyMisc, 496: FamilyMisc, 495: FamilyIPC, 494: FamilyIPC, 493: FamilyIPC, 492: FamilyIPC, 491: FamilyIPC, 490: FamilyIPC, 489: FamilyIPC, 488: FamilyIPC, 487: FamilyIPC, 486: FamilyIPC, 471: FamilyTime, 470: FamilyTime, 469: FamilyMisc, 468: FamilyMisc, 467: FamilyTime, 466: FamilyTime, 465: FamilyTime, 464: FamilyTime, 463: FamilyTime, 462: FamilyTime, 461: FamilyTime, 460: FamilyTime, 459: FamilyTime, 458: FamilyTime, 457: FamilyTime, 456: FamilyTime, 455: FamilyTime, 454: FamilyTime, 453: FamilyTime, 452: FamilyTime, 451: FamilyTime, 450: FamilyTime, 449: FamilyTime, 448: FamilyTime, 447: FamilyTime, 446: FamilyTime, 441: FamilyTime, 440: FamilyTime, 425: FamilyTime, 424: FamilyTime, 423: FamilyTime, 422: FamilyTime, 421: FamilyTime, 420: FamilyTime, 419: FamilyMisc, 418: FamilyMisc, 417: FamilyProcess, 416: FamilyProcess, 410: FamilySecurity, 409: FamilySecurity, 408: FamilySecurity, 407: FamilySecurity, 406: FamilySecurity, 405: FamilySecurity, 350: FamilyMisc, 349: FamilyMisc, 346: FamilyMemory, 345: FamilyMemory, 341: FamilySched, 340: FamilySched, 339: FamilySched, 338: FamilySched, 337: FamilySched, 336: FamilySched, 335: FamilySched, 334: FamilySched, 333: FamilySched, 332: FamilySched, 331: FamilySched, 330: FamilySched, 329: FamilySched, 328: FamilySched, 327: FamilySched, 326: FamilySched, 325: FamilySched, 324: FamilySched, 323: FamilySched, 322: FamilySched, 321: FamilySched, 320: FamilySched, 319: FamilySched, 318: FamilySched, 286: FamilyProcess, 285: FamilyProcess, 284: FamilyProcess, 283: FamilyProcess, 282: FamilyProcess, 281: FamilyProcess, 277: FamilyFS, 276: FamilyFS, 275: FamilyProcess, 274: FamilyProcess, 273: FamilyIPC, 272: FamilyIPC, 271: FamilyIPC, 270: FamilyIPC, 265: FamilyProcess, 264: FamilyProcess, 263: FamilyProcess, 262: FamilyProcess, 261: FamilyProcess, 260: FamilyProcess, 259: FamilyProcess, 258: FamilyProcess, 257: FamilyProcess, 256: FamilyProcess, 255: FamilyProcess, 254: FamilyProcess, 253: FamilyProcess, 252: FamilyProcess, 251: FamilyProcess, 250: FamilyProcess, 249: FamilyProcess, 248: FamilyProcess, 247: FamilyProcess, 246: FamilyProcess, 245: FamilyProcess, 244: FamilyProcess, 243: FamilyProcess, 242: FamilyProcess, 241: FamilyProcess, 240: FamilyProcess, 239: FamilyProcess, 238: FamilyProcess, 237: FamilyProcess, 236: FamilyProcess, 235: FamilyProcess, 234: FamilyProcess, 233: FamilyProcess, 232: FamilyProcess, 231: FamilyProcess, 230: FamilyProcess, 229: FamilyProcess, 228: FamilyProcess, 227: FamilyTime, 226: FamilyTime, 225: FamilyProcess, 224: FamilyProcess, 223: FamilyProcess, 222: FamilyProcess, 221: FamilyProcess, 220: FamilyProcess, 219: FamilyProcess, 218: FamilyProcess, 217: FamilyProcess, 216: FamilyProcess, 215: FamilyMisc, 214: FamilyMisc, 213: FamilyMisc, 212: FamilyMisc, 211: FamilyMisc, 210: FamilyMisc, 209: FamilyProcess, 208: FamilyProcess, 207: FamilyProcess, 206: FamilyProcess, 205: FamilyProcess, 204: FamilyProcess, 203: FamilyProcess, 202: FamilyProcess, 201: FamilyProcess, 200: FamilyProcess, 199: FamilyProcess, 198: FamilyProcess, 197: FamilyMisc, 196: FamilyMisc, 195: FamilyMisc, 194: FamilyMisc, 191: FamilyProcess, 190: FamilyProcess, 189: FamilySignals, 188: FamilySignals, 187: FamilySignals, 186: FamilySignals, 185: FamilySignals, 184: FamilySignals, 183: FamilySignals, 182: FamilySignals, 181: FamilyIPC, 180: FamilyIPC, 179: FamilySignals, 178: FamilySignals, 177: FamilySignals, 176: FamilySignals, 175: FamilySignals, 174: FamilySignals, 173: FamilySignals, 172: FamilySignals, 171: FamilySignals, 170: FamilySignals, 169: FamilySignals, 168: FamilySignals, 167: FamilySignals, 166: FamilySignals, 165: FamilySignals, 164: FamilySignals, 163: FamilySecurity, 162: FamilySecurity, 161: FamilySecurity, 160: FamilySecurity, 159: FamilySecurity, 158: FamilySecurity, 150: FamilyProcess, 148: FamilyProcess, 146: FamilyProcess, 145: FamilyProcess, 144: FamilyProcess, 143: FamilyProcess, 139: FamilyProcess, 138: FamilyProcess, 134: FamilyProcess, 133: FamilyProcess, 132: FamilyProcess, 131: FamilyProcess, 130: FamilyProcess, 129: FamilyProcess, 128: FamilyProcess, 127: FamilyProcess, 126: FamilyProcess, 125: FamilyProcess, 124: FamilyProcess, 123: FamilyProcess, 119: FamilyMemory, 118: FamilyMemory, 117: FamilyMisc, 116: FamilyMisc, 115: FamilyMisc, 114: FamilyMisc, 102: FamilyProcess, 101: FamilyProcess, 100: FamilyMemory, 99: FamilyMemory, 98: FamilyMisc, 97: FamilyMisc, 95: FamilyMisc, 94: FamilyMisc, 93: FamilyMisc, 92: FamilyMisc, 57: FamilySignals, 56: FamilySignals,
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
const UNCLASSIFIED = 0
const READ_CLASSIFIED = 1
const WRITE_CLASSIFIED = 2
const TRANSFER_CLASSIFIED = 3
const SYS_ENTER_SOCKET TraceId = 1847
const SYS_EXIT_SOCKET TraceId = 1846
const SYS_ENTER_SOCKETPAIR TraceId = 1845
const SYS_EXIT_SOCKETPAIR TraceId = 1844
const SYS_ENTER_BIND TraceId = 1843
const SYS_EXIT_BIND TraceId = 1842
const SYS_ENTER_LISTEN TraceId = 1841
const SYS_EXIT_LISTEN TraceId = 1840
const SYS_ENTER_ACCEPT4 TraceId = 1839
const SYS_EXIT_ACCEPT4 TraceId = 1838
const SYS_ENTER_ACCEPT TraceId = 1837
const SYS_EXIT_ACCEPT TraceId = 1836
const SYS_ENTER_CONNECT TraceId = 1835
const SYS_EXIT_CONNECT TraceId = 1834
const SYS_ENTER_GETSOCKNAME TraceId = 1833
const SYS_EXIT_GETSOCKNAME TraceId = 1832
const SYS_ENTER_GETPEERNAME TraceId = 1831
const SYS_EXIT_GETPEERNAME TraceId = 1830
const SYS_ENTER_SENDTO TraceId = 1829
const SYS_EXIT_SENDTO TraceId = 1828
const SYS_ENTER_RECVFROM TraceId = 1827
const SYS_EXIT_RECVFROM TraceId = 1826
const SYS_ENTER_SETSOCKOPT TraceId = 1825
const SYS_EXIT_SETSOCKOPT TraceId = 1824
const SYS_ENTER_GETSOCKOPT TraceId = 1823
const SYS_EXIT_GETSOCKOPT TraceId = 1822
const SYS_ENTER_SHUTDOWN TraceId = 1821
const SYS_EXIT_SHUTDOWN TraceId = 1820
const SYS_ENTER_SENDMSG TraceId = 1819
const SYS_EXIT_SENDMSG TraceId = 1818
const SYS_ENTER_SENDMMSG TraceId = 1817
const SYS_EXIT_SENDMMSG TraceId = 1816
const SYS_ENTER_RECVMSG TraceId = 1815
const SYS_EXIT_RECVMSG TraceId = 1814
const SYS_ENTER_RECVMMSG TraceId = 1813
const SYS_EXIT_RECVMMSG TraceId = 1812
const SYS_ENTER_GETRANDOM TraceId = 1575
const SYS_EXIT_GETRANDOM TraceId = 1574
const SYS_ENTER_IO_URING_REGISTER TraceId = 1528
const SYS_EXIT_IO_URING_REGISTER TraceId = 1527
const SYS_ENTER_IO_URING_ENTER TraceId = 1509
const SYS_EXIT_IO_URING_ENTER TraceId = 1508
const SYS_ENTER_IO_URING_SETUP TraceId = 1507
const SYS_EXIT_IO_URING_SETUP TraceId = 1506
const SYS_ENTER_IOPRIO_SET TraceId = 1491
const SYS_EXIT_IOPRIO_SET TraceId = 1490
const SYS_ENTER_IOPRIO_GET TraceId = 1489
const SYS_EXIT_IOPRIO_GET TraceId = 1488
const SYS_ENTER_LANDLOCK_CREATE_RULESET TraceId = 1463
const SYS_EXIT_LANDLOCK_CREATE_RULESET TraceId = 1462
const SYS_ENTER_LANDLOCK_ADD_RULE TraceId = 1461
const SYS_EXIT_LANDLOCK_ADD_RULE TraceId = 1460
const SYS_ENTER_LANDLOCK_RESTRICT_SELF TraceId = 1459
const SYS_EXIT_LANDLOCK_RESTRICT_SELF TraceId = 1458
const SYS_ENTER_LSM_SET_SELF_ATTR TraceId = 1456
const SYS_EXIT_LSM_SET_SELF_ATTR TraceId = 1455
const SYS_ENTER_LSM_GET_SELF_ATTR TraceId = 1454
const SYS_EXIT_LSM_GET_SELF_ATTR TraceId = 1453
const SYS_ENTER_LSM_LIST_MODULES TraceId = 1452
const SYS_EXIT_LSM_LIST_MODULES TraceId = 1451
const SYS_ENTER_ADD_KEY TraceId = 1449
const SYS_EXIT_ADD_KEY TraceId = 1448
const SYS_ENTER_REQUEST_KEY TraceId = 1447
const SYS_EXIT_REQUEST_KEY TraceId = 1446
const SYS_ENTER_KEYCTL TraceId = 1445
const SYS_EXIT_KEYCTL TraceId = 1444
const SYS_ENTER_MQ_OPEN TraceId = 1443
const SYS_EXIT_MQ_OPEN TraceId = 1442
const SYS_ENTER_MQ_UNLINK TraceId = 1441
const SYS_EXIT_MQ_UNLINK TraceId = 1440
const SYS_ENTER_MQ_TIMEDSEND TraceId = 1439
const SYS_EXIT_MQ_TIMEDSEND TraceId = 1438
const SYS_ENTER_MQ_TIMEDRECEIVE TraceId = 1437
const SYS_EXIT_MQ_TIMEDRECEIVE TraceId = 1436
const SYS_ENTER_MQ_NOTIFY TraceId = 1435
const SYS_EXIT_MQ_NOTIFY TraceId = 1434
const SYS_ENTER_MQ_GETSETATTR TraceId = 1433
const SYS_EXIT_MQ_GETSETATTR TraceId = 1432
const SYS_ENTER_SHMGET TraceId = 1431
const SYS_EXIT_SHMGET TraceId = 1430
const SYS_ENTER_SHMCTL TraceId = 1429
const SYS_EXIT_SHMCTL TraceId = 1428
const SYS_ENTER_SHMAT TraceId = 1427
const SYS_EXIT_SHMAT TraceId = 1426
const SYS_ENTER_SHMDT TraceId = 1425
const SYS_EXIT_SHMDT TraceId = 1424
const SYS_ENTER_SEMGET TraceId = 1423
const SYS_EXIT_SEMGET TraceId = 1422
const SYS_ENTER_SEMCTL TraceId = 1421
const SYS_EXIT_SEMCTL TraceId = 1420
const SYS_ENTER_SEMTIMEDOP TraceId = 1419
const SYS_EXIT_SEMTIMEDOP TraceId = 1418
const SYS_ENTER_SEMOP TraceId = 1417
const SYS_EXIT_SEMOP TraceId = 1416
const SYS_ENTER_MSGGET TraceId = 1415
const SYS_EXIT_MSGGET TraceId = 1414
const SYS_ENTER_MSGCTL TraceId = 1413
const SYS_EXIT_MSGCTL TraceId = 1412
const SYS_ENTER_MSGSND TraceId = 1411
const SYS_EXIT_MSGSND TraceId = 1410
const SYS_ENTER_MSGRCV TraceId = 1409
const SYS_EXIT_MSGRCV TraceId = 1408
const SYS_ENTER_QUOTACTL TraceId = 1164
const SYS_EXIT_QUOTACTL TraceId = 1163
const SYS_ENTER_QUOTACTL_FD TraceId = 1162
const SYS_EXIT_QUOTACTL_FD TraceId = 1161
const SYS_ENTER_NAME_TO_HANDLE_AT TraceId = 1146
const SYS_EXIT_NAME_TO_HANDLE_AT TraceId = 1145
const SYS_ENTER_OPEN_BY_HANDLE_AT TraceId = 1144
const SYS_EXIT_OPEN_BY_HANDLE_AT TraceId = 1143
const SYS_ENTER_FLOCK TraceId = 1130
const SYS_EXIT_FLOCK TraceId = 1129
const SYS_ENTER_IO_SETUP TraceId = 1111
const SYS_EXIT_IO_SETUP TraceId = 1110
const SYS_ENTER_IO_DESTROY TraceId = 1109
const SYS_EXIT_IO_DESTROY TraceId = 1108
const SYS_ENTER_IO_SUBMIT TraceId = 1107
const SYS_EXIT_IO_SUBMIT TraceId = 1106
const SYS_ENTER_IO_CANCEL TraceId = 1105
const SYS_EXIT_IO_CANCEL TraceId = 1104
const SYS_ENTER_IO_GETEVENTS TraceId = 1103
const SYS_EXIT_IO_GETEVENTS TraceId = 1102
const SYS_ENTER_IO_PGETEVENTS TraceId = 1101
const SYS_EXIT_IO_PGETEVENTS TraceId = 1100
const SYS_ENTER_USERFAULTFD TraceId = 1099
const SYS_EXIT_USERFAULTFD TraceId = 1098
const SYS_ENTER_EVENTFD2 TraceId = 1097
const SYS_EXIT_EVENTFD2 TraceId = 1096
const SYS_ENTER_EVENTFD TraceId = 1095
const SYS_EXIT_EVENTFD TraceId = 1094
const SYS_ENTER_TIMERFD_CREATE TraceId = 1093
const SYS_EXIT_TIMERFD_CREATE TraceId = 1092
const SYS_ENTER_TIMERFD_SETTIME TraceId = 1091
const SYS_EXIT_TIMERFD_SETTIME TraceId = 1090
const SYS_ENTER_TIMERFD_GETTIME TraceId = 1089
const SYS_EXIT_TIMERFD_GETTIME TraceId = 1088
const SYS_ENTER_SIGNALFD4 TraceId = 1087
const SYS_EXIT_SIGNALFD4 TraceId = 1086
const SYS_ENTER_SIGNALFD TraceId = 1085
const SYS_EXIT_SIGNALFD TraceId = 1084
const SYS_ENTER_EPOLL_CREATE1 TraceId = 1083
const SYS_EXIT_EPOLL_CREATE1 TraceId = 1082
const SYS_ENTER_EPOLL_CREATE TraceId = 1081
const SYS_EXIT_EPOLL_CREATE TraceId = 1080
const SYS_ENTER_EPOLL_CTL TraceId = 1079
const SYS_EXIT_EPOLL_CTL TraceId = 1078
const SYS_ENTER_EPOLL_WAIT TraceId = 1077
const SYS_EXIT_EPOLL_WAIT TraceId = 1076
const SYS_ENTER_EPOLL_PWAIT TraceId = 1075
const SYS_EXIT_EPOLL_PWAIT TraceId = 1074
const SYS_ENTER_EPOLL_PWAIT2 TraceId = 1073
const SYS_EXIT_EPOLL_PWAIT2 TraceId = 1072
const SYS_ENTER_FANOTIFY_INIT TraceId = 1071
const SYS_EXIT_FANOTIFY_INIT TraceId = 1070
const SYS_ENTER_FANOTIFY_MARK TraceId = 1069
const SYS_EXIT_FANOTIFY_MARK TraceId = 1068
const SYS_ENTER_INOTIFY_INIT1 TraceId = 1067
const SYS_EXIT_INOTIFY_INIT1 TraceId = 1066
const SYS_ENTER_INOTIFY_INIT TraceId = 1065
const SYS_EXIT_INOTIFY_INIT TraceId = 1064
const SYS_ENTER_INOTIFY_ADD_WATCH TraceId = 1063
const SYS_EXIT_INOTIFY_ADD_WATCH TraceId = 1062
const SYS_ENTER_INOTIFY_RM_WATCH TraceId = 1061
const SYS_EXIT_INOTIFY_RM_WATCH TraceId = 1060
const SYS_ENTER_FILE_GETATTR TraceId = 1059
const SYS_EXIT_FILE_GETATTR TraceId = 1058
const SYS_ENTER_FILE_SETATTR TraceId = 1057
const SYS_EXIT_FILE_SETATTR TraceId = 1056
const SYS_ENTER_FSOPEN TraceId = 1055
const SYS_EXIT_FSOPEN TraceId = 1054
const SYS_ENTER_FSPICK TraceId = 1053
const SYS_EXIT_FSPICK TraceId = 1052
const SYS_ENTER_FSCONFIG TraceId = 1051
const SYS_EXIT_FSCONFIG TraceId = 1050
const SYS_ENTER_STATFS TraceId = 1049
const SYS_EXIT_STATFS TraceId = 1048
const SYS_ENTER_FSTATFS TraceId = 1047
const SYS_EXIT_FSTATFS TraceId = 1046
const SYS_ENTER_USTAT TraceId = 1045
const SYS_EXIT_USTAT TraceId = 1044
const SYS_ENTER_GETCWD TraceId = 1043
const SYS_EXIT_GETCWD TraceId = 1042
const SYS_ENTER_UTIMENSAT TraceId = 1041
const SYS_EXIT_UTIMENSAT TraceId = 1040
const SYS_ENTER_FUTIMESAT TraceId = 1039
const SYS_EXIT_FUTIMESAT TraceId = 1038
const SYS_ENTER_UTIMES TraceId = 1037
const SYS_EXIT_UTIMES TraceId = 1036
const SYS_ENTER_UTIME TraceId = 1035
const SYS_EXIT_UTIME TraceId = 1034
const SYS_ENTER_SYNC TraceId = 1033
const SYS_EXIT_SYNC TraceId = 1032
const SYS_ENTER_SYNCFS TraceId = 1031
const SYS_EXIT_SYNCFS TraceId = 1030
const SYS_ENTER_FSYNC TraceId = 1029
const SYS_EXIT_FSYNC TraceId = 1028
const SYS_ENTER_FDATASYNC TraceId = 1027
const SYS_EXIT_FDATASYNC TraceId = 1026
const SYS_ENTER_SYNC_FILE_RANGE TraceId = 1025
const SYS_EXIT_SYNC_FILE_RANGE TraceId = 1024
const SYS_ENTER_VMSPLICE TraceId = 1023
const SYS_EXIT_VMSPLICE TraceId = 1022
const SYS_ENTER_SPLICE TraceId = 1021
const SYS_EXIT_SPLICE TraceId = 1020
const SYS_ENTER_TEE TraceId = 1019
const SYS_EXIT_TEE TraceId = 1018
const SYS_ENTER_SETXATTRAT TraceId = 985
const SYS_EXIT_SETXATTRAT TraceId = 984
const SYS_ENTER_SETXATTR TraceId = 983
const SYS_EXIT_SETXATTR TraceId = 982
const SYS_ENTER_LSETXATTR TraceId = 981
const SYS_EXIT_LSETXATTR TraceId = 980
const SYS_ENTER_FSETXATTR TraceId = 979
const SYS_EXIT_FSETXATTR TraceId = 978
const SYS_ENTER_GETXATTRAT TraceId = 977
const SYS_EXIT_GETXATTRAT TraceId = 976
const SYS_ENTER_GETXATTR TraceId = 975
const SYS_EXIT_GETXATTR TraceId = 974
const SYS_ENTER_LGETXATTR TraceId = 973
const SYS_EXIT_LGETXATTR TraceId = 972
const SYS_ENTER_FGETXATTR TraceId = 971
const SYS_EXIT_FGETXATTR TraceId = 970
const SYS_ENTER_LISTXATTRAT TraceId = 969
const SYS_EXIT_LISTXATTRAT TraceId = 968
const SYS_ENTER_LISTXATTR TraceId = 967
const SYS_EXIT_LISTXATTR TraceId = 966
const SYS_ENTER_LLISTXATTR TraceId = 965
const SYS_EXIT_LLISTXATTR TraceId = 964
const SYS_ENTER_FLISTXATTR TraceId = 963
const SYS_EXIT_FLISTXATTR TraceId = 962
const SYS_ENTER_REMOVEXATTRAT TraceId = 961
const SYS_EXIT_REMOVEXATTRAT TraceId = 960
const SYS_ENTER_REMOVEXATTR TraceId = 959
const SYS_EXIT_REMOVEXATTR TraceId = 958
const SYS_ENTER_LREMOVEXATTR TraceId = 957
const SYS_EXIT_LREMOVEXATTR TraceId = 956
const SYS_ENTER_FREMOVEXATTR TraceId = 955
const SYS_EXIT_FREMOVEXATTR TraceId = 954
const SYS_ENTER_UMOUNT TraceId = 953
const SYS_EXIT_UMOUNT TraceId = 952
const SYS_ENTER_OPEN_TREE TraceId = 951
const SYS_EXIT_OPEN_TREE TraceId = 950
const SYS_ENTER_MOUNT TraceId = 949
const SYS_EXIT_MOUNT TraceId = 948
const SYS_ENTER_FSMOUNT TraceId = 947
const SYS_EXIT_FSMOUNT TraceId = 946
const SYS_ENTER_MOVE_MOUNT TraceId = 945
const SYS_EXIT_MOVE_MOUNT TraceId = 944
const SYS_ENTER_PIVOT_ROOT TraceId = 943
const SYS_EXIT_PIVOT_ROOT TraceId = 942
const SYS_ENTER_MOUNT_SETATTR TraceId = 941
const SYS_EXIT_MOUNT_SETATTR TraceId = 940
const SYS_ENTER_OPEN_TREE_ATTR TraceId = 939
const SYS_EXIT_OPEN_TREE_ATTR TraceId = 938
const SYS_ENTER_STATMOUNT TraceId = 937
const SYS_EXIT_STATMOUNT TraceId = 936
const SYS_ENTER_LISTMOUNT TraceId = 935
const SYS_EXIT_LISTMOUNT TraceId = 934
const SYS_ENTER_SYSFS TraceId = 933
const SYS_EXIT_SYSFS TraceId = 932
const SYS_ENTER_CLOSE_RANGE TraceId = 931
const SYS_EXIT_CLOSE_RANGE TraceId = 930
const SYS_ENTER_DUP3 TraceId = 929
const SYS_EXIT_DUP3 TraceId = 928
const SYS_ENTER_DUP2 TraceId = 927
const SYS_EXIT_DUP2 TraceId = 926
const SYS_ENTER_DUP TraceId = 925
const SYS_EXIT_DUP TraceId = 924
const SYS_ENTER_SELECT TraceId = 919
const SYS_EXIT_SELECT TraceId = 918
const SYS_ENTER_PSELECT6 TraceId = 917
const SYS_EXIT_PSELECT6 TraceId = 916
const SYS_ENTER_POLL TraceId = 915
const SYS_EXIT_POLL TraceId = 914
const SYS_ENTER_PPOLL TraceId = 913
const SYS_EXIT_PPOLL TraceId = 912
const SYS_ENTER_GETDENTS TraceId = 911
const SYS_EXIT_GETDENTS TraceId = 910
const SYS_ENTER_GETDENTS64 TraceId = 909
const SYS_EXIT_GETDENTS64 TraceId = 908
const SYS_ENTER_IOCTL TraceId = 907
const SYS_EXIT_IOCTL TraceId = 906
const SYS_ENTER_FCNTL TraceId = 905
const SYS_EXIT_FCNTL TraceId = 904
const SYS_ENTER_MKNODAT TraceId = 903
const SYS_EXIT_MKNODAT TraceId = 902
const SYS_ENTER_MKNOD TraceId = 901
const SYS_EXIT_MKNOD TraceId = 900
const SYS_ENTER_MKDIRAT TraceId = 899
const SYS_EXIT_MKDIRAT TraceId = 898
const SYS_ENTER_MKDIR TraceId = 897
const SYS_EXIT_MKDIR TraceId = 896
const SYS_ENTER_RMDIR TraceId = 895
const SYS_EXIT_RMDIR TraceId = 894
const SYS_ENTER_UNLINKAT TraceId = 893
const SYS_EXIT_UNLINKAT TraceId = 892
const SYS_ENTER_UNLINK TraceId = 891
const SYS_EXIT_UNLINK TraceId = 890
const SYS_ENTER_SYMLINKAT TraceId = 889
const SYS_EXIT_SYMLINKAT TraceId = 888
const SYS_ENTER_SYMLINK TraceId = 887
const SYS_EXIT_SYMLINK TraceId = 886
const SYS_ENTER_LINKAT TraceId = 885
const SYS_EXIT_LINKAT TraceId = 884
const SYS_ENTER_LINK TraceId = 883
const SYS_EXIT_LINK TraceId = 882
const SYS_ENTER_RENAMEAT2 TraceId = 881
const SYS_EXIT_RENAMEAT2 TraceId = 880
const SYS_ENTER_RENAMEAT TraceId = 879
const SYS_EXIT_RENAMEAT TraceId = 878
const SYS_ENTER_RENAME TraceId = 877
const SYS_EXIT_RENAME TraceId = 876
const SYS_ENTER_PIPE2 TraceId = 875
const SYS_EXIT_PIPE2 TraceId = 874
const SYS_ENTER_PIPE TraceId = 873
const SYS_EXIT_PIPE TraceId = 872
const SYS_ENTER_EXECVE TraceId = 871
const SYS_EXIT_EXECVE TraceId = 870
const SYS_ENTER_EXECVEAT TraceId = 869
const SYS_EXIT_EXECVEAT TraceId = 868
const SYS_ENTER_NEWSTAT TraceId = 867
const SYS_EXIT_NEWSTAT TraceId = 866
const SYS_ENTER_NEWLSTAT TraceId = 865
const SYS_EXIT_NEWLSTAT TraceId = 864
const SYS_ENTER_NEWFSTATAT TraceId = 863
const SYS_EXIT_NEWFSTATAT TraceId = 862
const SYS_ENTER_NEWFSTAT TraceId = 861
const SYS_EXIT_NEWFSTAT TraceId = 860
const SYS_ENTER_READLINKAT TraceId = 859
const SYS_EXIT_READLINKAT TraceId = 858
const SYS_ENTER_READLINK TraceId = 857
const SYS_EXIT_READLINK TraceId = 856
const SYS_ENTER_STATX TraceId = 855
const SYS_EXIT_STATX TraceId = 854
const SYS_ENTER_LSEEK TraceId = 853
const SYS_EXIT_LSEEK TraceId = 852
const SYS_ENTER_READ TraceId = 851
const SYS_EXIT_READ TraceId = 850
const SYS_ENTER_WRITE TraceId = 849
const SYS_EXIT_WRITE TraceId = 848
const SYS_ENTER_PREAD64 TraceId = 847
const SYS_EXIT_PREAD64 TraceId = 846
const SYS_ENTER_PWRITE64 TraceId = 845
const SYS_EXIT_PWRITE64 TraceId = 844
const SYS_ENTER_READV TraceId = 843
const SYS_EXIT_READV TraceId = 842
const SYS_ENTER_WRITEV TraceId = 841
const SYS_EXIT_WRITEV TraceId = 840
const SYS_ENTER_PREADV TraceId = 839
const SYS_EXIT_PREADV TraceId = 838
const SYS_ENTER_PREADV2 TraceId = 837
const SYS_EXIT_PREADV2 TraceId = 836
const SYS_ENTER_PWRITEV TraceId = 835
const SYS_EXIT_PWRITEV TraceId = 834
const SYS_ENTER_PWRITEV2 TraceId = 833
const SYS_EXIT_PWRITEV2 TraceId = 832
const SYS_ENTER_SENDFILE64 TraceId = 831
const SYS_EXIT_SENDFILE64 TraceId = 830
const SYS_ENTER_COPY_FILE_RANGE TraceId = 829
const SYS_EXIT_COPY_FILE_RANGE TraceId = 828
const SYS_ENTER_TRUNCATE TraceId = 827
const SYS_EXIT_TRUNCATE TraceId = 826
const SYS_ENTER_FTRUNCATE TraceId = 825
const SYS_EXIT_FTRUNCATE TraceId = 824
const SYS_ENTER_FALLOCATE TraceId = 823
const SYS_EXIT_FALLOCATE TraceId = 822
const SYS_ENTER_FACCESSAT TraceId = 821
const SYS_EXIT_FACCESSAT TraceId = 820
const SYS_ENTER_FACCESSAT2 TraceId = 819
const SYS_EXIT_FACCESSAT2 TraceId = 818
const SYS_ENTER_ACCESS TraceId = 817
const SYS_EXIT_ACCESS TraceId = 816
const SYS_ENTER_CHDIR TraceId = 815
const SYS_EXIT_CHDIR TraceId = 814
const SYS_ENTER_FCHDIR TraceId = 813
const SYS_EXIT_FCHDIR TraceId = 812
const SYS_ENTER_CHROOT TraceId = 811
const SYS_EXIT_CHROOT TraceId = 810
const SYS_ENTER_FCHMOD TraceId = 809
const SYS_EXIT_FCHMOD TraceId = 808
const SYS_ENTER_FCHMODAT2 TraceId = 807
const SYS_EXIT_FCHMODAT2 TraceId = 806
const SYS_ENTER_FCHMODAT TraceId = 805
const SYS_EXIT_FCHMODAT TraceId = 804
const SYS_ENTER_CHMOD TraceId = 803
const SYS_EXIT_CHMOD TraceId = 802
const SYS_ENTER_FCHOWNAT TraceId = 801
const SYS_EXIT_FCHOWNAT TraceId = 800
const SYS_ENTER_CHOWN TraceId = 799
const SYS_EXIT_CHOWN TraceId = 798
const SYS_ENTER_LCHOWN TraceId = 797
const SYS_EXIT_LCHOWN TraceId = 796
const SYS_ENTER_FCHOWN TraceId = 795
const SYS_EXIT_FCHOWN TraceId = 794
const SYS_ENTER_OPEN TraceId = 793
const SYS_EXIT_OPEN TraceId = 792
const SYS_ENTER_OPENAT TraceId = 791
const SYS_EXIT_OPENAT TraceId = 790
const SYS_ENTER_OPENAT2 TraceId = 789
const SYS_EXIT_OPENAT2 TraceId = 788
const SYS_ENTER_CREAT TraceId = 787
const SYS_EXIT_CREAT TraceId = 786
const SYS_ENTER_CLOSE TraceId = 785
const SYS_EXIT_CLOSE TraceId = 784
const SYS_ENTER_VHANGUP TraceId = 783
const SYS_EXIT_VHANGUP TraceId = 782
const SYS_ENTER_MEMFD_CREATE TraceId = 781
const SYS_EXIT_MEMFD_CREATE TraceId = 780
const SYS_ENTER_MEMFD_SECRET TraceId = 774
const SYS_EXIT_MEMFD_SECRET TraceId = 773
const SYS_ENTER_MOVE_PAGES TraceId = 754
const SYS_EXIT_MOVE_PAGES TraceId = 753
const SYS_ENTER_SET_MEMPOLICY_HOME_NODE TraceId = 743
const SYS_EXIT_SET_MEMPOLICY_HOME_NODE TraceId = 742
const SYS_ENTER_MBIND TraceId = 741
const SYS_EXIT_MBIND TraceId = 740
const SYS_ENTER_SET_MEMPOLICY TraceId = 739
const SYS_EXIT_SET_MEMPOLICY TraceId = 738
const SYS_ENTER_MIGRATE_PAGES TraceId = 737
const SYS_EXIT_MIGRATE_PAGES TraceId = 736
const SYS_ENTER_GET_MEMPOLICY TraceId = 735
const SYS_EXIT_GET_MEMPOLICY TraceId = 734
const SYS_ENTER_SWAPOFF TraceId = 733
const SYS_EXIT_SWAPOFF TraceId = 732
const SYS_ENTER_SWAPON TraceId = 731
const SYS_EXIT_SWAPON TraceId = 730
const SYS_ENTER_MADVISE TraceId = 729
const SYS_EXIT_MADVISE TraceId = 728
const SYS_ENTER_PROCESS_MADVISE TraceId = 727
const SYS_EXIT_PROCESS_MADVISE TraceId = 726
const SYS_ENTER_MSEAL TraceId = 725
const SYS_EXIT_MSEAL TraceId = 724
const SYS_ENTER_PROCESS_VM_READV TraceId = 723
const SYS_EXIT_PROCESS_VM_READV TraceId = 722
const SYS_ENTER_PROCESS_VM_WRITEV TraceId = 721
const SYS_EXIT_PROCESS_VM_WRITEV TraceId = 720
const SYS_ENTER_MSYNC TraceId = 712
const SYS_EXIT_MSYNC TraceId = 711
const SYS_ENTER_MREMAP TraceId = 710
const SYS_EXIT_MREMAP TraceId = 709
const SYS_ENTER_MPROTECT TraceId = 708
const SYS_EXIT_MPROTECT TraceId = 707
const SYS_ENTER_PKEY_MPROTECT TraceId = 706
const SYS_EXIT_PKEY_MPROTECT TraceId = 705
const SYS_ENTER_PKEY_ALLOC TraceId = 704
const SYS_EXIT_PKEY_ALLOC TraceId = 703
const SYS_ENTER_PKEY_FREE TraceId = 702
const SYS_EXIT_PKEY_FREE TraceId = 701
const SYS_ENTER_BRK TraceId = 698
const SYS_EXIT_BRK TraceId = 697
const SYS_ENTER_MUNMAP TraceId = 696
const SYS_EXIT_MUNMAP TraceId = 695
const SYS_ENTER_REMAP_FILE_PAGES TraceId = 694
const SYS_EXIT_REMAP_FILE_PAGES TraceId = 693
const SYS_ENTER_MLOCK TraceId = 692
const SYS_EXIT_MLOCK TraceId = 691
const SYS_ENTER_MLOCK2 TraceId = 690
const SYS_EXIT_MLOCK2 TraceId = 689
const SYS_ENTER_MUNLOCK TraceId = 688
const SYS_EXIT_MUNLOCK TraceId = 687
const SYS_ENTER_MLOCKALL TraceId = 686
const SYS_EXIT_MLOCKALL TraceId = 685
const SYS_ENTER_MUNLOCKALL TraceId = 684
const SYS_EXIT_MUNLOCKALL TraceId = 683
const SYS_ENTER_MINCORE TraceId = 682
const SYS_EXIT_MINCORE TraceId = 681
const SYS_ENTER_READAHEAD TraceId = 616
const SYS_EXIT_READAHEAD TraceId = 615
const SYS_ENTER_FADVISE64 TraceId = 614
const SYS_EXIT_FADVISE64 TraceId = 613
const SYS_ENTER_PROCESS_MRELEASE TraceId = 604
const SYS_EXIT_PROCESS_MRELEASE TraceId = 603
const SYS_ENTER_CACHESTAT TraceId = 595
const SYS_EXIT_CACHESTAT TraceId = 594
const SYS_ENTER_RSEQ TraceId = 591
const SYS_EXIT_RSEQ TraceId = 590
const SYS_ENTER_PERF_EVENT_OPEN TraceId = 587
const SYS_EXIT_PERF_EVENT_OPEN TraceId = 586
const SYS_ENTER_BPF TraceId = 585
const SYS_EXIT_BPF TraceId = 584
const SYS_ENTER_SECCOMP TraceId = 526
const SYS_EXIT_SECCOMP TraceId = 525
const SYS_ENTER_KEXEC_FILE_LOAD TraceId = 508
const SYS_EXIT_KEXEC_FILE_LOAD TraceId = 507
const SYS_ENTER_KEXEC_LOAD TraceId = 506
const SYS_EXIT_KEXEC_LOAD TraceId = 505
const SYS_ENTER_ACCT TraceId = 504
const SYS_EXIT_ACCT TraceId = 503
const SYS_ENTER_SET_ROBUST_LIST TraceId = 499
const SYS_EXIT_SET_ROBUST_LIST TraceId = 498
const SYS_ENTER_GET_ROBUST_LIST TraceId = 497
const SYS_EXIT_GET_ROBUST_LIST TraceId = 496
const SYS_ENTER_FUTEX TraceId = 495
const SYS_EXIT_FUTEX TraceId = 494
const SYS_ENTER_FUTEX_WAITV TraceId = 493
const SYS_EXIT_FUTEX_WAITV TraceId = 492
const SYS_ENTER_FUTEX_WAKE TraceId = 491
const SYS_EXIT_FUTEX_WAKE TraceId = 490
const SYS_ENTER_FUTEX_WAIT TraceId = 489
const SYS_EXIT_FUTEX_WAIT TraceId = 488
const SYS_ENTER_FUTEX_REQUEUE TraceId = 487
const SYS_EXIT_FUTEX_REQUEUE TraceId = 486
const SYS_ENTER_GETITIMER TraceId = 471
const SYS_EXIT_GETITIMER TraceId = 470
const SYS_ENTER_ALARM TraceId = 469
const SYS_EXIT_ALARM TraceId = 468
const SYS_ENTER_SETITIMER TraceId = 467
const SYS_EXIT_SETITIMER TraceId = 466
const SYS_ENTER_TIMER_CREATE TraceId = 465
const SYS_EXIT_TIMER_CREATE TraceId = 464
const SYS_ENTER_TIMER_GETTIME TraceId = 463
const SYS_EXIT_TIMER_GETTIME TraceId = 462
const SYS_ENTER_TIMER_GETOVERRUN TraceId = 461
const SYS_EXIT_TIMER_GETOVERRUN TraceId = 460
const SYS_ENTER_TIMER_SETTIME TraceId = 459
const SYS_EXIT_TIMER_SETTIME TraceId = 458
const SYS_ENTER_TIMER_DELETE TraceId = 457
const SYS_EXIT_TIMER_DELETE TraceId = 456
const SYS_ENTER_CLOCK_SETTIME TraceId = 455
const SYS_EXIT_CLOCK_SETTIME TraceId = 454
const SYS_ENTER_CLOCK_GETTIME TraceId = 453
const SYS_EXIT_CLOCK_GETTIME TraceId = 452
const SYS_ENTER_CLOCK_ADJTIME TraceId = 451
const SYS_EXIT_CLOCK_ADJTIME TraceId = 450
const SYS_ENTER_CLOCK_GETRES TraceId = 449
const SYS_EXIT_CLOCK_GETRES TraceId = 448
const SYS_ENTER_CLOCK_NANOSLEEP TraceId = 447
const SYS_EXIT_CLOCK_NANOSLEEP TraceId = 446
const SYS_ENTER_NANOSLEEP TraceId = 441
const SYS_EXIT_NANOSLEEP TraceId = 440
const SYS_ENTER_TIME TraceId = 425
const SYS_EXIT_TIME TraceId = 424
const SYS_ENTER_GETTIMEOFDAY TraceId = 423
const SYS_EXIT_GETTIMEOFDAY TraceId = 422
const SYS_ENTER_SETTIMEOFDAY TraceId = 421
const SYS_EXIT_SETTIMEOFDAY TraceId = 420
const SYS_ENTER_ADJTIMEX TraceId = 419
const SYS_EXIT_ADJTIMEX TraceId = 418
const SYS_ENTER_KCMP TraceId = 417
const SYS_EXIT_KCMP TraceId = 416
const SYS_ENTER_DELETE_MODULE TraceId = 410
const SYS_EXIT_DELETE_MODULE TraceId = 409
const SYS_ENTER_INIT_MODULE TraceId = 408
const SYS_EXIT_INIT_MODULE TraceId = 407
const SYS_ENTER_FINIT_MODULE TraceId = 406
const SYS_EXIT_FINIT_MODULE TraceId = 405
const SYS_ENTER_SYSLOG TraceId = 350
const SYS_EXIT_SYSLOG TraceId = 349
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
const SYS_EXIT_RT_SIGRETURN TraceId = 56

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

type ExecEvent struct {
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Dirfd     int32
	Flags     int32
	Filename  [MAX_FILENAME_LENGTH]byte
	Comm      [MAX_PROGNAME_LENGTH]byte
}

func (e ExecEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Dirfd:%v Flags:%v Filename:%v Comm:%v", e.EventType, e.TraceId, e.Time, e.Pid, e.Tid, e.Dirfd, e.Flags, string(e.Filename[:]), string(e.Comm[:]))
}

func (e ExecEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*ExecEvent)
	if !ok {
		return false
	}
	return e.EventType == otherConcrete.EventType && e.TraceId == otherConcrete.TraceId && e.Time == otherConcrete.Time && e.Pid == otherConcrete.Pid && e.Tid == otherConcrete.Tid && e.Dirfd == otherConcrete.Dirfd && e.Flags == otherConcrete.Flags && e.Filename == otherConcrete.Filename && e.Comm == otherConcrete.Comm
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
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Fd        int32
	Ret       int64
}

func (a AcceptEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Fd:%v Ret:%v", a.EventType, a.TraceId, a.Time, a.Pid, a.Tid, a.Fd, a.Ret)
}

func (a AcceptEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*AcceptEvent)
	if !ok {
		return false
	}
	return a.EventType == otherConcrete.EventType && a.TraceId == otherConcrete.TraceId && a.Time == otherConcrete.Time && a.Pid == otherConcrete.Pid && a.Tid == otherConcrete.Tid && a.Fd == otherConcrete.Fd && a.Ret == otherConcrete.Ret
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
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Flags     int32
	Ret       int64
}

func (e EventfdEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Flags:%v Ret:%v", e.EventType, e.TraceId, e.Time, e.Pid, e.Tid, e.Flags, e.Ret)
}

func (e EventfdEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*EventfdEvent)
	if !ok {
		return false
	}
	return e.EventType == otherConcrete.EventType && e.TraceId == otherConcrete.TraceId && e.Time == otherConcrete.Time && e.Pid == otherConcrete.Pid && e.Tid == otherConcrete.Tid && e.Flags == otherConcrete.Flags && e.Ret == otherConcrete.Ret
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

var poolOfEventfdEvents = sync.Pool{
	New: func() any { return &EventfdEvent{} },
}

func NewEventfdEvent(raw []byte) *EventfdEvent {
	e := poolOfEventfdEvents.Get().(*EventfdEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, e); err != nil {
		*e = EventfdEvent{}
		poolOfEventfdEvents.Put(e)
		return nil
	}
	return e
}

func (e *EventfdEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, e)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *EventfdEvent) Recycle() {
	poolOfEventfdEvents.Put(e)
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
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	Nfds      int32
	TimeoutNs int64
}

func (p PollEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v Nfds:%v TimeoutNs:%v", p.EventType, p.TraceId, p.Time, p.Pid, p.Tid, p.Nfds, p.TimeoutNs)
}

func (p PollEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*PollEvent)
	if !ok {
		return false
	}
	return p.EventType == otherConcrete.EventType && p.TraceId == otherConcrete.TraceId && p.Time == otherConcrete.Time && p.Pid == otherConcrete.Pid && p.Tid == otherConcrete.Tid && p.Nfds == otherConcrete.Nfds && p.TimeoutNs == otherConcrete.TimeoutNs
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
	EventType EventType
	TraceId   TraceId
	Time      uint64
	Pid       uint32
	Tid       uint32
	FdA       int32
	FdB       int32
	Extra     uint64
}

func (t TwoFdEvent) String() string {
	return fmt.Sprintf("EventType:%v TraceId:%v Time:%v Pid:%v Tid:%v FdA:%v FdB:%v Extra:%v", t.EventType, t.TraceId, t.Time, t.Pid, t.Tid, t.FdA, t.FdB, t.Extra)
}

func (t TwoFdEvent) Equals(other any) bool {
	otherConcrete, ok := other.(*TwoFdEvent)
	if !ok {
		return false
	}
	return t.EventType == otherConcrete.EventType && t.TraceId == otherConcrete.TraceId && t.Time == otherConcrete.Time && t.Pid == otherConcrete.Pid && t.Tid == otherConcrete.Tid && t.FdA == otherConcrete.FdA && t.FdB == otherConcrete.FdB && t.Extra == otherConcrete.Extra
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
	t := poolOfTwoFdEvents.Get().(*TwoFdEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, t); err != nil {
		*t = TwoFdEvent{}
		poolOfTwoFdEvents.Put(t)
		return nil
	}
	return t
}

func (t *TwoFdEvent) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, t)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (t *TwoFdEvent) Recycle() {
	poolOfTwoFdEvents.Put(t)
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
