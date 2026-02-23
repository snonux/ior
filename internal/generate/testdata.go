package generate

// Real sysfs tracepoint format data captured from a Linux 6.18 kernel,
// used as test fixtures.

const FormatOpenat = `name: sys_enter_openat
ID: 784
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;
	field:umode_t mode;	offset:40;	size:8;	signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
`

const FormatExitOpenat = `name: sys_exit_openat
ID: 783
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatOpen = `name: sys_enter_open
ID: 786
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * filename;	offset:16;	size:8;	signed:0;
	field:int flags;	offset:24;	size:8;	signed:0;
	field:umode_t mode;	offset:32;	size:8;	signed:0;

print fmt: "filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
`

const FormatExitOpen = `name: sys_exit_open
ID: 785
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatRead = `name: sys_enter_read
ID: 844
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int fd;	offset:16;	size:8;	signed:0;
	field:char * buf;	offset:24;	size:8;	signed:0;
	field:size_t count;	offset:32;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))
`

const FormatExitRead = `name: sys_exit_read
ID: 843
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatWrite = `name: sys_enter_write
ID: 842
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int fd;	offset:16;	size:8;	signed:0;
	field:const char * buf;	offset:24;	size:8;	signed:0;
	field:size_t count;	offset:32;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))
`

const FormatExitWrite = `name: sys_exit_write
ID: 841
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatClose = `name: sys_enter_close
ID: 778
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int fd;	offset:16;	size:8;	signed:0;

print fmt: "fd: 0x%08lx", ((unsigned long)(REC->fd))
`

const FormatExitClose = `name: sys_exit_close
ID: 777
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatMsync = `name: sys_enter_msync
ID: 1029
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned long start;	offset:16;	size:8;	signed:0;
	field:size_t len;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;

print fmt: "start: 0x%08lx, len: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->start)), ((unsigned long)(REC->len)), ((unsigned long)(REC->flags))
`

const FormatMmap = `name: sys_enter_mmap
ID: 100
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned long addr;	offset:16;	size:8;	signed:0;
	field:unsigned long len;	offset:24;	size:8;	signed:0;
	field:unsigned long prot;	offset:32;	size:8;	signed:0;
	field:unsigned long flags;	offset:40;	size:8;	signed:0;
	field:unsigned long fd;	offset:48;	size:8;	signed:0;
	field:unsigned long off;	offset:56;	size:8;	signed:0;

print fmt: "addr: 0x%08lx, len: 0x%08lx, prot: 0x%08lx, flags: 0x%08lx, fd: 0x%08lx, off: 0x%08lx", ((unsigned long)(REC->addr)), ((unsigned long)(REC->len)), ((unsigned long)(REC->prot)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->fd)), ((unsigned long)(REC->off))
`

const FormatExitMmap = `name: sys_exit_mmap
ID: 99
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatExitMsync = `name: sys_exit_msync
ID: 1028
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatCopyFileRange = `name: sys_enter_copy_file_range
ID: 736
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fd_in;	offset:16;	size:8;	signed:0;
	field:loff_t * off_in;	offset:24;	size:8;	signed:0;
	field:int fd_out;	offset:32;	size:8;	signed:0;
	field:loff_t * off_out;	offset:40;	size:8;	signed:0;
	field:size_t len;	offset:48;	size:8;	signed:0;
	field:unsigned int flags;	offset:56;	size:8;	signed:0;

print fmt: "fd_in: 0x%08lx, off_in: 0x%08lx, fd_out: 0x%08lx, off_out: 0x%08lx, len: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->fd_in)), ((unsigned long)(REC->off_in)), ((unsigned long)(REC->fd_out)), ((unsigned long)(REC->off_out)), ((unsigned long)(REC->len)), ((unsigned long)(REC->flags))
`

const FormatExitCopyFileRange = `name: sys_exit_copy_file_range
ID: 735
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatRename = `name: sys_enter_rename
ID: 870
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * oldname;	offset:16;	size:8;	signed:0;
	field:const char * newname;	offset:24;	size:8;	signed:0;

print fmt: "oldname: 0x%08lx, newname: 0x%08lx", ((unsigned long)(REC->oldname)), ((unsigned long)(REC->newname))
`

const FormatExitRename = `name: sys_exit_rename
ID: 869
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatLinkat = `name: sys_enter_linkat
ID: 878
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int olddfd;	offset:16;	size:8;	signed:0;
	field:const char * oldname;	offset:24;	size:8;	signed:0;
	field:int newdfd;	offset:32;	size:8;	signed:0;
	field:const char * newname;	offset:40;	size:8;	signed:0;
	field:int flags;	offset:48;	size:8;	signed:0;

print fmt: "olddfd: 0x%08lx, oldname: 0x%08lx, newdfd: 0x%08lx, newname: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->olddfd)), ((unsigned long)(REC->oldname)), ((unsigned long)(REC->newdfd)), ((unsigned long)(REC->newname)), ((unsigned long)(REC->flags))
`

const FormatUnlink = `name: sys_enter_unlink
ID: 884
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * pathname;	offset:16;	size:8;	signed:0;

print fmt: "pathname: 0x%08lx", ((unsigned long)(REC->pathname))
`

const FormatDup3 = `name: sys_enter_dup3
ID: 922
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int oldfd;	offset:16;	size:8;	signed:0;
	field:unsigned int newfd;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;

print fmt: "oldfd: 0x%08lx, newfd: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->oldfd)), ((unsigned long)(REC->newfd)), ((unsigned long)(REC->flags))
`

const FormatExitDup3 = `name: sys_exit_dup3
ID: 921
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatDup = `name: sys_enter_dup
ID: 918
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int fildes;	offset:16;	size:8;	signed:0;

print fmt: "fildes: 0x%08lx", ((unsigned long)(REC->fildes))
`

const FormatDup2 = `name: sys_enter_dup2
ID: 920
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int oldfd;	offset:16;	size:8;	signed:0;
	field:unsigned int newfd;	offset:24;	size:8;	signed:0;

print fmt: "oldfd: 0x%08lx, newfd: 0x%08lx", ((unsigned long)(REC->oldfd)), ((unsigned long)(REC->newfd))
`

const FormatFcntl = `name: sys_enter_fcntl
ID: 898
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int fd;	offset:16;	size:8;	signed:0;
	field:unsigned int cmd;	offset:24;	size:8;	signed:0;
	field:unsigned long arg;	offset:32;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, cmd: 0x%08lx, arg: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->cmd)), ((unsigned long)(REC->arg))
`

const FormatExitFcntl = `name: sys_exit_fcntl
ID: 897
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatSync = `name: sys_enter_sync
ID: 1027
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;

print fmt: ""
`

const FormatExitSync = `name: sys_exit_sync
ID: 1026
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatGetcwd = `name: sys_enter_getcwd
ID: 795
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:char * buf;	offset:16;	size:8;	signed:0;
	field:unsigned long size;	offset:24;	size:8;	signed:0;

print fmt: "buf: 0x%08lx, size: 0x%08lx", ((unsigned long)(REC->buf)), ((unsigned long)(REC->size))
`

const FormatExitGetcwd = `name: sys_exit_getcwd
ID: 794
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatSyslog = `name: sys_enter_syslog
ID: 347
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int type;	offset:16;	size:8;	signed:0;
	field:char * buf;	offset:24;	size:8;	signed:0;
	field:int len;	offset:32;	size:8;	signed:0;

print fmt: "type: 0x%08lx, buf: 0x%08lx, len: 0x%08lx", ((unsigned long)(REC->type)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->len))
`

const FormatExitSyslog = `name: sys_exit_syslog
ID: 346
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatOpenByHandleAt = `name: sys_enter_open_by_handle_at
ID: 1133
format:
	field:unsigned short common_type;		offset:0;		size:2; signed:0;
	field:unsigned char common_flags;		offset:2;		size:1; signed:0;
	field:unsigned char common_preempt_count;		offset:3;		size:1; signed:0;
	field:int common_pid;		offset:4;		size:4; signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int mountdirfd;	offset:16;	size:8;	signed:0;
	field:struct file_handle * handle;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;

print fmt: "mountdirfd: 0x%08lx, handle: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->mountdirfd)), ((unsigned long)(REC->handle)), ((unsigned long)(REC->flags))
`

const FormatNameToHandleAt = `name: sys_enter_name_to_handle_at
ID: 1135
format:
	field:unsigned short common_type;		offset:0;		size:2; signed:0;
	field:unsigned char common_flags;		offset:2;		size:1; signed:0;
	field:unsigned char common_preempt_count;		offset:3;		size:1; signed:0;
	field:int common_pid;		offset:4;		size:4; signed:1;

	field:int __syscall_nr;		offset:8;		size:4; signed:1;
	field:int dfd;		offset:16;		size:8; signed:0;
	field:const char * name;		offset:24;		size:8; signed:0;
	field:struct file_handle * handle;		offset:32;		size:8; signed:0;
	field:void * mnt_id;		offset:40;		size:8; signed:0;
	field:int flag;		offset:48;		size:8; signed:0;

print fmt: "dfd: 0x%08lx, name: 0x%08lx, handle: 0x%08lx, mnt_id: 0x%08lx, flag: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->name)), ((unsigned long)(REC->handle)), ((unsigned long)(REC->mnt_id)), ((unsigned long)(REC->flag))
`

const FormatExitOpenByHandleAt = `name: sys_exit_open_by_handle_at
ID: 1132
format:
	field:unsigned short common_type;		offset:0;		size:2; signed:0;
	field:unsigned char common_flags;		offset:2;		size:1; signed:0;
	field:unsigned char common_preempt_count;		offset:3;		size:1; signed:0;
	field:int common_pid;		offset:4;		size:4; signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatExitNameToHandleAt = `name: sys_exit_name_to_handle_at
ID: 1134
format:
	field:unsigned short common_type;		offset:0;		size:2; signed:0;
	field:unsigned char common_flags;		offset:2;		size:1; signed:0;
	field:unsigned char common_preempt_count;		offset:3;		size:1; signed:0;
	field:int common_pid;		offset:4;		size:4; signed:1;

	field:int __syscall_nr;		offset:8;		size:4; signed:1;
	field:long ret;		offset:16;		size:8; signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatIoUringEnter = `name: sys_enter_io_uring_enter
ID: 1496
format:
	field:unsigned short common_type;		offset:0;		size:2; signed:0;
	field:unsigned char common_flags;		offset:2;		size:1; signed:0;
	field:unsigned char common_preempt_count;		offset:3;		size:1; signed:0;
	field:int common_pid;		offset:4;		size:4; signed:1;

	field:int __syscall_nr;		offset:8;		size:4; signed:1;
	field:unsigned int fd;		offset:16;		size:8; signed:0;
	field:u32 to_submit;		offset:24;		size:8; signed:0;
	field:u32 min_complete;		offset:32;		size:8; signed:0;
	field:u32 flags;		offset:40;		size:8; signed:0;
	field:const void * argp;		offset:48;		size:8; signed:0;
	field:size_t argsz;		offset:56;		size:8; signed:0;

print fmt: "fd: 0x%08lx, to_submit: 0x%08lx, min_complete: 0x%08lx, flags: 0x%08lx, argp: 0x%08lx, argsz: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->to_submit)), ((unsigned long)(REC->min_complete)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->argp)), ((unsigned long)(REC->argsz))
`

const FormatIoUringRegister = `name: sys_enter_io_uring_register
ID: 1515
format:
	field:unsigned short common_type;		offset:0;		size:2; signed:0;
	field:unsigned char common_flags;		offset:2;		size:1; signed:0;
	field:unsigned char common_preempt_count;		offset:3;		size:1; signed:0;
	field:int common_pid;		offset:4;		size:4; signed:1;

	field:int __syscall_nr;		offset:8;		size:4; signed:1;
	field:unsigned int fd;		offset:16;		size:8; signed:0;
	field:unsigned int opcode;		offset:24;		size:8; signed:0;
	field:void * arg;		offset:32;		size:8; signed:0;
	field:unsigned int nr_args;		offset:40;		size:8; signed:0;

print fmt: "fd: 0x%08lx, opcode: 0x%08lx, arg: 0x%08lx, nr_args: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->opcode)), ((unsigned long)(REC->arg)), ((unsigned long)(REC->nr_args))
`

const FormatExitIoUringRegister = `name: sys_exit_io_uring_register
ID: 1514
format:
	field:unsigned short common_type;		offset:0;		size:2; signed:0;
	field:unsigned char common_flags;		offset:2;		size:1; signed:0;
	field:unsigned char common_preempt_count;		offset:3;		size:1; signed:0;
	field:int common_pid;		offset:4;		size:4; signed:1;

	field:int __syscall_nr;		offset:8;		size:4; signed:1;
	field:long ret;		offset:16;		size:8; signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatExitIoUringEnter = `name: sys_exit_io_uring_enter
ID: 1495
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatOpenat2 = `name: sys_enter_openat2
ID: 782
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:struct open_how * how;	offset:32;	size:8;	signed:0;
	field:size_t usize;	offset:40;	size:8;	signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, how: 0x%08lx, usize: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->how)), ((unsigned long)(REC->usize))
`

const FormatCreat = `name: sys_enter_creat
ID: 780
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * pathname;	offset:16;	size:8;	signed:0;
	field:umode_t mode;	offset:24;	size:8;	signed:0;

print fmt: "pathname: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->pathname)), ((unsigned long)(REC->mode))
`

// Ignored tracepoints

const FormatExecve = `name: sys_enter_execve
ID: 864
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * filename;	offset:16;	size:8;	signed:0;
	field:const char *const * argv;	offset:24;	size:8;	signed:0;
	field:const char *const * envp;	offset:32;	size:8;	signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
`

const FormatExitExecve = `name: sys_exit_execve
ID: 863
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatMknod = `name: sys_enter_mknod
ID: 894
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * filename;	offset:16;	size:8;	signed:0;
	field:umode_t mode;	offset:24;	size:8;	signed:0;
	field:unsigned dev;	offset:32;	size:8;	signed:0;

print fmt: "filename: 0x%08lx, mode: 0x%08lx, dev: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->mode)), ((unsigned long)(REC->dev))
`

const FormatExitMknod = `name: sys_exit_mknod
ID: 893
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatKill = `name: sys_enter_kill
ID: 183
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:pid_t pid;	offset:16;	size:8;	signed:0;
	field:int sig;	offset:24;	size:8;	signed:0;

print fmt: "pid: 0x%08lx, sig: 0x%08lx", ((unsigned long)(REC->pid)), ((unsigned long)(REC->sig))
`

const FormatExitKill = `name: sys_exit_kill
ID: 182
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatAccept = `name: sys_enter_accept
ID: 1808
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fd;	offset:16;	size:8;	signed:0;
	field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
	field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, upeer_sockaddr: 0x%08lx, upeer_addrlen: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->upeer_sockaddr)), ((unsigned long)(REC->upeer_addrlen))
`

const FormatExitAccept = `name: sys_exit_accept
ID: 1807
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatSocket = `name: sys_enter_socket
ID: 1818
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int family;	offset:16;	size:8;	signed:0;
	field:int type;	offset:24;	size:8;	signed:0;
	field:int protocol;	offset:32;	size:8;	signed:0;

print fmt: "family: 0x%08lx, type: 0x%08lx, protocol: 0x%08lx", ((unsigned long)(REC->family)), ((unsigned long)(REC->type)), ((unsigned long)(REC->protocol))
`

const FormatExitSocket = `name: sys_exit_socket
ID: 1817
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatPread64 = `name: sys_enter_pread64
ID: 840
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int fd;	offset:16;	size:8;	signed:0;
	field:char * buf;	offset:24;	size:8;	signed:0;
	field:size_t count;	offset:32;	size:8;	signed:0;
	field:loff_t pos;	offset:40;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx, pos: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count)), ((unsigned long)(REC->pos))
`

const FormatExitPread64 = `name: sys_exit_pread64
ID: 839
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatSymlink = `name: sys_enter_symlink
ID: 880
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * oldname;	offset:16;	size:8;	signed:0;
	field:const char * newname;	offset:24;	size:8;	signed:0;

print fmt: "oldname: 0x%08lx, newname: 0x%08lx", ((unsigned long)(REC->oldname)), ((unsigned long)(REC->newname))
`

const FormatExitSymlink = `name: sys_exit_symlink
ID: 879
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret
`
