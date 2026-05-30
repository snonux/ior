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

// FormatLseek mirrors the real sys_enter_lseek tracepoint
// (lseek(unsigned int fd, off_t offset, unsigned int whence)). The first
// field is a generic "fd" of an fd-like type, so ClassifyFormat resolves it
// to KindFd via classifyByField (fd at args[0]) — exactly like read/write.
// The off_t offset and whence args are not captured by an fd_event.
const FormatLseek = `name: sys_enter_lseek
ID: 853
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int fd;	offset:16;	size:8;	signed:0;
	field:off_t offset;	offset:24;	size:8;	signed:0;
	field:unsigned int whence;	offset:32;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, offset: 0x%08lx, whence: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->offset)), ((unsigned long)(REC->whence))
`

// FormatExitLseek mirrors sys_exit_lseek. lseek returns the RESULTING FILE
// OFFSET (bytes from the start of the file), or -1 on error — a file
// position, NOT a count of bytes transferred. So its exit is a plain
// ret_event and stays UNCLASSIFIED; it must never be ReadClassified /
// WriteClassified / TransferClassified, which would wrongly inflate I/O byte
// totals.
const FormatExitLseek = `name: sys_exit_lseek
ID: 852
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

const FormatMunmap = `name: sys_enter_munmap
ID: 696
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned long addr;	offset:16;	size:8;	signed:0;
	field:size_t len;	offset:24;	size:8;	signed:0;

print fmt: "addr: 0x%08lx, len: 0x%08lx", ((unsigned long)(REC->addr)), ((unsigned long)(REC->len))
`

const FormatExitMunmap = `name: sys_exit_munmap
ID: 695
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatMremap = `name: sys_enter_mremap
ID: 710
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned long addr;	offset:16;	size:8;	signed:0;
	field:unsigned long old_len;	offset:24;	size:8;	signed:0;
	field:unsigned long new_len;	offset:32;	size:8;	signed:0;
	field:unsigned long flags;	offset:40;	size:8;	signed:0;
	field:unsigned long new_addr;	offset:48;	size:8;	signed:0;

print fmt: "addr: 0x%08lx, old_len: 0x%08lx, new_len: 0x%08lx, flags: 0x%08lx, new_addr: 0x%08lx", ((unsigned long)(REC->addr)), ((unsigned long)(REC->old_len)), ((unsigned long)(REC->new_len)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->new_addr))
`

const FormatExitMremap = `name: sys_exit_mremap
ID: 709
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

// FormatRmdir mirrors the real sys_enter_rmdir tracepoint format. rmdir(2) is
// "int rmdir(const char *pathname)": it deletes an empty directory and takes a
// single argument, a genuine const char * filesystem path at args[0]. It is the
// directory-removal sibling of unlink(2) (same single-pathname shape) and the
// inverse of mkdir(2), so it classifies as KindPathname with PathnameField
// "pathname" and the path is captured from args[0]. Its exit returns int 0/-1
// (no byte count), so the exit stays UNCLASSIFIED.
const FormatRmdir = `name: sys_enter_rmdir
ID: 882
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * pathname;	offset:16;	size:8;	signed:0;

print fmt: "pathname: 0x%08lx", ((unsigned long)(REC->pathname))
`

// FormatUtime mirrors the real sys_enter_utime tracepoint format: its first
// argument "filename" is a genuine const char * filesystem path (args[0]),
// so utime classifies as KindPathname with PathnameField "filename" — the
// path is captured, just like its siblings utimensat/futimesat.
const FormatUtime = `name: sys_enter_utime
ID: 1035
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:char * filename;	offset:16;	size:8;	signed:0;
	field:struct utimbuf * times;	offset:24;	size:8;	signed:0;

print fmt: "filename: 0x%08lx, times: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->times))
`

// FormatAccess mirrors the real sys_enter_access tracepoint format. access(2)
// checks the calling process's permissions for a file; its first argument
// "filename" is a genuine const char * filesystem path at args[0] (there is no
// dirfd), so access classifies as KindPathname with PathnameField "filename"
// and the path is captured from args[0]. The trailing __data_loc field is the
// kernel's own copy of the string and is ignored by the classifier.
const FormatAccess = `name: sys_enter_access
ID: 817
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * filename;	offset:16;	size:8;	signed:0;
	field:int mode;	offset:24;	size:8;	signed:0;
	field:__data_loc char[] __filename_val;	offset:32;	size:4;	signed:0;

print fmt: "filename: 0x%08lx \"%s\", mode: 0x%08lx", ((unsigned long)(REC->filename)), __get_str(__filename_val), ((unsigned long)(REC->mode))
`

// FormatFaccessat mirrors the real sys_enter_faccessat tracepoint format.
// faccessat(2) is access(2) relative to a directory file descriptor: its first
// argument is "dfd" (the dirfd, args[0]) and the real path "filename" is at
// args[1]. It must therefore classify as KindPathname with PathnameField
// "filename" while capturing the path from args[1] (not args[0]) — the key
// difference from access(2), whose path is at args[0].
const FormatFaccessat = `name: sys_enter_faccessat
ID: 821
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:int mode;	offset:32;	size:8;	signed:0;
	field:__data_loc char[] __filename_val;	offset:40;	size:4;	signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx \"%s\", mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), __get_str(__filename_val), ((unsigned long)(REC->mode))
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

// FormatExitDup2 mirrors the kernel's sys_exit_dup2 tracepoint. Like dup/dup3,
// dup2 returns the new descriptor (newfd) on success or -1 on error; that fd
// number is reported as a plain ret_event (UNCLASSIFIED), never a byte-count
// transfer.
const FormatExitDup2 = `name: sys_exit_dup2
ID: 919
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
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

const FormatPidfdGetfd = `name: sys_enter_pidfd_getfd
ID: 271
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int pidfd;	offset:16;	size:8;	signed:0;
	field:int fd;	offset:24;	size:8;	signed:0;
	field:unsigned int flags;	offset:32;	size:8;	signed:0;

print fmt: "pidfd: 0x%08lx, fd: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->pidfd)), ((unsigned long)(REC->fd)), ((unsigned long)(REC->flags))
`

const FormatExitPidfdGetfd = `name: sys_exit_pidfd_getfd
ID: 270
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

const FormatMount = `name: sys_enter_mount
ID: 949
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * dev_name;	offset:16;	size:8;	signed:0;
	field:const char * dir_name;	offset:24;	size:8;	signed:0;
	field:const char * type;	offset:32;	size:8;	signed:0;
	field:unsigned long flags;	offset:40;	size:8;	signed:0;
	field:void * data;	offset:48;	size:8;	signed:0;

print fmt: "dev_name: 0x%08lx, dir_name: 0x%08lx, type: 0x%08lx, flags: 0x%08lx, data: 0x%08lx", ((unsigned long)(REC->dev_name)), ((unsigned long)(REC->dir_name)), ((unsigned long)(REC->type)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->data))
`

const FormatExitMount = `name: sys_exit_mount
ID: 948
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatUmount = `name: sys_enter_umount
ID: 953
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * name;	offset:16;	size:8;	signed:0;
	field:int flags;	offset:24;	size:8;	signed:0;

print fmt: "name: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->name)), ((unsigned long)(REC->flags))
`

const FormatExitUmount = `name: sys_exit_umount
ID: 952
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatMoveMount = `name: sys_enter_move_mount
ID: 945
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int from_dfd;	offset:16;	size:8;	signed:0;
	field:const char * from_pathname;	offset:24;	size:8;	signed:0;
	field:int to_dfd;	offset:32;	size:8;	signed:0;
	field:const char * to_pathname;	offset:40;	size:8;	signed:0;
	field:unsigned int flags;	offset:48;	size:8;	signed:0;

print fmt: "from_dfd: 0x%08lx, from_pathname: 0x%08lx, to_dfd: 0x%08lx, to_pathname: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->from_dfd)), ((unsigned long)(REC->from_pathname)), ((unsigned long)(REC->to_dfd)), ((unsigned long)(REC->to_pathname)), ((unsigned long)(REC->flags))
`

const FormatExitMoveMount = `name: sys_exit_move_mount
ID: 944
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatFsmount = `name: sys_enter_fsmount
ID: 947
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fs_fd;	offset:16;	size:8;	signed:0;
	field:unsigned int flags;	offset:24;	size:8;	signed:0;
	field:unsigned int attr_flags;	offset:32;	size:8;	signed:0;

print fmt: "fs_fd: 0x%08lx, flags: 0x%08lx, attr_flags: 0x%08lx", ((unsigned long)(REC->fs_fd)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->attr_flags))
`

const FormatExitFsmount = `name: sys_exit_fsmount
ID: 946
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatPivotRoot = `name: sys_enter_pivot_root
ID: 943
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * new_root;	offset:16;	size:8;	signed:0;
	field:const char * put_old;	offset:24;	size:8;	signed:0;

print fmt: "new_root: 0x%08lx, put_old: 0x%08lx", ((unsigned long)(REC->new_root)), ((unsigned long)(REC->put_old))
`

const FormatExitPivotRoot = `name: sys_exit_pivot_root
ID: 942
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatQuotactl = `name: sys_enter_quotactl
ID: 1164
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int cmd;	offset:16;	size:8;	signed:0;
	field:const char * special;	offset:24;	size:8;	signed:0;
	field:qid_t id;	offset:32;	size:8;	signed:0;
	field:void * addr;	offset:40;	size:8;	signed:0;

print fmt: "cmd: 0x%08lx, special: 0x%08lx, id: 0x%08lx, addr: 0x%08lx", ((unsigned long)(REC->cmd)), ((unsigned long)(REC->special)), ((unsigned long)(REC->id)), ((unsigned long)(REC->addr))
`

const FormatExitQuotactl = `name: sys_exit_quotactl
ID: 1163
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatStatmount = `name: sys_enter_statmount
ID: 937
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:struct mnt_id_req * req;	offset:16;	size:8;	signed:0;
	field:struct statmount * smbuf;	offset:24;	size:8;	signed:0;
	field:size_t bufsize;	offset:32;	size:8;	signed:0;
	field:unsigned long flags;	offset:40;	size:8;	signed:0;

print fmt: "req: 0x%08lx, smbuf: 0x%08lx, bufsize: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->req)), ((unsigned long)(REC->smbuf)), ((unsigned long)(REC->bufsize)), ((unsigned long)(REC->flags))
`

const FormatExitStatmount = `name: sys_exit_statmount
ID: 936
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatListmount = `name: sys_enter_listmount
ID: 935
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:struct mnt_id_req * req;	offset:16;	size:8;	signed:0;
	field:u64 * mnt_ids;	offset:24;	size:8;	signed:0;
	field:size_t nr_mnt_ids;	offset:32;	size:8;	signed:0;
	field:unsigned long flags;	offset:40;	size:8;	signed:0;

print fmt: "req: 0x%08lx, mnt_ids: 0x%08lx, nr_mnt_ids: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->req)), ((unsigned long)(REC->mnt_ids)), ((unsigned long)(REC->nr_mnt_ids)), ((unsigned long)(REC->flags))
`

const FormatExitListmount = `name: sys_exit_listmount
ID: 934
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatListns = `name: sys_enter_listns
ID: 277
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const struct ns_id_req * req;	offset:16;	size:8;	signed:0;
	field:u64 * ns_ids;	offset:24;	size:8;	signed:0;
	field:size_t nr_ns_ids;	offset:32;	size:8;	signed:0;
	field:unsigned long flags;	offset:40;	size:8;	signed:0;

print fmt: "req: 0x%08lx, ns_ids: 0x%08lx, nr_ns_ids: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->req)), ((unsigned long)(REC->ns_ids)), ((unsigned long)(REC->nr_ns_ids)), ((unsigned long)(REC->flags))
`

const FormatExitListns = `name: sys_exit_listns
ID: 276
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatSwapon = `name: sys_enter_swapon
ID: 731
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * specialfile;	offset:16;	size:8;	signed:0;
	field:int swap_flags;	offset:24;	size:8;	signed:0;

print fmt: "specialfile: 0x%08lx, swap_flags: 0x%08lx", ((unsigned long)(REC->specialfile)), ((unsigned long)(REC->swap_flags))
`

const FormatExitSwapon = `name: sys_exit_swapon
ID: 730
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatSwapoff = `name: sys_enter_swapoff
ID: 733
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * specialfile;	offset:16;	size:8;	signed:0;

print fmt: "specialfile: 0x%08lx", ((unsigned long)(REC->specialfile))
`

const FormatExitSwapoff = `name: sys_exit_swapoff
ID: 732
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
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

const FormatExecveat = `name: sys_enter_execveat
ID: 869
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:const char *const * argv;	offset:32;	size:8;	signed:0;
	field:const char *const * envp;	offset:40;	size:8;	signed:0;
	field:int flags;	offset:48;	size:8;	signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp)), ((unsigned long)(REC->flags))
`

const FormatExitExecveat = `name: sys_exit_execveat
ID: 868
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

// FormatMknodat mirrors the real sys_enter_mknodat tracepoint format. Unlike
// mknod(2), mknodat(2) takes a directory fd (dfd) as its first argument, which
// pushes the filename (the real path) to args[1]. The classifier must capture
// the path from args[1] here, not args[0] (which is the dirfd).
const FormatMknodat = `name: sys_enter_mknodat
ID: 896
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:umode_t mode;	offset:32;	size:8;	signed:0;
	field:unsigned dev;	offset:40;	size:8;	signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, mode: 0x%08lx, dev: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->mode)), ((unsigned long)(REC->dev))
`

// FormatExitMknodat mirrors the real sys_exit_mknodat tracepoint format. Like
// mknod, mknodat returns a plain int (0 on success, -1 on error) and is
// therefore classified as a ret_event (UNCLASSIFIED return value).
const FormatExitMknodat = `name: sys_exit_mknodat
ID: 895
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
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

// FormatInitModule mirrors the real sys_enter_init_module tracepoint layout.
// Its arguments are a userspace ELF image pointer (umod), the image length
// (len), and a module-parameter string (uargs). uargs is a parameter string of
// the form "name=value ..." — NOT a filesystem path — so init_module must
// classify as KindModule (null_event) and capture neither an fd nor a path.
const FormatInitModule = `name: sys_enter_init_module
ID: 9370
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:void * umod;	offset:16;	size:8;	signed:0;
	field:unsigned long len;	offset:24;	size:8;	signed:0;
	field:const char * uargs;	offset:32;	size:8;	signed:0;

print fmt: "umod: 0x%08lx, len: 0x%08lx, uargs: 0x%08lx", ((unsigned long)(REC->umod)), ((unsigned long)(REC->len)), ((unsigned long)(REC->uargs))
`

const FormatExitInitModule = `name: sys_exit_init_module
ID: 9369
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

// FormatFinitModule mirrors the real sys_enter_finit_module tracepoint layout.
// Unlike init_module, finit_module reads the module from a file descriptor
// (fd at args[0]), so field-based classification must yield KindFd and capture
// fd = args[0]. This is the load-bearing distinction from init_module.
const FormatFinitModule = `name: sys_enter_finit_module
ID: 9371
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fd;	offset:16;	size:8;	signed:0;
	field:const char * uargs;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, uargs: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->uargs)), ((unsigned long)(REC->flags))
`

const FormatExitFinitModule = `name: sys_exit_finit_module
ID: 9372
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

const FormatAccept4 = `name: sys_enter_accept4
ID: 1810
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fd;	offset:16;	size:8;	signed:0;
	field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
	field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;
	field:int flags;	offset:40;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, upeer_sockaddr: 0x%08lx, upeer_addrlen: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->upeer_sockaddr)), ((unsigned long)(REC->upeer_addrlen)), ((unsigned long)(REC->flags))
`

const FormatExitAccept4 = `name: sys_exit_accept4
ID: 1809
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

const FormatSocketpair = `name: sys_enter_socketpair
ID: 1816
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int family;	offset:16;	size:8;	signed:0;
	field:int type;	offset:24;	size:8;	signed:0;
	field:int protocol;	offset:32;	size:8;	signed:0;
	field:int * usockvec;	offset:40;	size:8;	signed:0;

print fmt: "family: 0x%08lx, type: 0x%08lx, protocol: 0x%08lx, usockvec: 0x%08lx", ((unsigned long)(REC->family)), ((unsigned long)(REC->type)), ((unsigned long)(REC->protocol)), ((unsigned long)(REC->usockvec))
`

const FormatExitSocketpair = `name: sys_exit_socketpair
ID: 1815
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatPipe = `name: sys_enter_pipe
ID: 873
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int * fildes;	offset:16;	size:8;	signed:0;

print fmt: "fildes: 0x%08lx", ((unsigned long)(REC->fildes))
`

const FormatExitPipe = `name: sys_exit_pipe
ID: 872
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatPipe2 = `name: sys_enter_pipe2
ID: 875
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int * fildes;	offset:16;	size:8;	signed:0;
	field:int flags;	offset:24;	size:8;	signed:0;

print fmt: "fildes: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->fildes)), ((unsigned long)(REC->flags))
`

const FormatExitPipe2 = `name: sys_exit_pipe2
ID: 874
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatEventfd = `name: sys_enter_eventfd
ID: 1095
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int count;	offset:16;	size:8;	signed:0;

print fmt: "count: 0x%08lx", ((unsigned long)(REC->count))
`

const FormatExitEventfd = `name: sys_exit_eventfd
ID: 1094
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatEventfd2 = `name: sys_enter_eventfd2
ID: 1097
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:unsigned int count;	offset:16;	size:8;	signed:0;
	field:int flags;	offset:24;	size:8;	signed:0;

print fmt: "count: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->count)), ((unsigned long)(REC->flags))
`

const FormatExitEventfd2 = `name: sys_exit_eventfd2
ID: 1096
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

const FormatEpollCtl = `name: sys_enter_epoll_ctl
ID: 1079
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int epfd;	offset:16;	size:8;	signed:0;
	field:int op;	offset:24;	size:8;	signed:0;
	field:int fd;	offset:32;	size:8;	signed:0;
	field:struct epoll_event * event;	offset:40;	size:8;	signed:0;

print fmt: "epfd: 0x%08lx, op: 0x%08lx, fd: 0x%08lx, event: 0x%08lx", ((unsigned long)(REC->epfd)), ((unsigned long)(REC->op)), ((unsigned long)(REC->fd)), ((unsigned long)(REC->event))
`

const FormatExitEpollCtl = `name: sys_exit_epoll_ctl
ID: 1078
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatEpollWait = `name: sys_enter_epoll_wait
ID: 1077
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int epfd;	offset:16;	size:8;	signed:0;
	field:struct epoll_event * events;	offset:24;	size:8;	signed:0;
	field:int maxevents;	offset:32;	size:8;	signed:0;
	field:int timeout;	offset:40;	size:8;	signed:0;

print fmt: "epfd: 0x%08lx, events: 0x%08lx, maxevents: 0x%08lx, timeout: 0x%08lx", ((unsigned long)(REC->epfd)), ((unsigned long)(REC->events)), ((unsigned long)(REC->maxevents)), ((unsigned long)(REC->timeout))
`

const FormatExitEpollWait = `name: sys_exit_epoll_wait
ID: 1076
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatEpollPwait = `name: sys_enter_epoll_pwait
ID: 1075
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int epfd;	offset:16;	size:8;	signed:0;
	field:struct epoll_event * events;	offset:24;	size:8;	signed:0;
	field:int maxevents;	offset:32;	size:8;	signed:0;
	field:int timeout;	offset:40;	size:8;	signed:0;
	field:sigset_t * sigmask;	offset:48;	size:8;	signed:0;
	field:size_t sigsetsize;	offset:56;	size:8;	signed:0;

print fmt: "epfd: 0x%08lx, events: 0x%08lx, maxevents: 0x%08lx, timeout: 0x%08lx, sigmask: 0x%08lx, sigsetsize: 0x%08lx", ((unsigned long)(REC->epfd)), ((unsigned long)(REC->events)), ((unsigned long)(REC->maxevents)), ((unsigned long)(REC->timeout)), ((unsigned long)(REC->sigmask)), ((unsigned long)(REC->sigsetsize))
`

const FormatExitEpollPwait = `name: sys_exit_epoll_pwait
ID: 1074
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatEpollPwait2 = `name: sys_enter_epoll_pwait2
ID: 1073
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int epfd;	offset:16;	size:8;	signed:0;
	field:struct epoll_event * events;	offset:24;	size:8;	signed:0;
	field:int maxevents;	offset:32;	size:8;	signed:0;
	field:const struct __kernel_timespec * timeout;	offset:40;	size:8;	signed:0;
	field:const sigset_t * sigmask;	offset:48;	size:8;	signed:0;
	field:size_t sigsetsize;	offset:56;	size:8;	signed:0;

print fmt: "epfd: 0x%08lx, events: 0x%08lx, maxevents: 0x%08lx, timeout: 0x%08lx, sigmask: 0x%08lx, sigsetsize: 0x%08lx", ((unsigned long)(REC->epfd)), ((unsigned long)(REC->events)), ((unsigned long)(REC->maxevents)), ((unsigned long)(REC->timeout)), ((unsigned long)(REC->sigmask)), ((unsigned long)(REC->sigsetsize))
`

const FormatExitEpollPwait2 = `name: sys_exit_epoll_pwait2
ID: 1072
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

const FormatPoll = `name: sys_enter_poll
ID: 915
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:struct pollfd * ufds;	offset:16;	size:8;	signed:0;
	field:unsigned int nfds;	offset:24;	size:8;	signed:0;
	field:int timeout;	offset:32;	size:8;	signed:0;
`

const FormatExitPoll = `name: sys_exit_poll
ID: 914
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;
`

const FormatPpoll = `name: sys_enter_ppoll
ID: 913
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:struct pollfd * ufds;	offset:16;	size:8;	signed:0;
	field:unsigned int nfds;	offset:24;	size:8;	signed:0;
	field:const struct __kernel_timespec * tmo_p;	offset:32;	size:8;	signed:0;
	field:const sigset_t * sigmask;	offset:40;	size:8;	signed:0;
	field:size_t sigsetsize;	offset:48;	size:8;	signed:0;
`

const FormatExitPpoll = `name: sys_exit_ppoll
ID: 912
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;
`

const FormatSelect = `name: sys_enter_select
ID: 919
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int n;	offset:16;	size:8;	signed:0;
	field:fd_set * inp;	offset:24;	size:8;	signed:0;
	field:fd_set * outp;	offset:32;	size:8;	signed:0;
	field:fd_set * exp;	offset:40;	size:8;	signed:0;
	field:struct timeval * tvp;	offset:48;	size:8;	signed:0;
`

const FormatExitSelect = `name: sys_exit_select
ID: 918
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;
`

const FormatPselect6 = `name: sys_enter_pselect6
ID: 917
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int n;	offset:16;	size:8;	signed:0;
	field:fd_set * inp;	offset:24;	size:8;	signed:0;
	field:fd_set * outp;	offset:32;	size:8;	signed:0;
	field:fd_set * exp;	offset:40;	size:8;	signed:0;
	field:const struct __kernel_timespec * tsp;	offset:48;	size:8;	signed:0;
	field:void * sig;	offset:56;	size:8;	signed:0;
`

const FormatExitPselect6 = `name: sys_exit_pselect6
ID: 916
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;
`

const FormatNanosleep = `name: sys_enter_nanosleep
ID: 441
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:struct __kernel_timespec * rqtp;	offset:16;	size:8;	signed:0;
	field:struct __kernel_timespec * rmtp;	offset:24;	size:8;	signed:0;
`

const FormatExitNanosleep = `name: sys_exit_nanosleep
ID: 440
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;
`

const FormatClockNanosleep = `name: sys_enter_clock_nanosleep
ID: 447
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:clockid_t which_clock;	offset:16;	size:8;	signed:0;
	field:int flags;	offset:24;	size:8;	signed:0;
	field:const struct __kernel_timespec * rqtp;	offset:32;	size:8;	signed:0;
	field:struct __kernel_timespec * rmtp;	offset:40;	size:8;	signed:0;
`

const FormatExitClockNanosleep = `name: sys_exit_clock_nanosleep
ID: 446
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;
`

// epoll_create(int size) — single argument, no flags.
const FormatEpollCreate = `name: sys_enter_epoll_create
ID: 1451
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int size;	offset:16;	size:8;	signed:0;

print fmt: "size: 0x%08lx", ((unsigned long)(REC->size))
`

const FormatExitEpollCreate = `name: sys_exit_epoll_create
ID: 1450
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

// epoll_create1(int flags) — single argument carrying flags at args[0].
const FormatEpollCreate1 = `name: sys_enter_epoll_create1
ID: 1453
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int flags;	offset:16;	size:8;	signed:0;

print fmt: "flags: 0x%08lx", ((unsigned long)(REC->flags))
`

const FormatExitEpollCreate1 = `name: sys_exit_epoll_create1
ID: 1452
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

// pidfd_open(pid_t pid, unsigned int flags) — flags at args[1], not args[0].
const FormatPidfdOpen = `name: sys_enter_pidfd_open
ID: 1461
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:pid_t pid;	offset:16;	size:8;	signed:0;
	field:unsigned int flags;	offset:24;	size:8;	signed:0;

print fmt: "pid: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->pid)), ((unsigned long)(REC->flags))
`

const FormatExitPidfdOpen = `name: sys_exit_pidfd_open
ID: 1460
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

// FormatSignalfd4 is real sysfs data for signalfd4(2) captured from a Linux 7.0
// kernel. The raw syscall is signalfd4(int ufd, const sigset_t *mask, size_t
// sizemask, int flags): ufd at args[0], user_mask at args[1], sizemask at
// args[2], and crucially the flags (SFD_NONBLOCK/SFD_CLOEXEC) at args[3]. ior
// classifies it as KindEventfd (an fd-creating IPC syscall), so the generator
// must capture flags from args[3], never any earlier index.
const FormatSignalfd4 = `name: sys_enter_signalfd4
ID: 1087
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int ufd;	offset:16;	size:8;	signed:0;
	field:sigset_t * user_mask;	offset:24;	size:8;	signed:0;
	field:size_t sizemask;	offset:32;	size:8;	signed:0;
	field:int flags;	offset:40;	size:8;	signed:0;

print fmt: "ufd: 0x%08lx, user_mask: 0x%08lx, sizemask: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->ufd)), ((unsigned long)(REC->user_mask)), ((unsigned long)(REC->sizemask)), ((unsigned long)(REC->flags))
`

const FormatExitSignalfd4 = `name: sys_exit_signalfd4
ID: 1086
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

// FormatMkdirat is real sysfs data for mkdirat(2): the pathname argument sits
// at args[1], AFTER the dirfd at args[0]. Captured from a Linux 7.0 kernel,
// which also exposes the __data_loc __pathname_val trailing field. The
// generator must read the path from args[1] (the dfd at args[0] is NOT a path).
const FormatMkdirat = `name: sys_enter_mkdirat
ID: 899
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * pathname;	offset:24;	size:8;	signed:0;
	field:umode_t mode;	offset:32;	size:8;	signed:0;
	field:__data_loc char[] __pathname_val;	offset:40;	size:4;	signed:0;

print fmt: "dfd: 0x%08lx, pathname: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->pathname)), ((unsigned long)(REC->mode))
`

const FormatExitMkdirat = `name: sys_exit_mkdirat
ID: 898
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

// FormatMkdir is the sibling mkdir(2): it has NO dirfd, so the pathname is the
// first argument at args[0]. This is the key contrast with mkdirat above and
// guards against accidentally sharing a single arg index between the two.
const FormatMkdir = `name: sys_enter_mkdir
ID: 901
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

const FormatExitMkdir = `name: sys_exit_mkdir
ID: 900
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

// FormatBind / FormatExitBind mirror the real kernel tracepoint format for
// bind(2): int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen).
// The leading "fd" field (sockfd at args[0]) makes it a KindFd fd_event; the
// addr pointer and addrlen must NOT be captured. On exit bind returns 0/-1,
// which is UNCLASSIFIED (a plain ret_event, no read/write/transfer byte count).
const FormatBind = `name: sys_enter_bind
ID: 1843
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fd;	offset:16;	size:8;	signed:0;
	field:struct sockaddr * umyaddr;	offset:24;	size:8;	signed:0;
	field:int addrlen;	offset:32;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, umyaddr: 0x%08lx, addrlen: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->umyaddr)), ((unsigned long)(REC->addrlen))
`

const FormatExitBind = `name: sys_exit_bind
ID: 1842
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

// FormatGetsockname / FormatExitGetsockname mirror the real kernel tracepoint
// format for getsockname(2):
//
//	int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen).
//
// getsockname returns the local address a socket is bound to. The leading "fd"
// field (sockfd at args[0]) makes the enter a KindFd fd_event; both the addr
// output pointer (usockaddr, args[1]) and the addrlen in/out pointer
// (usockaddr_len, args[2]) are userspace pointers we do NOT capture — note that
// unlike bind(2)'s by-value addrlen, getsockname's third arg is itself a
// pointer. On exit getsockname returns 0/-1, which is UNCLASSIFIED (a plain
// ret_event, no read/write/transfer byte count). Field names/offsets are copied
// verbatim from /sys/kernel/tracing/events/syscalls/sys_enter_getsockname.
const FormatGetsockname = `name: sys_enter_getsockname
ID: 1833
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fd;	offset:16;	size:8;	signed:0;
	field:struct sockaddr * usockaddr;	offset:24;	size:8;	signed:0;
	field:int * usockaddr_len;	offset:32;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, usockaddr: 0x%08lx, usockaddr_len: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->usockaddr)), ((unsigned long)(REC->usockaddr_len))
`

const FormatExitGetsockname = `name: sys_exit_getsockname
ID: 1832
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`

// FormatKexecFileLoad / FormatExitKexecFileLoad mirror the real kernel
// tracepoint format for kexec_file_load(2):
//
//	long kexec_file_load(int kernel_fd, int initrd_fd,
//	                     unsigned long cmdline_len, const char *cmdline,
//	                     unsigned long flags)
//
// kexec_file_load loads a new kernel (and optional initrd) from open file
// descriptors so it can later be booted by reboot(2); it returns 0 on success
// or -1 on error. The leading "kernel_fd" field (args[0]) makes the enter a
// KindFd fd_event capturing ev->fd = args[0] — the FieldNumber("fd") lookup
// finds no field literally named "fd" here, so generateExtraFd falls back to
// args[0], which IS kernel_fd. There are TWO fds (kernel_fd at args[0],
// initrd_fd at args[1]); by the single-fd KindFd convention only the first
// (kernel_fd) is captured. Critically, cmdline_ptr (args[3]) is a command-line
// STRING for the new kernel, NOT a filesystem path, so it must NOT be read with
// bpf_probe_read_user_str. On exit kexec_file_load returns 0/-1, which is
// UNCLASSIFIED (a plain ret_event, no read/write/transfer byte count). Field
// names/offsets are copied verbatim from
// /sys/kernel/tracing/events/syscalls/sys_enter_kexec_file_load.
const FormatKexecFileLoad = `name: sys_enter_kexec_file_load
ID: 508
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int kernel_fd;	offset:16;	size:8;	signed:0;
	field:int initrd_fd;	offset:24;	size:8;	signed:0;
	field:unsigned long cmdline_len;	offset:32;	size:8;	signed:0;
	field:const char * cmdline_ptr;	offset:40;	size:8;	signed:0;
	field:unsigned long flags;	offset:48;	size:8;	signed:0;

print fmt: "kernel_fd: 0x%08lx, initrd_fd: 0x%08lx, cmdline_len: 0x%08lx, cmdline_ptr: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->kernel_fd)), ((unsigned long)(REC->initrd_fd)), ((unsigned long)(REC->cmdline_len)), ((unsigned long)(REC->cmdline_ptr)), ((unsigned long)(REC->flags))
`

const FormatExitKexecFileLoad = `name: sys_exit_kexec_file_load
ID: 507
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "0x%lx", REC->ret
`
