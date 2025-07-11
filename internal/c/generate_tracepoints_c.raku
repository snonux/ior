#!/usr/bin/env raku

use v6.d;

# TODO: Also add sys_enter_open_by_handler_at
# TOOD: creat is an open_event?
 
# Grammar to parse  /sys/kernel/tracing/events/syscalls/sys_{enter,exit}_*/format'
grammar SysTraceFormat {
    rule TOP { <whole-format-section>* }
    rule whole-format-section { <name> <id> <format> <print-fmt> }
    rule name { 'name:' <identifier> }
    rule id { 'ID:' <number> }
    rule format { 'format:' <field>* }

    rule field { 'field:' <field-elements> }
    rule field-elements { <field-declaration> <field-offset> <field-size> <field-signed> }
    rule field-declaration { <field-type>+ <identifier> ';' }

    token field-type { <-[ \t]> }
    token field-offset { 'offset:' <number> ';' }
    token field-size { 'size:' <number> ';' }
    token field-signed { 'signed:' <cbool> ';' }

    token identifier { <[a..zA..Z0..9_]>+ }
    token number { \d+ }
    token cbool { '0' | '1' }
    token print-fmt { 'print fmt' <-[\n]>+ "\n" }
}

class Field {
    has Str $.type is rw;
    has Str $.name is rw;
    has Int $.offset is rw;
    has Int $.size is rw;
    has Bool $.signed is rw;
}

role TracepointTemplate {
    method template(%vals --> Str) {
        my Bool \is-enter = %vals<name>.split('_')[1] eq 'enter';
        my Str \ctx-struct = is-enter ?? 'trace_event_raw_sys_enter' !! 'trace_event_raw_sys_exit';
        my Str @parts;

        @parts.push: qq:to/BPF_C_CODE/;
        /// {%vals<name>.lc} is a struct {%vals<event-struct>}
        SEC("tracepoint/syscalls/{%vals<name>}")
        int handle_{%vals<name>.lc}(struct {ctx-struct} *ctx) \{
            __u32 pid, tid;
            if (filter(&pid, &tid))
                return 0;

            struct {%vals<event-struct>} *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct {%vals<event-struct>}), 0);
            if (!ev)
                return 0;

            ev->event_type = {(is-enter ?? 'ENTER_' !! 'EXIT_') ~ %vals<event-struct>.uc};
            ev->trace_id = {%vals<name>.uc};
            ev->pid = pid;
            ev->tid = tid;
            ev->time = bpf_ktime_get_boot_ns();
        BPF_C_CODE

        @parts.push: %vals<extra> if %vals<extra>:exists;

        @parts.push: qq:to/BPF_C_CODE/;

            bpf_ringbuf_submit(ev, 0);
            return 0;
        \}
        BPF_C_CODE

        [~] @parts;
    }
}

class FdTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Str $extra = qq:to/BPF_C_CODE/;
            ev->fd = (__s32)ctx->args[0];
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'fd_event', :$extra ).hash );
    }
}

class Dup3Tracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Str $extra = qq:to/BPF_C_CODE/;
            ev->fd = (__s32)ctx->args[0];
            ev->flags = (__s32)ctx->args[2];
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'dup3_event', :$extra ).hash );
    }
}

class NameTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Int \oldname-field-number = %vals<format>.field-number('oldname');
        my Int \newname-field-number = %vals<format>.field-number('newname');
        my Str $extra = qq:to/BPF_C_CODE/;
            __builtin_memset(\&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));
            bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[{oldname-field-number}]);
            bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[{newname-field-number}]);
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'name_event', :$extra ).hash );
    }
}

class OpenTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Int \filename-field-number = %vals<format>.field-number('filename');
        my Int \flags-field-number = %vals<format>.field-number('flags');
        my Str $extra = qq:to/BPF_C_CODE/;
            __builtin_memset(\&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm));
            bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[{filename-field-number}]);
            bpf_get_current_comm(\&ev->comm, sizeof(ev->comm));
            ev->flags = {flags-field-number > -1 ?? ('ctx->args[' ~ flags-field-number ~ '];') !! '-1; // Probably OK'}
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'open_event', :$extra ).hash );
    }
}

class PathnameTracepoint does TracepointTemplate {
    has Str $.field-name is required;
    submethod new (Str $field-name) { self.bless: :$field-name }
    
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Int \field-number = %vals<format>.field-number($.field-name);
        my Str $extra = qq:to/BPF_C_CODE/;
            __builtin_memset(\&(ev->pathname), 0, sizeof(ev->pathname));
            bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[{field-number}]);
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'path_event', :$extra ).hash );
    }
}

role TracepointClassification {
    has %!map = 
        accept => 'noio',
        accept4 => 'noio',
        access => 'noio',
        acct => 'noio',
        add_key => 'noio',
        adjtimex => 'noio',
        alarm => 'noio',
        arch_prctl => 'noio',
        bind => 'noio',
        bpf => 'noio',
        brk => 'noio',
        cachestat => 'noio',
        capget => 'noio',
        capset => 'noio',
        chdir => 'noio',
        chmod => 'noio',
        chown => 'noio',
        chroot => 'noio',
        clock_adjtime => 'noio',
        clock_getres => 'noio',
        clock_gettime => 'noio',
        clock_nanosleep => 'noio',
        clock_settime => 'noio',
        clone => 'noio',
        clone3 => 'noio',
        close => 'noio',
        close_range => 'noio',
        connect => 'noio',
        copy_file_range => 'transfer',
        creat => 'noio',
        delete_module => 'noio',
        dup => 'noio',
        dup2 => 'noio',
        dup3 => 'noio',
        epoll_create => 'noio',
        epoll_create1 => 'noio',
        epoll_ctl => 'noio',
        epoll_pwait => 'noio',
        epoll_pwait2 => 'noio',
        epoll_wait => 'noio',
        eventfd => 'noio',
        eventfd2 => 'noio',
        execve => 'noio',
        execveat => 'noio',
        exit => 'noio',
        exit_group => 'noio',
        faccessat => 'noio',
        faccessat2 => 'noio',
        fadvise64 => 'noio',
        fallocate => 'noio',
        fanotify_init => 'noio',
        fanotify_mark => 'noio',
        fchdir => 'noio',
        fchmod => 'noio',
        fchmodat => 'noio',
        fchmodat2 => 'noio',
        fchown => 'noio',
        fchownat => 'noio',
        fcntl => 'noio',
        fdatasync => 'noio',
        fgetxattr => 'noio',
        finit_module => 'noio',
        flistxattr => 'noio',
        flock => 'noio',
        fork => 'noio',
        fremovexattr => 'noio',
        fsconfig => 'noio',
        fsetxattr => 'noio',
        fsmount => 'noio',
        fsopen => 'noio',
        fspick => 'noio',
        fstatfs => 'noio',
        fsync => 'noio',
        ftruncate => 'noio',
        futex => 'noio',
        futex_requeue => 'noio',
        futex_wait => 'noio',
        futex_waitv => 'noio',
        futex_wake => 'noio',
        futimesat => 'noio',
        get_mempolicy => 'noio',
        get_robust_list => 'noio',
        getcpu => 'noio',
        getcwd => 'noio',
        getdents => 'read',
        getdents64 => 'read',
        getegid => 'noio',
        geteuid => 'noio',
        getgid => 'noio',
        getgroups => 'noio',
        getitimer => 'noio',
        getpeername => 'noio',
        getpgid => 'noio',
        getpgrp => 'noio',
        getpid => 'noio',
        getppid => 'noio',
        getpriority => 'noio',
        getrandom => 'noio',
        getresgid => 'noio',
        getresuid => 'noio',
        getrlimit => 'noio',
        getrusage => 'noio',
        getsid => 'noio',
        getsockname => 'noio',
        getsockopt => 'noio',
        gettid => 'noio',
        gettimeofday => 'noio',
        getuid => 'noio',
        getxattr => 'noio',
        getxattrat => 'noio',
        init_module => 'noio',
        inotify_add_watch => 'noio',
        inotify_init => 'noio',
        inotify_init1 => 'noio',
        inotify_rm_watch => 'noio',
        io_cancel => 'noio',
        io_destroy => 'noio',
        io_getevents => 'noio',
        io_pgetevents => 'noio',
        io_setup => 'noio',
        io_submit => 'noio',
        io_uring_enter => 'noio',
        io_uring_register => 'noio',
        io_uring_setup => 'noio',
        ioctl => 'noio',
        ioperm => 'noio',
        iopl => 'noio',
        ioprio_get => 'noio',
        ioprio_set => 'noio',
        kcmp => 'noio',
        kexec_file_load => 'noio',
        kexec_load => 'noio',
        keyctl => 'noio',
        kill => 'noio',
        landlock_add_rule => 'noio',
        landlock_create_ruleset => 'noio',
        landlock_restrict_self => 'noio',
        lchown => 'noio',
        lgetxattr => 'noio',
        link => 'noio',
        linkat => 'noio',
        listen => 'noio',
        listmount => 'noio',
        listxattr => 'noio',
        listxattrat => 'noio',
        llistxattr => 'noio',
        lremovexattr => 'noio',
        lseek => 'noio',
        lsetxattr => 'noio',
        lsm_get_self_attr => 'noio',
        lsm_list_modules => 'noio',
        lsm_set_self_attr => 'noio',
        madvise => 'noio',
        map_shadow_stack => 'noio',
        mbind => 'noio',
        membarrier => 'noio',
        memfd_create => 'noio',
        memfd_secret => 'noio',
        migrate_pages => 'noio',
        mincore => 'noio',
        mkdir => 'noio',
        mkdirat => 'noio',
        mknod => 'noio',
        mknodat => 'noio',
        mlock => 'noio',
        mlock2 => 'noio',
        mlockall => 'noio',
        mmap => 'noio',
        modify_ldt => 'noio',
        mount => 'noio',
        mount_setattr => 'noio',
        move_mount => 'noio',
        move_pages => 'noio',
        mprotect => 'noio',
        mq_getsetattr => 'noio',
        mq_notify => 'noio',
        mq_open => 'noio',
        mq_timedreceive => 'noio',
        mq_timedsend => 'noio',
        mq_unlink => 'noio',
        mremap => 'noio',
        mseal => 'noio',
        msgctl => 'noio',
        msgget => 'noio',
        msgrcv => 'noio',
        msgsnd => 'noio',
        msync => 'noio',
        munlock => 'noio',
        munlockall => 'noio',
        munmap => 'noio',
        name_to_handle_at => 'noio',
        nanosleep => 'noio',
        newfstat => 'noio',
        newfstatat => 'noio',
        newlstat => 'noio',
        newstat => 'noio',
        newuname => 'noio',
        open => 'noio',
        open_by_handle_at => 'noio',
        open_tree => 'noio',
        open_tree_attr => 'noio',
        openat => 'noio',
        openat2 => 'noio',
        pause => 'noio',
        perf_event_open => 'noio',
        personality => 'noio',
        pidfd_getfd => 'noio',
        pidfd_open => 'noio',
        pidfd_send_signal => 'noio',
        pipe => 'noio',
        pipe2 => 'noio',
        pivot_root => 'noio',
        pkey_alloc => 'noio',
        pkey_free => 'noio',
        pkey_mprotect => 'noio',
        poll => 'noio',
        ppoll => 'noio',
        prctl => 'noio',
        pread64 => 'read',
        preadv => 'read',
        preadv2 => 'read',
        prlimit64 => 'noio',
        process_madvise => 'noio',
        process_mrelease => 'noio',
        process_vm_readv => 'read',
        process_vm_writev => 'write',
        pselect6 => 'noio',
        ptrace => 'noio',
        pwrite64 => 'write',
        pwritev => 'write',
        pwritev2 => 'write',
        quotactl => 'noio',
        quotactl_fd => 'noio',
        read => 'read',
        readahead => 'noio',
        readlink => 'read',
        readlinkat => 'read',
        readv => 'read',
        reboot => 'noio',
        recvfrom => 'read',
        recvmmsg => 'read',
        recvmsg => 'read',
        remap_file_pages => 'noio',
        removexattr => 'noio',
        removexattrat => 'noio',
        rename => 'noio',
        renameat => 'noio',
        renameat2 => 'noio',
        request_key => 'noio',
        restart_syscall => 'noio',
        rmdir => 'noio',
        rseq => 'noio',
        rt_sigaction => 'noio',
        rt_sigpending => 'noio',
        rt_sigprocmask => 'noio',
        rt_sigqueueinfo => 'noio',
        rt_sigreturn => 'noio',
        rt_sigsuspend => 'noio',
        rt_sigtimedwait => 'noio',
        rt_tgsigqueueinfo => 'noio',
        sched_get_priority_max => 'noio',
        sched_get_priority_min => 'noio',
        sched_getaffinity => 'noio',
        sched_getattr => 'noio',
        sched_getparam => 'noio',
        sched_getscheduler => 'noio',
        sched_rr_get_interval => 'noio',
        sched_setaffinity => 'noio',
        sched_setattr => 'noio',
        sched_setparam => 'noio',
        sched_setscheduler => 'noio',
        sched_yield => 'noio',
        seccomp => 'noio',
        select => 'noio',
        semctl => 'noio',
        semget => 'noio',
        semop => 'noio',
        semtimedop => 'noio',
        sendfile64 => 'transfer',
        sendmmsg => 'write',
        sendmsg => 'write',
        sendto => 'write',
        set_mempolicy => 'noio',
        set_mempolicy_home_node => 'noio',
        set_robust_list => 'noio',
        set_tid_address => 'noio',
        setdomainname => 'noio',
        setfsgid => 'noio',
        setfsuid => 'noio',
        setgid => 'noio',
        setgroups => 'noio',
        sethostname => 'noio',
        setitimer => 'noio',
        setns => 'noio',
        setpgid => 'noio',
        setpriority => 'noio',
        setregid => 'noio',
        setresgid => 'noio',
        setresuid => 'noio',
        setreuid => 'noio',
        setrlimit => 'noio',
        setsid => 'noio',
        setsockopt => 'noio',
        settimeofday => 'noio',
        setuid => 'noio',
        setxattr => 'noio',
        setxattrat => 'noio',
        shmat => 'noio',
        shmctl => 'noio',
        shmdt => 'noio',
        shmget => 'noio',
        shutdown => 'noio',
        sigaltstack => 'noio',
        signalfd => 'noio',
        signalfd4 => 'noio',
        socket => 'noio',
        socketpair => 'noio',
        splice => 'transfer',
        statfs => 'noio',
        statmount => 'noio',
        statx => 'noio',
        swapoff => 'noio',
        swapon => 'noio',
        symlink => 'noio',
        symlinkat => 'noio',
        sync => 'noio',
        sync_file_range => 'noio',
        syncfs => 'noio',
        sysfs => 'noio',
        sysinfo => 'noio',
        syslog => 'noio',
        tee => 'transfer',
        tgkill => 'noio',
        time => 'noio',
        timer_create => 'noio',
        timer_delete => 'noio',
        timer_getoverrun => 'noio',
        timer_gettime => 'noio',
        timer_settime => 'noio',
        timerfd_create => 'noio',
        timerfd_gettime => 'noio',
        timerfd_settime => 'noio',
        times => 'noio',
        tkill => 'noio',
        truncate => 'noio',
        umask => 'noio',
        umount => 'noio',
        unlink => 'noio',
        unlinkat => 'noio',
        unshare => 'noio',
        uretprobe => 'noio',
        userfaultfd => 'noio',
        ustat => 'noio',
        utime => 'noio',
        utimensat => 'noio',
        utimes => 'noio',
        vfork => 'noio',
        vhangup => 'noio',
        vmsplice => 'transfer',
        wait4 => 'noio',
        waitid => 'noio',
        write => 'write',
        writev => 'write';

    method classify-tracepoint(Str \name --> Str) {
        my Str \syscall = name.subst(/^SYS_EXIT_/, '').lc;
        die "Syscall '{syscall}' for tracepoint '{name}' not found in classification map"
            unless %!map<syscall>:exists;
        given %!map{syscall} {
            when 'read'  { 'READ_CLASSIFIED' }
            when 'write' { 'WRITE_CLASSIFIED' }
            default      { 'OTHER_CLASSIFIED' }
        }
    }
}

class RetTracepoint does TracepointTemplate does TracepointClassification {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Str $extra = qq:to/BPF_C_CODE/;
            ev->ret = ctx->ret;
            ev->ret_type = {self.classify-tracepoint: %vals<name>};
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'ret_event', :$extra ).hash );
    }
}

class NullTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        self.template: %vals.append( ( event-struct => 'null_event' ).hash );
    }
}

class FcntlTracepoint does TracepointTemplate {
    method generate-bpf-c-tracepoint(%vals --> Str) {
        my Int \fd-field-number = %vals<format>.field-number('fd');
        my Int \cmd-field-number = %vals<format>.field-number('cmd');
        my Int \arg-field-number = %vals<format>.field-number('arg');
        my Str $extra = qq:to/BPF_C_CODE/;
            ev->fd = {'ctx->args[' ~ fd-field-number ~ ']'};
            ev->cmd = {'ctx->args[' ~ cmd-field-number ~ ']'};
            ev->arg = {'ctx->args[' ~ arg-field-number ~ ']'};
        BPF_C_CODE
        self.template: %vals.append( ( event-struct => 'fcntl_event', :$extra ).hash );
    }
}

class Format {
    has Field @!internal-fields; # Fields not accessible from raw tracepoints.
    has Field @!external-fields; # Fields accessible from raw tracepoints.
    has Bool $!is-external = False; # Track internal/external field sections.
    has Str $.name is rw;
    has Int $.id is rw;
    has $.format-impl;

    method push(Field \field) {
        $!is-external = True if field.name eq '__syscall_nr'; 

        if $!is-external {
            push @!external-fields: field;
        } else {
            push @!internal-fields: field;
            return;
        }

        self.set-format-impl($.name, field.type, field.name) unless $!format-impl;
    }

    # Tracepoints to ignore
    multi method set-format-impl(Str $s where /^sys_enter_mknod/, $, $) { }
    multi method set-format-impl(Str $s where /^sys_enter_execve/, $, $) { }
    multi method set-format-impl(Str $s where /^sys_enter_accept/, $, $) { }
    multi method set-format-impl(Str $s where /^sys_enter_listen/, $, $) { }
    multi method set-format-impl(Str $s where /^sys_enter_epoll/, $, $) { }
    multi method set-format-impl(Str $s where /^sys_enter_.*recv/, $, $) { }
    multi method set-format-impl(Str $s where /^sys_enter_.*send/, $, $) { }
    multi method set-format-impl(Str $s where /^sys_enter_.*sock/, $, $) { }
    multi method set-format-impl(Str $s where /^sys_enter_.*inotify/, $, $) { }
    multi method set-format-impl(Str $s where /^sys_enter_.*pidfd/, $, $) { }
    multi method set-format-impl('sys_enter_bind', $, $) { }
    multi method set-format-impl('sys_enter_setns', $, $) { }
    multi method set-format-impl('sys_enter_shutdown', $, $) { }
    multi method set-format-impl('sys_enter_connect', $, $) { }
    multi method set-format-impl('sys_enter_fanotify_init', $, $) { }
    multi method set-format-impl('sys_enter_getpeername', $, $) { }

    # Explicitly map some tracepoints
    multi method set-format-impl(Str $s where /^sys_enter.*open.*/, 'const char *', 'filename') { $!format-impl = OpenTracepoint.new }
    multi method set-format-impl('sys_enter_fcntl', $, $) { $!format-impl = FcntlTracepoint.new }
    multi method set-format-impl('sys_enter_dup', 'unsigned int', 'fildes') { $!format-impl = FdTracepoint.new }
    multi method set-format-impl('sys_enter_dup2', 'unsigned int', 'oldfd') { $!format-impl = FdTracepoint.new }
    multi method set-format-impl('sys_enter_dup3', 'unsigned int', 'oldfd') { $!format-impl = Dup3Tracepoint.new }

    # Tracepoint groups by arguments
    multi method set-format-impl($, Str $type where { $_ eq 'unsigned int' || $_ eq 'unsigned long' || $_ eq 'int' }, 'fd') { 
        $!format-impl = FdTracepoint.new 
    }
    multi method set-format-impl($, 'const char *', 'newname') { $!format-impl = NameTracepoint.new }
    multi method set-format-impl($, 'const char *', 'pathname') { $!format-impl = PathnameTracepoint.new('pathname') }
    multi method set-format-impl($, 'const char *', 'path') { $!format-impl = PathnameTracepoint.new('path') }
    multi method set-format-impl($, 'const char *', 'filename') { $!format-impl = PathnameTracepoint.new('filename') }
    multi method set-format-impl($, 'long', 'ret') { $!format-impl = RetTracepoint.new }

    # Async I/O, at least capture the count and the durations
    multi method set-format-impl('sys_enter_syslog', $, $) { $!format-impl = NullTracepoint.new }
    multi method set-format-impl('sys_enter_sync', $, $) { $!format-impl = NullTracepoint.new }
    multi method set-format-impl(Str $s where /^sys_enter_io_/, $, $) { $!format-impl = NullTracepoint.new }

    # All remaining tracepoints are ignored
    multi method set-format-impl($, $, $) { }

    method generate-c-constant returns Str { "#define {$!name.uc} {$!id}" }
    method generate-bpf-c-tracepoint returns Str { $!format-impl.generate-bpf-c-tracepoint: (format => self, :$!name).hash }

    method field-number(Str \field-name) { (@!external-fields.first(*.name eq field-name, :k) // 0) - 1 }
    method can-generate returns Bool { so $!format-impl.^can('generate-bpf-c-tracepoint') }

    method enter-reject returns Bool { $!format-impl !~~ any(
        FdTracepoint, NameTracepoint, OpenTracepoint, PathnameTracepoint, FcntlTracepoint, NullTracepoint, Dup3Tracepoint
    ) }
}

class SysTraceFormatActions {
    has Hash %!formats;
    has Format $!current-format = Format.new;
    has Field $!current-field = Field.new;

    method TOP($/) { make %!formats }

    method whole-format-section($/) {
        my ($, \enter-exit, \what) = $!current-format.name.split('_', 3);
        %!formats{what}{enter-exit} = $!current-format;
        $!current-format = Format.new;
    }

    method name($/) { $!current-format.name = ~$/<identifier> }
    method id($/) { $!current-format.id = +$/<number> }

    method field-declaration($/) {
        $!current-field.name = ~$/<identifier>;
        $!current-field.type = $/<field-type>.join('').trim-trailing;
        $!current-format.push($!current-field);
        $!current-field = Field.new;
    }

    method field-offset($/) { $!current-field.offset = +$/<number> }
    method field-size($/) { $!current-field.size = +$/<number> }
    method field-signed($/) { $!current-field.signed = +$/<cbool> == 0 ?? False !! True }
}

say qq:to/BPF_C_CODE/;
// Code generated - don't change manually!
BPF_C_CODE

my Format @formats = gather for
    SysTraceFormat.parse($*IN.slurp, actions => SysTraceFormatActions.new).made.values -> %syscall {

    if !all(%syscall.values.map(*.can-generate)) {
        say "/// Ignoring {%syscall.values.map(*.name).sort} as possibly not file I/O related";
        next;
    } elsif %syscall<enter>.enter-reject {
        say "/// Ignoring {%syscall.values.map(*.name).sort} as enter-rejected";
        next;   
    }

    .take for %syscall.values;
}

@formats .= sort({ $^b.id cmp $^a.id });

say qq:to/BPF_C_CODE/;

{@formats.map(*.generate-c-constant).join("\n")}

{@formats.map(*.generate-bpf-c-tracepoint).join("\n")}
BPF_C_CODE
