# TODO's

## FlameGraphs

More ideas

```
user;cmd_name;pid;tid;syscall_name count
user;cmd_name;pid;tid;syscall_name bytes

user:cmd_name;pid:tid;prev_syscall_name->syscall_name;duration  IN DIFFERENT COLOR
user:cmd_name;pid:tid;prev_syscall_name->syscall_name;fd;duration  IN DIFFERENT COLOR
user;cmd_name;pid;tid;syscall_name duration
user;cmd_name;pid;tid;syscall_name;fd duration

user;cmd_name;pid;tid;PATHMATCH;syscall_name duration
user;cmd_name;pid;tid;OTHER;syscall_name duration
```

`pathdecoded`? Maybe:

* By directory
* By mountpoint
* By device


Consider:

* File base path or mount point or device name
* Filename?
* Time spent between syscalls?
