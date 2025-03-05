# TODO's

* Target OS is Rocky 9 and not Rocky 8 (can use a bhyve VM)
* More filters
  * By directory
  * By directory sub-match
  * By regex match of whole path
  * By syscall
* Output format so that it is compatible with the flamegraph grapher
* Capture more tracepoints? See comments in tracepoints.c's header.
* Automatic testing (integration tests)
* Performance benchmark...

## FlameGraphs

What format? What to visualize on the stack axis?

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
