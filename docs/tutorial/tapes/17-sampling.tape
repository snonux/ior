# TUI sampling: per-family rates, per-syscall override, counts and traced gaps.
Output docs/tutorial/assets/17-sampling.gif
Set Shell "bash"
Set Width 1600
Set Height 900
Set FontSize 16
Set Padding 20

Hide
Type 'cd "$IOR_DEMO_DIR" && clear'
Enter
Sleep 300ms
Show

Type "sudo -n ./ior -trace-families FS,Time,Misc -syscall-sampling-families Time=100,Misc=0 -syscall-sampling-syscalls read=10"
Enter
Sleep 5s
Enter
Sleep 4s
Type "3"
Sleep 4s
Type "6"
Sleep 5s
Type "q"
Sleep 1s
