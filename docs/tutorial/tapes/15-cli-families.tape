# Family and syscall selectors: only matching calls reach plain CSV.
Output docs/tutorial/assets/15-cli-families.gif
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

Type "# Time: sleeps and timers"
Enter
Type "sudo -n ./ior -plain -trace-families Time -duration 3 2>/dev/null | head -n 7"
Enter
Sleep 5s
Type "# Memory: mappings and address ranges"
Enter
Type "sudo -n ./ior -plain -trace-kinds mmap,mem -duration 3 2>/dev/null | head -n 7"
Enter
Sleep 5s
Type "# Just file opens and closes"
Enter
Type "sudo -n ./ior -plain -trace-syscalls openat,close -duration 3 2>/dev/null | head -n 7"
Enter
Sleep 5s
