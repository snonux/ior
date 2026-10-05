# A mismatched PID/TID produces a warning badge and a readable Stream row.
Output docs/tutorial/assets/18-stream-warnings.gif
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

Type "sudo -n ./ior -pid 1 -tid $$"
Enter
Sleep 6s
Type "2"
Sleep 3s
Type "7"
Sleep 1s
Space
Type "g"
Sleep 2s
Enter
Sleep 5s
Escape
Type "q"
Sleep 1s
