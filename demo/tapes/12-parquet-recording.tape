# 12-parquet-recording: start parquet recording (R), accept default filename (Enter), dwell, stop (R), exit, ls the file.
Output demo/assets/12-parquet-recording.gif
Set Shell "bash"
Set Padding 20

Hide
Type "cd $(mktemp -d -t ior-demo-XXXX) && clear"
Enter
Sleep 300ms
Show

Type "sudo -n /home/paul/git/ior/ior"
Enter
Sleep 5s
Enter
Sleep 4s
Type "R"
Sleep 1500ms
Enter
Sleep 4s
Screenshot demo/assets/screenshot-recording-active.png
Type "R"
Sleep 1500ms
Type "q"
Sleep 1s
Type "ls -lh ior-recording-*.parquet"
Enter
Sleep 2s
