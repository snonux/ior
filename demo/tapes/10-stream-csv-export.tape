# 10-stream-csv-export: 'e' to export current filtered stream snapshot, then ls the CSV produced.
# Key 7 switches to Stream.
Output demo/assets/10-stream-csv-export.gif
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
Type "7"
Sleep 4s
Type "e"
Sleep 2s
Screenshot demo/assets/screenshot-stream-export.png
Sleep 1s
Type "q"
Sleep 1s
Type "ls -lh ior-stream-*.csv"
Enter
Sleep 2s
