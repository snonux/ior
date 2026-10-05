# 10-stream-csv-export: 'e', Enter to export the filtered stream snapshot, then ls the CSV.
# Key 7 switches to Stream.
Output docs/tutorial/assets/10-stream-csv-export.gif
Set Shell "bash"
Set Padding 20

Hide
Type 'cd "$IOR_DEMO_DIR" && clear'
Enter
Sleep 300ms
Show

Type "sudo -n ./ior"
Enter
Sleep 5s
Enter
Sleep 4s
Type "7"
Sleep 4s
Type "e"
Sleep 2s
Screenshot docs/tutorial/assets/screenshot-stream-export.png
Enter
Wait+Screen@30s /Exported:/
Sleep 2s
Escape
Type "q"
Sleep 1s
Wait+Line@30s /^> *$/
Type "ls -lh ior-stream-*.csv"
Enter
Sleep 2s
