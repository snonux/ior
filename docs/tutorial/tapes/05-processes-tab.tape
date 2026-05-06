# 05-processes-tab: processes tab, scroll, and reverse-sort.
# Key 5 switches to Processes.
Output demo/assets/05-processes-tab.gif
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
Type "5"
Sleep 3s
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 800ms
Type "S"
Sleep 2s
Screenshot demo/assets/screenshot-processes.png
Type "q"
Sleep 1s
