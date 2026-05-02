# 03-syscalls-tab: sortable syscalls table, j/k to scroll, s/S to sort/reverse-sort.
# Key 3 switches to Syscalls.
Output demo/assets/03-syscalls-tab.gif
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
Type "3"
Sleep 3s
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 800ms
Type "k"
Sleep 600ms
Right
Sleep 600ms
Type "s"
Sleep 1500ms
Type "S"
Sleep 2s
Screenshot demo/assets/screenshot-syscalls.png
Type "q"
Sleep 1s
