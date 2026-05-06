# 09-stream-regex-search: regex search forward (/), n to advance, ? for backward.
# Key 7 switches to Stream.
Output demo/assets/09-stream-regex-search.gif
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
Space
Sleep 1s
Type "/"
Sleep 600ms
Type "openat"
Sleep 700ms
Enter
Sleep 1500ms
Type "n"
Sleep 800ms
Type "n"
Sleep 800ms
Screenshot demo/assets/screenshot-stream-search.png
Type "?"
Sleep 600ms
Type "stat"
Sleep 700ms
Enter
Sleep 1500ms
Type "q"
Sleep 1s
