# 07-stream-live: stream tab live-tailing rows.
# Key 7 switches to Stream.
Output demo/assets/07-stream-live.gif
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
Sleep 6s
Screenshot demo/assets/screenshot-stream-live.png
Type "q"
Sleep 1s
