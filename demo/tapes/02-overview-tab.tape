# 02-overview-tab: dashboard Overview tab — sparkline, top syscalls, top paths fill in.
# Key 2 switches to Overview (key 1 is Flamegraph, the default landing tab).
Output demo/assets/02-overview-tab.gif
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
Type "2"
Sleep 6s
Screenshot demo/assets/screenshot-overview.png
Sleep 1s
Type "q"
Sleep 1s
