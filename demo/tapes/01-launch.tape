# 01-launch: cold start of ior. Shows the PID picker, then the default landing tab
# (Flamegraph) once Enter selects "All PIDs".
Output demo/assets/01-launch.gif
Set Shell "bash"
Set Padding 20

Hide
Type "cd $(mktemp -d -t ior-demo-XXXX) && clear"
Enter
Sleep 300ms
Show

Type "sudo -n /home/paul/git/ior/ior"
Enter
Sleep 4500ms
Screenshot demo/assets/screenshot-pidpicker.png
Sleep 1500ms
Enter
Sleep 5s
Screenshot demo/assets/screenshot-dashboard.png
Sleep 2s
Type "q"
Sleep 1s
