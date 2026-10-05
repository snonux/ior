# 01-launch: cold start of ior. Shows the PID picker, then the default landing tab
# (Flamegraph) once Enter selects "All PIDs".
Output docs/tutorial/assets/01-launch.gif
Set Shell "bash"
Set Padding 20

Hide
Type 'cd "$IOR_DEMO_DIR" && clear'
Enter
Sleep 300ms
Show

Type "sudo -n ./ior"
Enter
Sleep 4500ms
Screenshot docs/tutorial/assets/screenshot-pidpicker.png
Sleep 1500ms
Enter
Sleep 5s
Screenshot docs/tutorial/assets/screenshot-dashboard.png
Sleep 2s
Type "q"
Sleep 1s
