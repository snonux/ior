# 06-latency-gaps-tab: latency + inter-syscall gap histograms (driven by dd writes).
# Key 6 switches to Latency.
Output docs/tutorial/assets/06-latency-gaps-tab.gif
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
Type "6"
Sleep 8s
Screenshot docs/tutorial/assets/screenshot-latency.png
Type "q"
Sleep 1s
