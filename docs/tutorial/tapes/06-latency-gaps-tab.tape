# 06-latency-gaps-tab: latency + inter-syscall gap histograms (driven by dd writes).
# Key 6 switches to Latency.
Output demo/assets/06-latency-gaps-tab.gif
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
Type "6"
Sleep 8s
Screenshot demo/assets/screenshot-latency.png
Type "q"
Sleep 1s
