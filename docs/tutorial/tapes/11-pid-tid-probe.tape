# 11-pid-tid-probe: re-open PID picker (p), TID picker (t), probe toggle dialog (o).
Output demo/assets/11-pid-tid-probe.gif
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
Type "p"
Sleep 2s
Down
Sleep 400ms
Down
Sleep 400ms
Screenshot demo/assets/screenshot-pidpicker-open.png
Escape
Sleep 1s
Type "t"
Sleep 2s
Screenshot demo/assets/screenshot-tidpicker.png
Escape
Sleep 1s
Type "o"
Sleep 2s
Down
Sleep 400ms
Down
Sleep 400ms
Screenshot demo/assets/screenshot-probes.png
Escape
Sleep 1s
Type "q"
Sleep 1s
