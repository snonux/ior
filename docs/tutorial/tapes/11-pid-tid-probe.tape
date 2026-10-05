# 11-pid-tid-probe: re-open PID picker (p), TID picker (t), probe toggle dialog (O).
Output docs/tutorial/assets/11-pid-tid-probe.gif
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
Type "p"
Sleep 2s
Down
Sleep 400ms
Down
Sleep 400ms
Screenshot docs/tutorial/assets/screenshot-pidpicker-open.png
Escape
Sleep 1s
Wait+Screen@30s /\[LIVE\]/
Type "t"
Wait+Screen@30s /Select TID/
Sleep 2s
Screenshot docs/tutorial/assets/screenshot-tidpicker.png
Escape
Sleep 1s
Wait+Screen@30s /\[LIVE\]/
Type "O"
Wait+Screen@30s /Probes \(/
Sleep 2s
Down
Sleep 400ms
Down
Sleep 400ms
Screenshot docs/tutorial/assets/screenshot-probes.png
Escape
Sleep 1s
Type "q"
Sleep 1s
