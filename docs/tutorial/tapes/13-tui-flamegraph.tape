# 13-tui-flamegraph: in-TUI flamegraph view. The default landing tab (key `1`) is the
# live flamegraph. Workload running in the background drives real frame data.
# `-fields` and `-count` let you reshape stack ordering and the size metric.
Output docs/tutorial/assets/13-tui-flamegraph.gif
Set Shell "bash"
Set Padding 20

Hide
Type 'cd "$IOR_DEMO_DIR" && clear'
Enter
Sleep 300ms
Show

Type "sudo -n ./ior -fields comm,path,tracepoint -count count"
Enter
Sleep 5s
Enter
Sleep 8s
Screenshot docs/tutorial/assets/screenshot-flamegraph.png
Sleep 2s
Type "q"
Sleep 1s
