# 08-stream-pause-filter: pause stream, navigate cells, push two filters onto the stack, undo with Esc.
# Key 7 switches to Stream.
Output demo/assets/08-stream-pause-filter.gif
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
Down
Sleep 300ms
Down
Sleep 300ms
Down
Sleep 800ms
Right
Sleep 500ms
Right
Sleep 500ms
Enter
Sleep 1500ms
Down
Sleep 400ms
Right
Sleep 400ms
Enter
Sleep 2s
Screenshot demo/assets/screenshot-stream-filtered.png
Escape
Sleep 1s
Escape
Sleep 1500ms
Type "q"
Sleep 1s
