# 04-files-tab: files tab plus directory-grouped view toggle (`d`).
# Key 4 switches to Files.
Output demo/assets/04-files-tab.gif
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
Type "4"
Sleep 3s
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Type "j"
Sleep 800ms
Type "d"
Sleep 3s
Screenshot demo/assets/screenshot-files-grouped.png
Type "d"
Sleep 2s
Type "q"
Sleep 1s
