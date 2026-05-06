# 14-headless-modes: all three headless flows in one tape — -flamegraph -name (.ior.zst),
# -parquet (streaming rows), -plain (CSV to stdout). Each capped with -duration so the demo terminates.
Output demo/assets/14-headless-modes.gif
Set Shell "bash"
Set Padding 20

Hide
Type "cd $(mktemp -d -t ior-demo-XXXX) && clear"
Enter
Sleep 300ms
Show

Type "# 1) Aggregated native trace artifact (.ior.zst)"
Enter
Sleep 800ms
Type "sudo -n /home/paul/git/ior/ior -flamegraph -name demo-trace -duration 5"
Enter
Sleep 7s
Type "ls -lh demo-trace*.ior.zst"
Enter
Sleep 2s

Type "# 2) Per-row streaming Parquet"
Enter
Sleep 800ms
Type "sudo -n /home/paul/git/ior/ior -parquet demo.parquet -duration 5"
Enter
Sleep 7s
Type "ls -lh demo.parquet"
Enter
Sleep 2s

Type "# 3) Plain CSV to stdout (head only)"
Enter
Sleep 800ms
Type "sudo -n /home/paul/git/ior/ior -plain -duration 3 2>/dev/null | head -n 8"
Enter
Sleep 6s
