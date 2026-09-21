#!/usr/bin/env python3
"""Compare freshly generated BPF tracepoint handlers with the committed ones.

Usage:
    mage generateTracepointsCStdout > /tmp/gen_local.c
    scripts/compare-generated-handlers.py /tmp/gen_local.c internal/c/generated_tracepoints.c

Why this exists: `mage generate` is diff-gated on the derived result table and
refuses to run on a kernel that lacks syscalls the committed artifact contains.
Even where it does run, the `#define SYS_ENTER_X <id>` block carries
kernel-assigned tracepoint IDs, which legitimately differ between kernels, so a
plain `git diff` cannot tell "the generator reproduces the artifact" from "only
the IDs moved". This script compares handler BODIES by tracepoint name and
ignores the ID block, which is the question the audit gate actually asks.

Exit status: 0 when every handler present on both sides is byte-identical,
1 when at least one differs, 2 on a usage error. Handlers that exist on only one
side are reported but do not fail the comparison: they are syscalls one kernel
has and the other lacks.
"""

import re
import sys


def handlers(path):
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    found = {}
    for part in re.split(r"(?=^/// sys_)", source, flags=re.M):
        match = re.match(r"/// (sys_\w+) is a struct", part)
        if match:
            found[match.group(1)] = part.strip()
    return found


def syscall_names(tracepoints):
    return sorted({name.split("_", 2)[2] for name in tracepoints})


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    local, committed = handlers(argv[1]), handlers(argv[2])
    if not local or not committed:
        print("error: no handlers found in one of the inputs", file=sys.stderr)
        return 2

    shared = [name for name in local if name in committed]
    different = sorted(name for name in shared if local[name] != committed[name])
    only_local = set(local) - set(committed)
    only_committed = set(committed) - set(local)

    print(f"local handlers:      {len(local)}")
    print(f"committed handlers:  {len(committed)}")
    print(f"identical:           {len(shared) - len(different)}")
    print(f"different:           {len(different)}")
    for name in different:
        print(f"  DIFFERENT {name}")
    print(f"only in committed:   {len(only_committed)}  (syscalls this kernel lacks)")
    for name in syscall_names(only_committed):
        print(f"  {name}")
    print(f"only in local:       {len(only_local)}  (syscalls newer than the committed artifact)")
    for name in syscall_names(only_local):
        print(f"  {name}")
    return 1 if different else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
