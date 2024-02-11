#!/bin/bash

set -xeuf -o pipefail

find . -name ioriotng -exec rm -v {} \;
find . -name \*.o -exec rm -v {} \;
if [ -f internal/vmlinux.h ]; then
   rm -v internal/vmlinux.h 
fi
