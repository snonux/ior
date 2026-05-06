#!/usr/bin/env bash
# Refreshes the sudo timestamp every minute so a long demo regen never trips a
# password prompt. Intended to be backgrounded by `mage demo` and killed at the
# end of the run.

set -u

trap 'exit 0' TERM INT

while true; do
    sudo -n true 2>/dev/null || exit 1
    sleep 60
done
