#!/usr/bin/env bash
# Refreshes the sudo timestamp every minute so a long demo regen never trips a
# password prompt. Intended to be backgrounded by `mage demo` and killed at the
# end of the run.

set -u

# The sleep runs in the background and is waited for: bash defers a trap until
# the foreground command returns, so a foreground `sleep 60` made `mage demo`
# stall for the rest of that minute when it stopped the keepalive.
sleep_pid=
trap '[ -n "$sleep_pid" ] && kill "$sleep_pid" 2>/dev/null; exit 0' TERM INT

while true; do
    sudo -n true 2>/dev/null || exit 1
    sleep 60 &
    sleep_pid=$!
    wait "$sleep_pid"
done
