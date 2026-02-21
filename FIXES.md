## Plan
1. Prevent `openat2` file tracking from panicking on unknown flags by allowing `-1` (unknown) flags in userland and covering it with a focused test.
2. Decide whether to enable `name_to_handle_at`/`open_by_handle_at` tracing or remove the correlation logic if the tracepoints stay excluded.
3. Add `close_range` handling that removes all fds in the range from the fd table.
4. Improve `io_uring_*` attribution by correlating setup/enter operations with returned fds or otherwise marking them as non-file-backed operations.
