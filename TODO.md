# TODO - I/O Riot NG Development Tasks

## High Priority (Core functionality)

### 1. Add unit test for FcntlEvent handling
- Test F_SETFL flag modification
- Test F_DUPFD file descriptor duplication  
- Test F_DUPFD_CLOEXEC with O_CLOEXEC flag
- Location: internal/eventloop.go:305

### 2. Implement byte count tracking for read/write syscalls
- Track number of bytes read/written in each I/O operation
- Add to flamegraph statistics
- Location: internal/flamegraph/counter.go:11

## Medium Priority (Additional syscalls)

### 3. Implement copy_file_range syscall
- Capture source and destination file descriptors
- Track byte count copied
- Location: internal/eventloop.go:353

### 4. Implement mmap/msync syscalls
- Track memory-mapped file operations
- Capture file descriptor and memory addresses
- Location: internal/eventloop.go:356

### 5. Implement sync_file_range syscall
- Capture file descriptor and range parameters
- Track selective file synchronization
- Location: internal/eventloop.go:358

## Low Priority (Less common syscalls)

### 6. Implement open_by_handle_at syscall
- Handle file access by handle
- Location: internal/eventloop.go:354

### 7. Implement name_to_handle_at syscall  
- Convert pathname to handle
- Location: internal/eventloop.go:355

### 8. Implement getcwd syscall
- Track current working directory queries
- Location: internal/eventloop.go:357

### 9. Add sys_enter_open_by_handle_at to BPF
- Update BPF tracepoint generation
- Location: internal/c/generate_tracepoints_c.raku:5

### 10. Enhance io_uring_enter capture with FD tracking
- Currently captured but without file descriptor context
- Location: internal/eventloop.go:359

## General Improvements

### 11. Write comprehensive unit tests
- Increase overall test coverage
- Location: internal/ior.go:21

### 12. Write integration tests
- Use C/Cgo to simulate real I/O operations
- Test end-to-end functionality
- Location: internal/ior.go:22

## Completed Tasks ✓

All previously listed test cases have been implemented:
- Helper functions for all event types
- Test cases for all basic syscalls
- File descriptor lifecycle tests
- Edge case handling tests
- Filtering and comm tracking tests