# TODO - Eventloop Test Coverage

## Remaining Helper Functions
- [x] Create helper functions for NameEvent (makeEnterNameEvent/makeExitNameEvent)
- [x] Create helper functions for NullEvent (makeEnterNullEvent/makeExitNullEvent)  
- [x] Create helper functions for Dup3Event (makeEnterDup3Event/makeExitDup3Event)

## Remaining Test Cases

### FdEvent Syscalls
- [x] Add test case for fsync syscall
- [x] Add test case for ftruncate syscall

### PathEvent Syscalls  
- [x] Add test case for unlink syscall
- [x] Add test case for creat syscall
- [x] Add test case for stat syscall
- [x] Add test case for access syscall

### NameEvent Syscalls
- [x] Add test case for rename syscall
- [x] Add test case for link syscall
- [x] Add test case for symlink syscall

### NullEvent Syscalls
- [x] Add test case for sync syscall
- [x] Add test case for io_uring_setup syscall

### Dup3Event Syscalls
- [x] Add test case for dup3 syscall

## Advanced Test Cases

### File Descriptor Lifecycle
- [x] Test that fd from openat is properly tracked in subsequent read/write/close operations
- [x] Test dup/dup2/dup3 creating new file descriptors
- [x] Test close removing fd from tracking
- [x] Test multiple file descriptors being tracked simultaneously

### Edge Cases
- [x] Test missing enter events (only exit event received)
- [x] Test missing exit events (only enter event received)
- [x] Test mismatched enter/exit pairs
- [x] Test out-of-order events
- [x] Test events from different threads/processes

### Filtering and Comm Tracking
- [ ] Test that comm names are properly propagated across syscalls
- [ ] Test filter behavior for each event type
- [ ] Test comm filter enable/disable functionality