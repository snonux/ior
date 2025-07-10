# TODO - Eventloop Test Coverage

## Remaining Helper Functions
- [x] Create helper functions for NameEvent (makeEnterNameEvent/makeExitNameEvent)
- [x] Create helper functions for NullEvent (makeEnterNullEvent/makeExitNullEvent)  
- [x] Create helper functions for Dup3Event (makeEnterDup3Event/makeExitDup3Event)

## Remaining Test Cases

### FdEvent Syscalls
- [ ] Add test case for fsync syscall
- [ ] Add test case for ftruncate syscall

### PathEvent Syscalls  
- [ ] Add test case for unlink syscall
- [ ] Add test case for creat syscall
- [ ] Add test case for stat syscall
- [ ] Add test case for access syscall

### NameEvent Syscalls
- [ ] Add test case for rename syscall
- [ ] Add test case for link syscall
- [ ] Add test case for symlink syscall

### NullEvent Syscalls
- [ ] Add test case for sync syscall
- [ ] Add test case for io_uring_setup syscall

### Dup3Event Syscalls
- [ ] Add test case for dup3 syscall

## Advanced Test Cases

### File Descriptor Lifecycle
- [ ] Test that fd from openat is properly tracked in subsequent read/write/close operations
- [ ] Test dup/dup2/dup3 creating new file descriptors
- [ ] Test close removing fd from tracking
- [ ] Test multiple file descriptors being tracked simultaneously

### Edge Cases
- [ ] Test missing enter events (only exit event received)
- [ ] Test missing exit events (only enter event received)
- [ ] Test mismatched enter/exit pairs
- [ ] Test out-of-order events
- [ ] Test events from different threads/processes

### Filtering and Comm Tracking
- [ ] Test that comm names are properly propagated across syscalls
- [ ] Test filter behavior for each event type
- [ ] Test comm filter enable/disable functionality