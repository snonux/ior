package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sysvShmPayload is written into the attached SysV shared-memory segment so the
// scenario touches the mapping (forcing a real page fault) rather than just
// attaching and detaching it.
var sysvShmPayload = []byte("ior-sysv-shm")

// sysvShmBasic exercises the SysV shared-memory family end-to-end without any
// privileges: it creates a private anonymous segment (shmget IPC_PRIVATE),
// attaches it (shmat), writes a few bytes into the mapped region, detaches it
// (shmdt), and finally removes it (shmctl IPC_RMID). IPC_RMID is always issued
// (even on a partial failure) so the test never leaks a kernel IPC object.
func sysvShmBasic() error {
	const segSize = 4096
	shmid, err := shmGet(segSize)
	if err != nil {
		return err
	}
	// Guarantee the segment is removed regardless of how the rest fares; an
	// orphaned IPC_PRIVATE segment would otherwise leak until reboot.
	defer func() { _ = shmRemove(shmid) }()

	addr, err := shmAttach(shmid)
	if err != nil {
		return err
	}
	if err := shmWrite(addr, segSize); err != nil {
		_ = shmDetach(addr)
		return err
	}
	if err := shmDetach(addr); err != nil {
		return err
	}
	return nil
}

// shmGet creates a new private SysV shared-memory segment of the given size and
// returns its identifier.
func shmGet(size uintptr) (uintptr, error) {
	shmid, _, errno := syscall.Syscall(
		syscall.SYS_SHMGET,
		uintptr(unix.IPC_PRIVATE),
		size,
		uintptr(unix.IPC_CREAT|0o600),
	)
	if errno != 0 {
		return 0, fmt.Errorf("shmget: %w", errno)
	}
	return shmid, nil
}

// shmAttach attaches the segment into the address space and returns its base
// address. shmflg 0 requests a read/write mapping at a kernel-chosen address.
func shmAttach(shmid uintptr) (uintptr, error) {
	addr, _, errno := syscall.Syscall(syscall.SYS_SHMAT, shmid, 0, 0)
	if errno != 0 {
		return 0, fmt.Errorf("shmat: %w", errno)
	}
	return addr, nil
}

// shmWrite copies the payload into the mapped segment, faulting the page in so
// the workload genuinely uses the shared memory.
func shmWrite(addr, size uintptr) error {
	if uintptr(len(sysvShmPayload)) > size {
		return fmt.Errorf("shm payload (%d) exceeds segment size (%d)", len(sysvShmPayload), size)
	}
	seg := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(sysvShmPayload))
	copy(seg, sysvShmPayload)
	return nil
}

// shmDetach detaches the previously attached segment from the address space.
func shmDetach(addr uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_SHMDT, addr, 0, 0)
	if errno != 0 {
		return fmt.Errorf("shmdt: %w", errno)
	}
	return nil
}

// shmRemove marks the segment for destruction (IPC_RMID); the kernel frees it
// once the last attachment is gone.
func shmRemove(shmid uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_SHMCTL, shmid, uintptr(unix.IPC_RMID), 0)
	if errno != 0 {
		return fmt.Errorf("shmctl IPC_RMID: %w", errno)
	}
	return nil
}

// sysvMsgText is the message body copied into and read back out of the SysV
// message queue. Its length (NOT including mtype) is the msgsz passed to
// msgsnd/msgrcv.
var sysvMsgText = []byte("ior-sysv-msg")

// sysvMsgbuf mirrors the kernel's `struct msgbuf`: an 8-byte signed message
// type (must be > 0 for msgsnd) followed by the message body. The body is sized
// to hold sysvMsgText.
type sysvMsgbuf struct {
	mtype int64
	mtext [16]byte
}

// sysvMsgBasic exercises the SysV message-queue family end-to-end: it creates a
// private queue (msgget IPC_PRIVATE), sends a small message (msgsnd), receives
// it back (msgrcv), and removes the queue (msgctl IPC_RMID). IPC_RMID is always
// issued so no kernel message queue leaks.
func sysvMsgBasic() error {
	msqid, err := msgGet()
	if err != nil {
		return err
	}
	// Guarantee removal even on a partial failure; an orphaned IPC_PRIVATE
	// queue would otherwise leak until reboot.
	defer func() { _ = msgRemove(msqid) }()

	if err := msgSend(msqid); err != nil {
		return err
	}
	return msgReceive(msqid)
}

// msgGet creates a new private SysV message queue and returns its identifier.
func msgGet() (uintptr, error) {
	msqid, _, errno := syscall.Syscall(
		syscall.SYS_MSGGET,
		uintptr(unix.IPC_PRIVATE),
		uintptr(unix.IPC_CREAT|0o600),
		0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("msgget: %w", errno)
	}
	return msqid, nil
}

// msgSend enqueues a single message. msgsz counts only the message body
// (mtext), excluding the leading mtype field.
func msgSend(msqid uintptr) error {
	buf := sysvMsgbuf{mtype: 1}
	copy(buf.mtext[:], sysvMsgText)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_MSGSND,
		msqid,
		uintptr(unsafe.Pointer(&buf)),
		uintptr(len(sysvMsgText)),
		0, // msgflg: blocking send (the empty queue cannot be full)
		0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("msgsnd: %w", errno)
	}
	return nil
}

// msgReceive dequeues the message previously sent. msgtyp 0 returns the first
// message regardless of type; msgsz must be at least the body size sent.
func msgReceive(msqid uintptr) error {
	var buf sysvMsgbuf
	_, _, errno := syscall.Syscall6(
		syscall.SYS_MSGRCV,
		msqid,
		uintptr(unsafe.Pointer(&buf)),
		uintptr(len(sysvMsgText)),
		0, // msgtyp 0: first message in the queue
		0, // msgflg: blocking receive (a message is already enqueued)
		0,
	)
	if errno != 0 {
		return fmt.Errorf("msgrcv: %w", errno)
	}
	return nil
}

// msgRemove marks the message queue for immediate destruction (IPC_RMID).
func msgRemove(msqid uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MSGCTL, msqid, uintptr(unix.IPC_RMID), 0)
	if errno != 0 {
		return fmt.Errorf("msgctl IPC_RMID: %w", errno)
	}
	return nil
}

// sysvSembuf mirrors the kernel's `struct sembuf` used by semop:
// unsigned short sem_num; short sem_op; short sem_flg;
type sysvSembuf struct {
	semNum uint16
	semOp  int16
	semFlg int16
}

// sysvSemBasic exercises the SysV semaphore family end-to-end: it creates a
// private set of one semaphore (semget IPC_PRIVATE), increments it (semop
// sem_op=+1), then decrements it back to zero (semop sem_op=-1), and removes the
// set (semctl IPC_RMID). The increment happens first so the decrement can never
// block, keeping the scenario hang-free. IPC_RMID is always issued so no kernel
// semaphore set leaks.
func sysvSemBasic() error {
	semid, err := semGet()
	if err != nil {
		return err
	}
	// Guarantee removal even on a partial failure; an orphaned IPC_PRIVATE
	// semaphore set would otherwise leak until reboot.
	defer func() { _ = semRemove(semid) }()

	if err := semOp(semid, +1); err != nil {
		return err
	}
	return semOp(semid, -1)
}

// semGet creates a new private SysV semaphore set with a single semaphore and
// returns its identifier.
func semGet() (uintptr, error) {
	semid, _, errno := syscall.Syscall(
		syscall.SYS_SEMGET,
		uintptr(unix.IPC_PRIVATE),
		1, // nsems: one semaphore in the set
		uintptr(unix.IPC_CREAT|0o600),
	)
	if errno != 0 {
		return 0, fmt.Errorf("semget: %w", errno)
	}
	return semid, nil
}

// semOp applies a single operation to semaphore 0 of the set. A positive delta
// increments (never blocks); a negative delta decrements (only safe once the
// value is high enough, which the caller guarantees by incrementing first).
func semOp(semid uintptr, delta int16) error {
	sop := sysvSembuf{semNum: 0, semOp: delta, semFlg: 0}
	_, _, errno := syscall.Syscall(
		syscall.SYS_SEMOP,
		semid,
		uintptr(unsafe.Pointer(&sop)),
		1, // nsops: one operation
	)
	if errno != 0 {
		return fmt.Errorf("semop(%d): %w", delta, errno)
	}
	return nil
}

// semRemove removes the semaphore set (IPC_RMID). On Linux the union semun
// fourth argument is ignored for IPC_RMID, so passing 0 is safe.
func semRemove(semid uintptr) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SEMCTL,
		semid,
		0, // semnum: ignored for IPC_RMID
		uintptr(unix.IPC_RMID),
		0, // arg (union semun): ignored for IPC_RMID
		0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("semctl IPC_RMID: %w", errno)
	}
	return nil
}
