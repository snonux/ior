package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	mqPayload = "ior-mq-payload"
)

type mqAttr struct {
	Flags   int64
	Maxmsg  int64
	Msgsize int64
	Curmsgs int64
	Pad     [4]int64
}

func mqPosixBasic() error {
	name := fmt.Sprintf("/ior-mq-%d-%d", os.Getpid(), time.Now().UnixNano())
	attr := mqAttr{Maxmsg: 8, Msgsize: 128}
	mqd, err := mqOpen(name, syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR, 0o600, &attr)
	if err != nil {
		return err
	}
	defer syscall.Close(mqd) //nolint:errcheck
	defer mqUnlink(name)     //nolint:errcheck

	if err := mqNotify(mqd); err != nil {
		return err
	}
	if err := mqGetsetattr(mqd); err != nil {
		return err
	}

	deadline := time.Now().Add(2 * time.Second)
	if err := mqTimedsend(mqd, []byte(mqPayload), 0, deadline); err != nil {
		return err
	}

	buf := make([]byte, 128)
	n, err := mqTimedreceive(mqd, buf, deadline)
	if err != nil {
		return err
	}
	if got := string(buf[:n]); got != mqPayload {
		return fmt.Errorf("mq_timedreceive payload = %q, want %q", got, mqPayload)
	}
	return nil
}

func mqOpen(name string, flags int, mode uint32, attr *mqAttr) (int, error) {
	ptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf("queue name: %w", err)
	}
	fd, _, errno := syscall.Syscall6(
		syscall.SYS_MQ_OPEN,
		uintptr(unsafe.Pointer(ptr)),
		uintptr(flags),
		uintptr(mode),
		uintptr(unsafe.Pointer(attr)),
		0,
		0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("mq_open: %w", errno)
	}
	return int(fd), nil
}

func mqUnlink(name string) error {
	ptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return fmt.Errorf("queue name: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_MQ_UNLINK, uintptr(unsafe.Pointer(ptr)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("mq_unlink: %w", errno)
	}
	return nil
}

func mqNotify(mqd int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MQ_NOTIFY, uintptr(mqd), 0, 0)
	if errno == 0 || errors.Is(errno, syscall.EINVAL) {
		return nil
	}
	return fmt.Errorf("mq_notify: %w", errno)
}

func mqGetsetattr(mqd int) error {
	var old mqAttr
	_, _, errno := syscall.Syscall(
		syscall.SYS_MQ_GETSETATTR,
		uintptr(mqd),
		0,
		uintptr(unsafe.Pointer(&old)),
	)
	if errno != 0 {
		return fmt.Errorf("mq_getsetattr: %w", errno)
	}
	return nil
}

func mqTimedsend(mqd int, payload []byte, priority uint32, deadline time.Time) error {
	ts := syscall.NsecToTimespec(deadline.UnixNano())
	_, _, errno := syscall.Syscall6(
		syscall.SYS_MQ_TIMEDSEND,
		uintptr(mqd),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(priority),
		uintptr(unsafe.Pointer(&ts)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("mq_timedsend: %w", errno)
	}
	return nil
}

func mqTimedreceive(mqd int, buf []byte, deadline time.Time) (int, error) {
	ts := syscall.NsecToTimespec(deadline.UnixNano())
	var prio uint32
	n, _, errno := syscall.Syscall6(
		syscall.SYS_MQ_TIMEDRECEIVE,
		uintptr(mqd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&prio)),
		uintptr(unsafe.Pointer(&ts)),
		0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("mq_timedreceive: %w", errno)
	}
	return int(n), nil
}
