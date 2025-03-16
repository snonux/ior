package file

import (
	"strings"
	"syscall"
)

var flagsToHuman = map[int]string{
	syscall.O_ACCMODE:   "O_ACCMODE",
	syscall.O_APPEND:    "O_APPEND",
	syscall.O_ASYNC:     "O_ASYNC",
	syscall.O_CLOEXEC:   "O_CLOEXEC",
	syscall.O_CREAT:     "O_CREAT",
	syscall.O_DIRECT:    "O_DIRECT",
	syscall.O_DIRECTORY: "O_DIRECTORY",
	syscall.O_DSYNC:     "O_DSYNC",
	syscall.O_EXCL:      "O_EXCL",
	syscall.O_NOATIME:   "O_NOATIME",
	syscall.O_NOCTTY:    "O_NOCTTY",
	syscall.O_NOFOLLOW:  "O_NOFOLLOW",
	syscall.O_NONBLOCK:  "O_NONBLOCK",
	syscall.O_RDONLY:    "O_RDONLY",
	syscall.O_RDWR:      "O_RDWR",
	syscall.O_SYNC:      "O_SYNC",
	syscall.O_TRUNC:     "O_TRUNC",
	syscall.O_WRONLY:    "O_WRONLY",
}

func FlagsToStr(flags int32) string {
	return strings.Join(FlagsToStrs(flags), "|")
}

func FlagsToStrs(flags int32) (result []string) {
	for flag, name := range flagsToHuman {
		if int(flags)&flag == flag {
			result = append(result, name)
		}
	}
	if len(result) == 0 {
		result = append(result, "O_RDONLY")
	}
	return
}
