package file

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

var flagsToHumanCache = map[int32]string{}

type tuple struct {
	syscallNr int
	str       string
}

var flagsToHuman = []tuple{
	{syscall.O_RDONLY, "O_RDONLY"},
	{syscall.O_WRONLY, "O_WRONLY"},
	{syscall.O_RDWR, "O_RDWR"},
	{syscall.O_ACCMODE, "O_ACCMODE"},
	{syscall.O_APPEND, "O_APPEND"},
	{syscall.O_ASYNC, "O_ASYNC"},
	{syscall.O_CLOEXEC, "O_CLOEXEC"},
	{syscall.O_CREAT, "O_CREAT"},
	{syscall.O_DIRECT, "O_DIRECT"},
	{syscall.O_DIRECTORY, "O_DIRECTORY"},
	{syscall.O_DSYNC, "O_DSYNC"},
	{syscall.O_EXCL, "O_EXCL"},
	{syscall.O_NOATIME, "O_NOATIME"},
	{syscall.O_NOCTTY, "O_NOCTTY"},
	{syscall.O_NOFOLLOW, "O_NOFOLLOW"},
	{syscall.O_NONBLOCK, "O_NONBLOCK"},
	{syscall.O_SYNC, "O_SYNC"},
	{syscall.O_TRUNC, "O_TRUNC"},
}

func flagsToStr(sb *strings.Builder, flags int32) {
	if str, ok := flagsToHumanCache[flags]; ok {
		sb.WriteString(str)
		return
	}
	str := strings.Join(flagsToStrs(flags), "|")
	flagsToHumanCache[flags] = fmt.Sprintf("%O=>%s", flags, str)
	sb.WriteString(str)
}

func flagsToStrs(flags int32) (result []string) {

	if int(flags)&(os.O_WRONLY|os.O_RDWR) == 0 {
		// Must be read only then
		result = append(result, "O_RDONLY")
	}
	for _, toHuman := range flagsToHuman[1:] {
		if int(flags)&toHuman.syscallNr == toHuman.syscallNr {
			result = append(result, toHuman.str)
		}
	}
	if len(result) == 0 {
		result = append(result, "non=>O_RDONLY")
	}
	return
}
