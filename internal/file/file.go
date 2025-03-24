package file

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type File interface {
	String() string
	Name() string
	FlagsString() string
}

type FdFile struct {
	fd              int32
	name            string
	Flags           int32
	flagsFromFdInfo bool
}

func NewFd(fd int32, name []byte, flags int32) FdFile {
	return FdFile{
		fd:    fd,
		name:  stringValue(name),
		Flags: flags,
	}
}

func NewFdWithPid(fd int32, pid uint32) FdFile {
	linkName, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		fmt.Println("DEBUG", err)
		return FdFile{
			fd:              fd,
			name:            "?",
			Flags:           -1,
			flagsFromFdInfo: true,
		}
	}

	flags, _ := readFlagsFromFdInfo(fd, pid)
	return FdFile{
		fd:              fd,
		name:            linkName,
		Flags:           flags,
		flagsFromFdInfo: true,
	}
}

func (f FdFile) Dup(fd int32) FdFile {
	duppedFd := f
	duppedFd.fd = fd
	duppedFd.flagsFromFdInfo = false
	return duppedFd
}

func readFlagsFromFdInfo(fd int32, pid uint32) (int32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return -1, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "flags:") {
			flagsStr := strings.Fields(line)[1]
			flags, err := strconv.ParseUint(flagsStr, 8, 32)
			return int32(flags), err
		}
	}
	return -1, scanner.Err()
}

func (f FdFile) Name() string {
	return f.name
}

func (f FdFile) FlagsString() string {
	return flagsToStr(f.Flags)
}

func (f FdFile) String() string {
	var sb strings.Builder

	if len(f.name) == 0 {
		sb.WriteString("?")
	} else {
		sb.WriteString(f.name)
		sb.WriteString(" (")
		sb.WriteString(strconv.FormatInt(int64(f.fd), 10))
		sb.WriteString(",")
		sb.WriteString(f.FlagsString())
		sb.WriteString(")")
		if f.flagsFromFdInfo {
			sb.WriteString(" flags from fd info")
		}
	}

	return sb.String()
}

type oldnameNewnameFile struct {
	Oldname, Newname string
}

func NewOldnameNewname(oldname, newname []byte) oldnameNewnameFile {
	return oldnameNewnameFile{stringValue(oldname), stringValue(newname)}
}

func (f oldnameNewnameFile) Name() string {
	return f.Newname
}

func (f oldnameNewnameFile) FlagsString() string {
	return ""
}

func (f oldnameNewnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("old:")
	sb.WriteString(f.Oldname)
	sb.WriteString(" ->new:")
	sb.WriteString(f.Newname)
	sb.WriteString(" (")
	sb.WriteString(f.FlagsString())
	sb.WriteString(")")

	return sb.String()
}

type pathnameFile struct {
	Pathname string
}

func NewPathname(pathname []byte) pathnameFile {
	return pathnameFile{stringValue(pathname)}
}

func (f pathnameFile) Name() string {
	return f.Pathname
}

func (f pathnameFile) FlagsString() string {
	return ""
}

func (f pathnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("pathname:")
	sb.WriteString(f.Pathname)
	sb.WriteString(" (")
	sb.WriteString(f.FlagsString())
	sb.WriteString(")")

	return sb.String()
}

// As data comes in from arrays, converted to slices, there will be null-bytes at the end..
func stringValue(byteStr []byte) string {
	return string(byteStr[:bytes.IndexByte(byteStr, 0)])
}
