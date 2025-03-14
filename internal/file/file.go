package file

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type File interface {
	String() string
	Name() string
}

type fdFile struct {
	fd   int32
	name string
}

func NewFd(fd int32, name []byte) fdFile {
	return fdFile{fd, stringValue(name)}
}

func NewFdWithPid(fd int32, pid uint32) fdFile {
	if linkName, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd)); err == nil {
		return fdFile{fd, linkName}
	}
	return fdFile{fd, "?"}
}

func (f fdFile) Name() string {
	return f.name
}

func (f fdFile) String() string {
	var sb strings.Builder

	if len(f.name) == 0 {
		sb.WriteString("?")
	} else {
		sb.WriteString(f.name)
		sb.WriteString(" (")
		sb.WriteString(strconv.FormatInt(int64(f.fd), 10))
		sb.WriteString(")")
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

func (f oldnameNewnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("old:")
	sb.WriteString(f.Oldname)
	sb.WriteString(" ->new:")
	sb.WriteString(f.Newname)

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

func (f pathnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("pathname:")
	sb.WriteString(f.Pathname)

	return sb.String()
}

// As data comes in from arrays, converted to slices, there will be null-bytes at the end..
func stringValue(byteStr []byte) string {
	// TODO: Hopefully, this won't cause a panic when the filename is as long as the array itself. Unit test this!
	return string(byteStr[:bytes.IndexByte(byteStr, 0)])
}
