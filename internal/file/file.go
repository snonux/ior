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

type FdFile struct {
	fd   int32
	name string
}

func NewFd(fd int32, name []byte) FdFile {
	return FdFile{fd, stringValue(name)}
}

func NewFdWithPid(fd int32, pid uint32) FdFile {
	if linkName, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd)); err == nil {
		return FdFile{fd, linkName}
	}
	return FdFile{fd, "?"}
}

func (f FdFile) Name() string {
	return f.name
}

func (f FdFile) String() string {
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

type OldnameNewnameFile struct {
	Oldname, Newname string
}

func NewOldnameNewname(oldname, newname []byte) OldnameNewnameFile {
	return OldnameNewnameFile{stringValue(oldname), stringValue(newname)}
}

func (f OldnameNewnameFile) Name() string {
	return f.Newname
}

func (f OldnameNewnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("old:")
	sb.WriteString(f.Oldname)
	sb.WriteString(" ->new:")
	sb.WriteString(f.Newname)

	return sb.String()
}

type PathnameFile struct {
	Pathname string
}

func NewPathname(pathname []byte) PathnameFile {
	return PathnameFile{stringValue(pathname)}
}

func (f PathnameFile) Name() string {
	return f.Pathname
}

func (f PathnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("pathname:")
	sb.WriteString(f.Pathname)

	return sb.String()
}

func stringValue(byteStr []byte) string {
	// TODO: Hopefully, this won't cause a panic when the filename is as long as the array itself
	return string(byteStr[:bytes.IndexByte(byteStr, 0)])
}
