package internal

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type file interface {
	String() string
	Name() string
}

type fdFile struct {
	fd   int32
	name string
}

func newFdFile(fd int32, name string) fdFile {
	return fdFile{fd, name}
}

func newFdFileWithPid(fd int32, pid uint32) fdFile {
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
	oldname, newname string
}

func (f oldnameNewnameFile) Name() string {
	return f.newname
}

func (f oldnameNewnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("old:")
	sb.WriteString(f.oldname)
	sb.WriteString(" ->new:")
	sb.WriteString(f.newname)

	return sb.String()
}

type pathnameFile struct {
	pathname string
}

func (f pathnameFile) Name() string {
	return f.pathname
}

func (f pathnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("pathname:")
	sb.WriteString(f.pathname)

	return sb.String()
}
