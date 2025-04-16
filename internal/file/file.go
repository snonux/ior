package file

import (
	"bufio"
	"bytes"
	"fmt"
	"ior/internal/types"
	"os"
	"strconv"
	"strings"
)

type File interface {
	String() string
	Name() string
	Flags() Flags
}

type FdFile struct {
	fd              int32
	name            string
	flags           Flags
	flagsFromProcFS bool
}

func NewFd(fd int32, name []byte, flags int32) FdFile {
	f := FdFile{
		fd:    fd,
		name:  types.StringValue(name),
		flags: Flags(flags),
	}
	if f.flags == -1 {
		panic(fmt.Sprintf("DEBUG with -1 flags: %v", f))
	}
	return f
}

func NewFdWithPid(fd int32, pid uint32) (f FdFile) {
	var err error

	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	f.name, err = os.Readlink(procPath)
	if err != nil {
		f.name = ""
	}

	f.flags, _ = readFlagsFromFdInfo(fd, pid)
	f.flagsFromProcFS = true

	return f
}

func (f FdFile) Dup(fd int32) FdFile {
	dupFd := f
	dupFd.fd = fd
	return dupFd
}

func readFlagsFromFdInfo(fd int32, pid uint32) (Flags, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return unknownFlag, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "flags:") {
			flagsStr := strings.Fields(line)[1]
			flags, err := strconv.ParseUint(flagsStr, 8, 32)
			return Flags(flags), err
		}
	}
	return unknownFlag, scanner.Err()
}

func (f FdFile) Name() string {
	return f.name
}

func (f FdFile) String() string {
	var sb strings.Builder

	if len(f.name) == 0 {
		sb.WriteString("E:name") // Emtpy name string
	} else {
		sb.WriteString(f.name)
	}
	sb.WriteString("%(")
	sb.WriteString(strconv.FormatInt(int64(f.fd), 10))
	sb.WriteString(",")
	sb.WriteString(f.Flags().String())
	sb.WriteString(")")

	return sb.String()
}

func (f FdFile) Flags() Flags {
	return f.flags
}

func (f *FdFile) AddFlags(flags int32) {
	f.flags = Flags(int32(f.flags) | flags)
}

type oldnameNewnameFile struct {
	Oldname, Newname string
}

func NewOldnameNewname(oldname, newname []byte) oldnameNewnameFile {
	return oldnameNewnameFile{types.StringValue(oldname), types.StringValue(newname)}
}

func (f oldnameNewnameFile) Name() string {
	return f.Newname
}

func (f oldnameNewnameFile) Flags() Flags {
	return unknownFlag
}

func (f oldnameNewnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("old:")
	sb.WriteString(f.Oldname)
	sb.WriteString(" ->new:")
	sb.WriteString(f.Newname)
	sb.WriteString("%(")
	sb.WriteString(f.Flags().String())
	sb.WriteString(")")

	return sb.String()
}

type pathnameFile struct {
	Pathname string
}

func NewPathname(pathname []byte) pathnameFile {
	return pathnameFile{types.StringValue(pathname)}
}

func (f pathnameFile) Name() string {
	return f.Pathname
}

func (f pathnameFile) Flags() Flags {
	return unknownFlag
}

func (f pathnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("pathname:")
	sb.WriteString(f.Pathname)
	sb.WriteString("%(")
	sb.WriteString(f.Flags().String())
	sb.WriteString(")")

	return sb.String()
}
