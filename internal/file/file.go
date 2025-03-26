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
	flagsFromProcFS bool
	unknownFlags    bool
}

func NewFd(fd int32, name []byte, flags int32) FdFile {
	f := FdFile{
		fd:    fd,
		name:  stringValue(name),
		Flags: flags,
	}
	if f.Flags == -1 {
		panic(fmt.Sprintf("DEBUG with -1 flags: %v", f))
	}
	return f
}

func NewFdWithPid(fd int32, pid uint32) (f FdFile) {
	var err error

	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	f.name, err = os.Readlink(procPath)
	if err != nil {
		// fmt.Println("DEBUGXXX", procPath)
		f.name = ""
	}

	f.Flags, err = readFlagsFromFdInfo(fd, pid)
	if err != nil {
		f.unknownFlags = true
		f.Flags = 0
	} else {
		f.flagsFromProcFS = true
	}

	return f
}

func (f FdFile) Dup(fd int32) FdFile {
	duppedFd := f
	duppedFd.fd = fd
	return duppedFd
}

func readFlagsFromFdInfo(fd int32, pid uint32) (int32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return 0, err
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
	return 0, scanner.Err()
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
	sb.WriteString(f.FlagsString())
	sb.WriteString(")")

	return sb.String()
}

func (f FdFile) FlagsString() string {
	var sb strings.Builder

	if f.unknownFlags {
		sb.WriteString("U") // Unknown
	}
	if f.flagsFromProcFS {
		sb.WriteString("P") // ProcFS
	}
	if f.unknownFlags || f.flagsFromProcFS {
		sb.WriteString(":flags") // ProcFS
	}

	flagsToStr(&sb, f.Flags)
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
	sb.WriteString("%(")
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
	sb.WriteString("%(")
	sb.WriteString(f.FlagsString())
	sb.WriteString(")")

	return sb.String()
}

// As data comes in from arrays, converted to slices, there will be null-bytes at the end..
func stringValue(byteStr []byte) string {
	return string(byteStr[:bytes.IndexByte(byteStr, 0)])
}
