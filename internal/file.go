package internal

import (
	"strconv"
	"strings"
)

type file interface {
	String() string
}

type fdFile struct {
	fd   int32
	name string
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

func (f pathnameFile) String() string {
	var sb strings.Builder

	sb.WriteString("pathname:")
	sb.WriteString(f.pathname)

	return sb.String()
}
