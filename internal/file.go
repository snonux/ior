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
		sb.WriteString("file:?")
	} else {
		sb.WriteString("file:(")
		sb.WriteString(strconv.FormatInt(int64(f.fd), 10))
		sb.WriteString(")")
		sb.WriteString(f.name)
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
