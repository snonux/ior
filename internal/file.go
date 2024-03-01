package internal

import (
	"strconv"
	"strings"
)

type file struct {
	fd   int32
	name string
}

func (f file) String() string {
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
