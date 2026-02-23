package generate

import "strings"

type TracepointKind int

const (
	KindNone TracepointKind = iota
	KindFd
	KindOpen
	KindPathname
	KindName
	KindRet
	KindFcntl
	KindNull
	KindDup3
	KindOpenByHandleAt
)

type RetClassification string

const (
	Unclassified       RetClassification = "UNCLASSIFIED"
	ReadClassified     RetClassification = "READ_CLASSIFIED"
	WriteClassified    RetClassification = "WRITE_CLASSIFIED"
	TransferClassified RetClassification = "TRANSFER_CLASSIFIED"
)

type ClassificationResult struct {
	Kind          TracepointKind
	PathnameField string // for KindPathname: "pathname", "path", "filename", or "name"
}

// ClassifyFormat determines the tracepoint kind for a parsed format section.
// It mirrors the Raku multi-dispatch: name-based ignores take priority,
// then name-only mappings, then each external field is tried in order until
// one matches a name+field or generic field pattern.
func ClassifyFormat(f *Format) ClassificationResult {
	if len(f.ExternalFields) == 0 {
		return ClassificationResult{Kind: KindNone}
	}

	if shouldIgnore(f.Name) {
		return ClassificationResult{Kind: KindNone}
	}

	if r, ok := classifyNameOnly(f.Name); ok {
		return r
	}

	for _, field := range f.ExternalFields {
		if field.Name == "__syscall_nr" {
			continue
		}
		if r, ok := classifyNameAndField(f.Name, field.Type, field.Name); ok {
			return r
		}
		if r, ok := classifyByField(field.Type, field.Name); ok {
			return r
		}
	}

	return ClassificationResult{Kind: KindNone}
}

func shouldIgnore(name string) bool {
	prefixIgnores := []string{
		"sys_enter_mknod",
		"sys_enter_execve",
		"sys_enter_accept",
		"sys_enter_listen",
		"sys_enter_epoll",
	}
	for _, p := range prefixIgnores {
		if strings.HasPrefix(name, p) {
			return true
		}
	}

	if strings.HasPrefix(name, "sys_enter_") {
		containsIgnores := []string{"recv", "send", "sock", "inotify", "pidfd"}
		for _, sub := range containsIgnores {
			if strings.Contains(name, sub) {
				return true
			}
		}
	}

	exactIgnores := map[string]bool{
		"sys_enter_bind":          true,
		"sys_enter_setns":         true,
		"sys_enter_shutdown":      true,
		"sys_enter_connect":       true,
		"sys_enter_fanotify_init": true,
		"sys_enter_getpeername":   true,
	}
	return exactIgnores[name]
}

// classifyNameOnly handles tracepoints classified by name alone,
// independent of any field.
func classifyNameOnly(name string) (ClassificationResult, bool) {
	switch name {
	case "sys_enter_open_by_handle_at":
		return ClassificationResult{Kind: KindOpenByHandleAt}, true
	case "sys_enter_io_uring_enter":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_io_uring_register":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_fcntl":
		return ClassificationResult{Kind: KindFcntl}, true
	case "sys_enter_syslog":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sync":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_msync":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getcwd":
		return ClassificationResult{Kind: KindNull}, true
	}
	if strings.HasPrefix(name, "sys_enter_io_") {
		return ClassificationResult{Kind: KindNull}, true
	}
	return ClassificationResult{}, false
}

// classifyNameAndField handles tracepoints that need both the name and
// a specific field to classify.
func classifyNameAndField(name, fieldType, fieldName string) (ClassificationResult, bool) {
	switch name {
	case "sys_enter_dup":
		if fieldType == "unsigned int" && fieldName == "fildes" {
			return ClassificationResult{Kind: KindFd}, true
		}
	case "sys_enter_dup2":
		if fieldType == "unsigned int" && fieldName == "oldfd" {
			return ClassificationResult{Kind: KindFd}, true
		}
	case "sys_enter_dup3":
		if fieldType == "unsigned int" && fieldName == "oldfd" {
			return ClassificationResult{Kind: KindDup3}, true
		}
	case "sys_enter_name_to_handle_at":
		if fieldType == "const char *" && fieldName == "name" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "name"}, true
		}
	case "sys_enter_copy_file_range":
		if isFdType(fieldType) && fieldName == "fd_in" {
			return ClassificationResult{Kind: KindFd}, true
		}
	}

	if strings.HasPrefix(name, "sys_enter") &&
		strings.Contains(name, "open") &&
		fieldType == "const char *" && fieldName == "filename" {
		return ClassificationResult{Kind: KindOpen}, true
	}

	return ClassificationResult{}, false
}

func classifyByField(fieldType, fieldName string) (ClassificationResult, bool) {
	switch {
	case fieldName == "fd" && isFdType(fieldType):
		return ClassificationResult{Kind: KindFd}, true
	case fieldType == "const char *" && fieldName == "newname":
		return ClassificationResult{Kind: KindName}, true
	case fieldType == "const char *" && fieldName == "pathname":
		return ClassificationResult{Kind: KindPathname, PathnameField: "pathname"}, true
	case fieldType == "const char *" && fieldName == "path":
		return ClassificationResult{Kind: KindPathname, PathnameField: "path"}, true
	case fieldType == "const char *" && fieldName == "filename":
		return ClassificationResult{Kind: KindPathname, PathnameField: "filename"}, true
	case fieldType == "long" && fieldName == "ret":
		return ClassificationResult{Kind: KindRet}, true
	}
	return ClassificationResult{}, false
}

func isFdType(t string) bool {
	return t == "unsigned int" || t == "unsigned long" || t == "int"
}

// ClassifyRet returns the RetClassification for a syscall exit name.
func ClassifyRet(name string) RetClassification {
	syscall := strings.ToLower(strings.TrimPrefix(name, "sys_exit_"))
	if c, ok := retClassifications[syscall]; ok {
		return c
	}
	return Unclassified
}

var retClassifications = map[string]RetClassification{
	"fgetxattr":        ReadClassified,
	"flistxattr":       ReadClassified,
	"getdents":         ReadClassified,
	"getdents64":       ReadClassified,
	"getxattr":         ReadClassified,
	"lgetxattr":        ReadClassified,
	"listxattr":        ReadClassified,
	"llistxattr":       ReadClassified,
	"pread64":          ReadClassified,
	"preadv":           ReadClassified,
	"preadv2":          ReadClassified,
	"process_vm_readv": ReadClassified,
	"read":             ReadClassified,
	"readlink":         ReadClassified,
	"readlinkat":       ReadClassified,
	"readv":            ReadClassified,
	"recvmmsg":         ReadClassified,
	"recvmsg":          ReadClassified,
	"recvfrom":         ReadClassified,
	"syslog":           ReadClassified,

	"copy_file_range": TransferClassified,
	"sendfile64":      TransferClassified,
	"splice":          TransferClassified,
	"tee":             TransferClassified,
	"vmsplice":        TransferClassified,

	"process_vm_writev": WriteClassified,
	"pwrite64":          WriteClassified,
	"pwritev":           WriteClassified,
	"pwritev2":          WriteClassified,
	"sendmmsg":          WriteClassified,
	"sendmsg":           WriteClassified,
	"sendto":            WriteClassified,
	"write":             WriteClassified,
	"writev":            WriteClassified,
}
