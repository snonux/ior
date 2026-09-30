package generate

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGenerateXattrRequestedSizeCapture(t *testing.T) {
	tests := []struct {
		name string
		arg  int
	}{
		{name: "fgetxattr", arg: 3},
		{name: "flistxattr", arg: 2},
		{name: "getxattr", arg: 3},
		{name: "lgetxattr", arg: 3},
		{name: "listxattr", arg: 2},
		{name: "listxattrat", arg: 4},
		{name: "llistxattr", arg: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b strings.Builder
			writeRequestedSizeCapture(&b, &Format{Name: "sys_enter_" + tt.name})
			want := fmt.Sprintf("ev->size = (__u64)ctx->args[%d];", tt.arg)
			if !strings.Contains(b.String(), want) {
				t.Fatalf("requested-size capture missing %q:\n%s", want, b.String())
			}
			if !strings.Contains(b.String(), "ev->size_valid = 1;") {
				t.Fatalf("requested-size capture is not marked valid:\n%s", b.String())
			}
		})
	}
}

func TestGenerateGetxattratReadsSizeFromXattrArgs(t *testing.T) {
	var b strings.Builder
	writeRequestedSizeCapture(&b, &Format{Name: "sys_enter_getxattrat"})
	got := b.String()
	for _, want := range []string{
		"struct { __u64 value; __u32 size; __u32 flags; } ior_xattr_args = {};",
		"if (ctx->args[4] != 0)",
		"bpf_probe_read_user(&ior_xattr_args, sizeof(ior_xattr_args), (void *)ctx->args[4]) == 0",
		"ev->size = ior_xattr_args.size;",
		"ev->size_valid = 1;",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("getxattrat requested-size capture missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ev->size = (__u64)ctx->args[4]") {
		t.Fatalf("getxattrat captured the xattr_args pointer as a size:\n%s", got)
	}
}

func TestGenerateNonXattrSizeMetadataIsInvalid(t *testing.T) {
	var b strings.Builder
	writeRequestedSizeCapture(&b, &Format{Name: "sys_enter_read"})
	if got, want := b.String(), "    ev->size_valid = 0;\n    ev->size = 0;\n"; got != want {
		t.Fatalf("non-xattr size metadata = %q, want %q", got, want)
	}
}

// receiveFixture is a recvfrom/recvmsg enter tracepoint classified the way the
// generator's override table classifies it.
func receiveFixture(name string) GeneratedTracepoint {
	return GeneratedTracepoint{
		Format:         &Format{Name: "sys_enter_" + name, ExternalFields: []Field{{Name: "__syscall_nr"}, {Name: "fd"}}},
		Classification: ClassificationResult{Kind: KindFdSize},
	}
}

func TestReceiveSyscallsUseTheSizeCarryingFdRecord(t *testing.T) {
	for _, name := range []string{"recvfrom", "recvmsg"} {
		if got, ok := nameOnlyKindsTable["sys_enter_"+name]; !ok || got != KindFdSize {
			t.Errorf("sys_enter_%s kind = %v (listed %v), want KindFdSize", name, got, ok)
		}
	}
}

// TestGenerateRecvfromCapturesFlagsAndBufferSize pins the two scalars that
// decide how many bytes a recvfrom moved: flags (args[3]) and the buffer size
// (args[2]), the latter marked valid so a zero-length receive is recognizable.
func TestGenerateRecvfromCapturesFlagsAndBufferSize(t *testing.T) {
	got := generateExtraFdSize(receiveFixture("recvfrom").Format)
	for _, want := range []string{
		"ev->fd = (__s32)ctx->args[0];",
		"ev->flags = (__u32)ctx->args[3];",
		"ev->size = (__u64)ctx->args[2];",
		"ev->size_valid = 1;",
		"ev->schema_version = FD_SIZE_EVENT_SCHEMA_VERSION;",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("recvfrom capture missing %q:\n%s", want, got)
		}
	}
}

// TestGenerateRecvmsgCapturesFlagsAndGuardsIovecRead pins that recvmsg reads
// its flags from args[2], and reads the msghdr (args[1]) only when MSG_TRUNC is
// set: the extra user-memory reads are not paid on ordinary receives, and the
// flags must be stored before the guard tests them.
func TestGenerateRecvmsgCapturesFlagsAndGuardsIovecRead(t *testing.T) {
	got := generateExtraFdSize(receiveFixture("recvmsg").Format)
	flags := strings.Index(got, "ev->flags = (__u32)ctx->args[2];")
	guard := strings.Index(got, "if (ev->flags & IOR_MSG_TRUNC)")
	call := strings.Index(got, "ior_recvmsg_capacity((void *)ctx->args[1], &ev->size, &ev->size_valid);")
	if flags < 0 || guard < 0 || call < 0 || flags > guard || guard > call {
		t.Fatalf("recvmsg capture must store flags, then guard the iovec read on MSG_TRUNC (flags=%d guard=%d call=%d):\n%s",
			flags, guard, call, got)
	}
	if !strings.Contains(got, "ev->size_valid = 0;\n    ev->size = 0;\n") {
		t.Errorf("recvmsg capacity must default to unknown:\n%s", got)
	}
	if strings.Contains(got, "ev->size_valid = 1;") {
		t.Errorf("recvmsg marks its capacity valid without reading the iovec:\n%s", got)
	}
}

// TestGenerateNonReceiveFdSizeWritesZeroFlags pins that the xattr users of
// fd_size_event initialize the flags word: the ring-buffer reservation is not
// zeroed, so an unwritten word would submit kernel memory.
func TestGenerateNonReceiveFdSizeWritesZeroFlags(t *testing.T) {
	got := generateExtraFdSize(&Format{Name: "sys_enter_fgetxattr"})
	if !strings.Contains(got, "ev->flags = 0;\n") {
		t.Errorf("fgetxattr does not initialize flags:\n%s", got)
	}
	if strings.Contains(got, "IOR_MSG_TRUNC") || strings.Contains(got, "ior_recvmsg_capacity") {
		t.Errorf("fgetxattr picked up recvmsg capture:\n%s", got)
	}
}

// TestRecvHelperMatchesTheSocketABI compares the constants and struct layout
// of internal/c/recv.c with the values the kernel ABI defines, and requires it
// to be included before the generated handlers that call it. A wrong
// MSG_TRUNC value would silently skip the iovec read; a wrong msghdr layout
// would read the wrong field as the iovec pointer.
func TestRecvHelperMatchesTheSocketABI(t *testing.T) {
	recvC, err := readCSource("recv.c")
	if err != nil {
		t.Fatalf("read recv.c: %v", err)
	}
	if want := fmt.Sprintf("#define IOR_MSG_TRUNC %#x", unix.MSG_TRUNC); !strings.Contains(recvC, want) {
		t.Errorf("recv.c must contain %q", want)
	}
	// struct msghdr: name ptr (0), namelen int + pad (8), iov ptr (16),
	// iovlen (24). The C struct is checked field by field in declaration order
	// because its members are all naturally aligned 8/4-byte scalars.
	fields := regexp.MustCompile(`(?s)struct ior_user_msghdr \{(.*?)\};`).FindStringSubmatch(recvC)
	if fields == nil {
		t.Fatal("recv.c lacks struct ior_user_msghdr")
	}
	got := strings.Fields(strings.ReplaceAll(fields[1], ";", " ;"))
	want := strings.Fields("__u64 msg_name ; __s32 msg_namelen ; __u32 pad ; __u64 msg_iov ; __u64 msg_iovlen ;")
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("struct ior_user_msghdr = %v, want %v", got, want)
	}

	bpfC, err := readCSource("ior.bpf.c")
	if err != nil {
		t.Fatalf("read ior.bpf.c: %v", err)
	}
	helper, generated := strings.Index(bpfC, `#include "recv.c"`), strings.Index(bpfC, `#include "generated_tracepoints.c"`)
	if helper < 0 || generated < 0 || helper > generated {
		t.Errorf("ior.bpf.c must include recv.c (%d) before generated_tracepoints.c (%d)", helper, generated)
	}
}

// TestGeneratedReceiveHandlersMatchCommittedArtifact pins the complete enter
// handlers of both receive syscalls against the committed C, so a caller that
// stopped wiring writeReceiveFlagsCapture into generateExtraFdSize fails here
// even though the helper's own tests stay green.
func TestGeneratedReceiveHandlersMatchCommittedArtifact(t *testing.T) {
	artifact, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	for _, name := range []string{"recvfrom", "recvmsg"} {
		t.Run(name, func(t *testing.T) {
			tp := receiveFixture(name)
			got := handlerBody(t, artifact, tp.Format.Name)
			want := strings.TrimSuffix(generateBPFHandler(tp), "\n")
			if got != want {
				t.Fatalf("committed %s handler differs from the complete generator output", tp.Format.Name)
			}
		})
	}
}

func TestGenerateTransferCapturesDestinationFd(t *testing.T) {
	tests := []struct {
		name string
		arg  int
	}{
		{name: "copy_file_range", arg: 2},
		{name: "splice", arg: 2},
		{name: "tee", arg: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateExtraFd(&Format{Name: "sys_enter_" + tt.name})
			want := fmt.Sprintf("ev->fd = (__s32)ctx->args[%d];", tt.arg)
			if !strings.Contains(got, want) {
				t.Fatalf("destination fd capture missing %q:\n%s", want, got)
			}
			if strings.Contains(got, "ev->fd = (__s32)ctx->args[0];") {
				t.Fatalf("%s still attributes transfer to source args[0]:\n%s", tt.name, got)
			}
		})
	}
}

func TestGeneratedRequestedSizeHandlersMatchCommittedArtifact(t *testing.T) {
	artifact, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}

	for _, tp := range requestedSizeHandlerFixtures() {
		name := tp.Format.Name
		t.Run(name, func(t *testing.T) {
			got := handlerBody(t, artifact, name)
			want := strings.TrimSuffix(generateBPFHandler(tp), "\n")
			if got != want {
				t.Fatalf("committed %s handler differs from the complete generator output", name)
			}
		})
	}
}

// This mutation pins the member inside getxattrat's pointer-backed argument,
// not merely its argument provenance. Both .size and .flags originate at
// args[4], so the broad syscall-semantics oracle cannot distinguish them.
func TestGeneratedRequestedSizeHandlerParityRejectsWrongXattrArgsMember(t *testing.T) {
	artifact, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	mutated := replaceInHandler(t, artifact, "enter", "getxattrat",
		"            ev->size = ior_xattr_args.size;",
		"            ev->size = ior_xattr_args.flags;")

	tp := requestedSizeHandlerFixtures()[1]
	got := handlerBody(t, mutated, tp.Format.Name)
	want := strings.TrimSuffix(generateBPFHandler(tp), "\n")
	if got == want {
		t.Fatal("complete-handler parity accepted getxattrat flags as requested size")
	}
}

// requestedSizeHandlerFixtures deliberately builds whole fd and pathname
// handlers. Testing writeRequestedSizeCapture alone would stay green if a
// caller stopped wiring that helper into generateExtraFd or
// generateExtraPathname.
func requestedSizeHandlerFixtures() []GeneratedTracepoint {
	fgetxattr := &Format{
		Name: "sys_enter_fgetxattr",
		ExternalFields: []Field{
			{Name: "__syscall_nr"},
			{Name: "fd"},
			{Name: "name"},
			{Name: "value"},
			{Name: "size"},
		},
	}
	getxattrat := &Format{
		Name: "sys_enter_getxattrat",
		ExternalFields: []Field{
			{Name: "__syscall_nr"},
			{Name: "dfd"},
			{Name: "pathname"},
			{Name: "at_flags"},
			{Name: "name"},
			{Name: "uargs"},
			{Name: "usize"},
		},
	}
	return []GeneratedTracepoint{
		{Format: fgetxattr, Classification: ClassificationResult{Kind: KindFdSize}},
		{Format: getxattrat, Classification: ClassificationResult{Kind: KindPathname, PathnameField: "pathname"}},
	}
}
