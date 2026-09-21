package generate

import (
	"fmt"
	"strings"
	"testing"
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
		{Format: fgetxattr, Classification: ClassificationResult{Kind: KindFd}},
		{Format: getxattrat, Classification: ClassificationResult{Kind: KindPathname, PathnameField: "pathname"}},
	}
}
