package generate

import (
	"go/format"
	"os"
	"strings"
	"testing"
)

func TestNotificationTypesMatchGenerator(t *testing.T) {
	header, err := os.ReadFile("../c/types.h")
	if err != nil {
		t.Fatal(err)
	}
	tracepoints, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatal(err)
	}
	structs, constants, err := ParseCTypesInput(strings.NewReader(string(header) + "\n" + tracepoints))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := format.Source([]byte(AddTypesImports(GenerateTypesGo(structs, constants))))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile("../types/generated_types.go")
	if err != nil {
		t.Fatal(err)
	}
	section := func(text string) string {
		start := strings.Index(text, "type FdPathEvent struct")
		end := strings.Index(text, "type FcntlEvent struct")
		if start < 0 || end <= start {
			t.Fatal("cannot locate notification codec")
		}
		return text[start:end]
	}
	if section(string(generated)) != section(string(artifact)) {
		t.Fatal("committed notification types/codec differ from the generator")
	}
}

func notificationFormats() []Format {
	return []Format{
		{Name: "sys_enter_inotify_add_watch", ID: 9004, ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"}, {Type: "int", Name: "fd"},
			{Type: "const char *", Name: "pathname"}, {Type: "u32", Name: "mask"},
		}},
		{Name: "sys_exit_inotify_add_watch", ID: 9003, ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"}, {Type: "long", Name: "ret"},
		}},
		{Name: "sys_enter_fanotify_mark", ID: 9002, ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"}, {Type: "int", Name: "fanotify_fd"},
			{Type: "unsigned int", Name: "flags"}, {Type: "u64", Name: "mask"},
			{Type: "int", Name: "dfd"}, {Type: "const char *", Name: "pathname"},
		}},
		{Name: "sys_exit_fanotify_mark", ID: 9001, ExternalFields: []Field{
			{Type: "int", Name: "__syscall_nr"}, {Type: "long", Name: "ret"},
		}},
	}
}

func TestGeneratedNotificationHandlersMatchProducer(t *testing.T) {
	artifact, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatal(err)
	}
	formats := notificationFormats()
	generated := GenerateTracepointsC(formats)
	for _, format := range formats {
		body := handlerBody(t, generated, format.Name)
		if body != handlerBody(t, artifact, format.Name) {
			t.Errorf("%s committed handler differs from the generator", format.Name)
		}
		if strings.HasPrefix(format.Name, "sys_exit_") {
			requireContains(t, body, "ev->ret_type = UNCLASSIFIED;")
			continue
		}
		for _, expected := range []string{
			"struct fd_path_event *ev = bpf_ringbuf_reserve", "ev->event_type = ENTER_FD_PATH_EVENT;",
			"ev->fd = (__s32)ctx->args[0];", "ev->schema_version = FD_PATH_EVENT_SCHEMA_VERSION;",
			"ev->pathname_status = PATH_READ_NULL;", "ev->pathname_status = PATH_READ_FAILED;",
			"__builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));",
		} {
			requireContains(t, body, expected)
		}
		if strings.Contains(format.Name, "fanotify") {
			requireContains(t, body, "ev->dirfd = (__s32)ctx->args[3];")
			requireContains(t, body, "ev->flags = (__u32)ctx->args[1];")
			requireContains(t, body, "(void*)ctx->args[4]) < 0)")
		} else {
			requireContains(t, body, "ev->dirfd = -100;")
			requireContains(t, body, "ev->flags = 0;")
			requireContains(t, body, "(void*)ctx->args[1]) < 0)")
		}
	}
}
