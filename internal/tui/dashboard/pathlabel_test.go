package dashboard

import (
	"testing"

	"ior/internal/statsengine"
)

func TestRootPathLabelFromFSPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: "root"},
		{in: "/", want: "root"},
		{in: "/var/log", want: "root/var/log"},
		{in: "var/log", want: "root/var/log"},
		{in: "./tmp", want: "root/tmp"},
	}
	for _, tc := range cases {
		if got := rootPathLabelFromFSPath(tc.in); got != tc.want {
			t.Fatalf("rootPathLabelFromFSPath(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestTreemapRootPathTextDirectoryOnly(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil,
		nil,
		nil,
		[]statsengine.SyscallSnapshot{{Name: "read", Count: 3, Bytes: 12}},
		[]statsengine.FileSnapshot{{Path: "/var/log/app.log", Accesses: 4, BytesRead: 16, BytesWritten: 8}},
		[]statsengine.ProcessSnapshot{{PID: 42, Comm: "proc", Syscalls: 5, Bytes: 20}},
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	sysItems := buildSyscallTreemapItems(snap.Syscalls(), bubbleMetricCount)
	if len(sysItems) == 0 || sysItems[0].Name != "read" {
		t.Fatalf("expected syscall treemap label to stay native, got %#v", sysItems)
	}

	fileItems := buildFilesTreemapItems(&snap, bubbleMetricCount)
	if len(fileItems) == 0 || fileItems[0].Name != "root/var/log" {
		t.Fatalf("expected files treemap label root path, got %#v", fileItems)
	}

	procItems := buildProcessesTreemapItems(&snap, bubbleMetricCount)
	if len(procItems) == 0 || procItems[0].Name != "42:proc" {
		t.Fatalf("expected process treemap label to stay native, got %#v", procItems)
	}
}

func TestBubbleRootPathTextDirectoryOnly(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil,
		nil,
		nil,
		[]statsengine.SyscallSnapshot{{Name: "write", Count: 2, Bytes: 64}},
		[]statsengine.FileSnapshot{{Path: "/home/paul/.config/a", Accesses: 1, BytesRead: 5, BytesWritten: 7}},
		[]statsengine.ProcessSnapshot{{PID: 7, Comm: "worker", Syscalls: 9, Bytes: 70}},
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	sys := syscallBubbleData(snap.Syscalls())
	if len(sys) == 0 || sys[0].Label != "write" {
		t.Fatalf("expected syscall bubble label to stay native, got %#v", sys)
	}

	files := filesDirBubbleData(&snap)
	if len(files) == 0 || files[0].Label != "root/home/paul/.config" {
		t.Fatalf("expected files bubble label full root path, got %#v", files)
	}

	procs := processBubbleData(&snap)
	if len(procs) == 0 || procs[0].Label != "7:worker" {
		t.Fatalf("expected process bubble label to stay native, got %#v", procs)
	}
}
