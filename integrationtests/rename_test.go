package integrationtests

import "testing"

func TestRenameBasic(t *testing.T) {
	runScenario(t, "rename-basic", []ExpectedEvent{
		{
			PathContains: "newname.txt",
			Tracepoint:   "enter_rename",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestRenameRenameat(t *testing.T) {
	runScenario(t, "rename-renameat", []ExpectedEvent{
		{
			PathContains: "renameat-new.txt",
			Tracepoint:   "enter_renameat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestRenameRenameat2(t *testing.T) {
	runScenario(t, "rename-renameat2", []ExpectedEvent{
		{
			PathContains: "renameat2-new.txt",
			Tracepoint:   "enter_renameat2",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestRenameEnoent(t *testing.T) {
	runScenario(t, "rename-enoent", []ExpectedEvent{
		{
			PathContains: "rename-enoent-new.txt",
			Tracepoint:   "enter_rename",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestRenameNoreplace(t *testing.T) {
	runScenario(t, "rename-noreplace", []ExpectedEvent{
		{
			PathContains: "noreplace-dst.txt",
			Tracepoint:   "enter_renameat2",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
