package integrationtests

import "testing"

func TestLinkBasic(t *testing.T) {
	runScenario(t, "link-basic", []ExpectedEvent{
		{
			PathContains: "hardlink.txt",
			Tracepoint:   "enter_link",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "symlink.txt",
			Tracepoint:   "enter_symlink",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "symlink.txt",
			Tracepoint:   "enter_readlink",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestLinkLinkat(t *testing.T) {
	runScenario(t, "link-linkat", []ExpectedEvent{
		{
			PathContains: "linkat-hard.txt",
			Tracepoint:   "enter_linkat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestLinkSymlinkat(t *testing.T) {
	runScenario(t, "link-symlinkat", []ExpectedEvent{
		{
			PathContains: "symlinkat-link.txt",
			Tracepoint:   "enter_symlinkat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestLinkReadlinkat(t *testing.T) {
	runScenario(t, "link-readlinkat", []ExpectedEvent{
		{
			PathContains: "readlinkat-link.txt",
			Tracepoint:   "enter_readlinkat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestLinkEnoent(t *testing.T) {
	runScenario(t, "link-enoent", []ExpectedEvent{
		{
			PathContains: "link-enoent-missing.txt",
			Tracepoint:   "enter_link",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestLinkSymlinkEexist(t *testing.T) {
	runScenario(t, "link-symlink-eexist", []ExpectedEvent{
		{
			PathContains: "symlink-eexist.txt",
			Tracepoint:   "enter_symlink",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestLinkReadlinkatEinval(t *testing.T) {
	runScenario(t, "link-readlinkat-einval", []ExpectedEvent{
		{
			PathContains: "readlinkat-einval.txt",
			Tracepoint:   "enter_readlinkat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
