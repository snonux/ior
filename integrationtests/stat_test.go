package integrationtests

import "testing"

func TestStatBasic(t *testing.T) {
	runScenario(t, "stat-basic", []ExpectedEvent{
		{
			PathContains: "statfile.txt",
			Tracepoint:   "enter_newstat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestStatFstat(t *testing.T) {
	runScenario(t, "stat-fstat", []ExpectedEvent{
		{
			PathContains: "fstatfile.txt",
			Tracepoint:   "enter_newfstat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestStatLstat(t *testing.T) {
	runScenario(t, "stat-lstat", []ExpectedEvent{
		{
			PathContains: "lstatfile.txt",
			Tracepoint:   "enter_newlstat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestStatNewfstatat(t *testing.T) {
	runScenario(t, "stat-newfstatat", []ExpectedEvent{
		{
			PathContains: "fstatatfile.txt",
			Tracepoint:   "enter_newfstatat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestStatStatx(t *testing.T) {
	runScenario(t, "stat-statx", []ExpectedEvent{
		{
			PathContains: "statxfile.txt",
			Tracepoint:   "enter_statx",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestStatAccess(t *testing.T) {
	runScenario(t, "stat-access", []ExpectedEvent{
		{
			PathContains: "accessfile.txt",
			Tracepoint:   "enter_access",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestStatFaccessat(t *testing.T) {
	runScenario(t, "stat-faccessat", []ExpectedEvent{
		{
			PathContains: "faccessatfile.txt",
			Tracepoint:   "enter_faccessat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestStatEnoent(t *testing.T) {
	runScenario(t, "stat-enoent", []ExpectedEvent{
		{
			PathContains: "stat-enoent-missing.txt",
			Tracepoint:   "enter_newstat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestStatAccessEnoent(t *testing.T) {
	runScenario(t, "stat-access-enoent", []ExpectedEvent{
		{
			PathContains: "access-enoent-missing.txt",
			Tracepoint:   "enter_access",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestStatFstatEbadf(t *testing.T) {
	runScenario(t, "stat-fstat-ebadf", []ExpectedEvent{
		{
			Tracepoint: "enter_newfstat",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
