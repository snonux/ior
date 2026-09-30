package integrationtests

import (
	"testing"

	"golang.org/x/sys/unix"
)

const (
	pollingParquetDuration    = 10
	pollingWorkloadStartupEnv = "IOR_WORKLOAD_STARTUP_DELAY_MS=1000"
)

var pollingTraceArgs = []string{"-trace-syscalls", "epoll_ctl,epoll_wait,epoll_pwait,epoll_pwait2,poll,ppoll,select,pselect6"}

func TestPollingEpollSemanticsInParquet(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "polling-epoll", pollingParquetDuration,
		pollingTraceArgs, []string{pollingWorkloadStartupEnv})

	positiveFD := int32(1)
	positive := int64(1)
	zero := int64(0)
	zeroBytes := uint64(0)
	notError := false
	add := "ADD"
	empty := ""
	events := uint32(unix.EPOLLIN)
	maxEvents := int32(4)
	oneFD := int32(1)
	epollWaitTimeout := int64(250_000_000)
	shortTimeout := int64(100_000_000)
	infiniteTimeout := int64(-1)
	unknownTimeout := int64(-2)
	efault := -int64(unix.EFAULT)
	einval := -int64(unix.EINVAL)
	isError := true
	expected := []ExpectedRow{
		{
			Syscall:              "epoll_ctl",
			Comm:                 "ioworkload",
			FDAtLeast:            &positiveFD,
			RetVal:               &zero,
			IsError:              &notError,
			EpollOp:              &add,
			EpollTargetFDAtLeast: &positiveFD,
			EpollEvents:          &events,
		},
	}
	expected = append(expected,
		ExpectedRow{Syscall: "epoll_wait", Comm: "ioworkload", FDAtLeast: &positiveFD, RetValAtLeast: &positive, IsError: &notError, Bytes: &zeroBytes, EpollOp: &empty, Nfds: &maxEvents, TimeoutNs: &epollWaitTimeout},
		ExpectedRow{Syscall: "epoll_pwait", Comm: "ioworkload", FDAtLeast: &positiveFD, RetValAtLeast: &positive, IsError: &notError, Bytes: &zeroBytes, EpollOp: &empty, Nfds: &maxEvents, TimeoutNs: &shortTimeout},
		ExpectedRow{Syscall: "poll", Comm: "ioworkload", RetValAtLeast: &positive, IsError: &notError, Bytes: &zeroBytes, EpollOp: &empty, Nfds: &oneFD, TimeoutNs: &infiniteTimeout},
		ExpectedRow{Syscall: "ppoll", Comm: "ioworkload", RetValAtLeast: &positive, IsError: &notError, Bytes: &zeroBytes, EpollOp: &empty, Nfds: &oneFD, TimeoutNs: &shortTimeout},
		ExpectedRow{Syscall: "ppoll", Comm: "ioworkload", RetVal: &efault, IsError: &isError, Nfds: &oneFD, TimeoutNs: &unknownTimeout},
		ExpectedRow{Syscall: "ppoll", Comm: "ioworkload", RetVal: &einval, IsError: &isError, Nfds: &oneFD, TimeoutNs: &unknownTimeout},
	)
	for _, syscallName := range []string{"select", "pselect6"} {
		expected = append(expected, ExpectedRow{Syscall: syscallName, Comm: "ioworkload", RetValAtLeast: &positive, IsError: &notError, Bytes: &zeroBytes, EpollOp: &empty, TimeoutNs: &shortTimeout})
	}
	// select normalises tv_usec >= 1e6 like the kernel ({0, 1500000} is a valid
	// 1.5 s timeout) and reports a negative tv_usec (EINVAL) as unknown.
	normalisedTimeout := int64(1_500_000_000)
	expected = append(expected,
		ExpectedRow{Syscall: "select", Comm: "ioworkload", RetValAtLeast: &positive, IsError: &notError, TimeoutNs: &normalisedTimeout},
		ExpectedRow{Syscall: "select", Comm: "ioworkload", RetVal: &einval, IsError: &isError, TimeoutNs: &unknownTimeout},
	)
	AssertRowsPresent(t, rows, expected)

	var sawPwait2 bool
	for _, row := range rows {
		if row.Syscall == "epoll_pwait2" {
			sawPwait2 = true
		}
	}

	if sawPwait2 {
		AssertRowsPresent(t, rows, []ExpectedRow{{
			Syscall:       "epoll_pwait2",
			Comm:          "ioworkload",
			RetValAtLeast: &positive,
			IsError:       &notError,
			Bytes:         &zeroBytes,
			EpollOp:       &empty,
			FDAtLeast:     &positiveFD,
			Nfds:          &maxEvents,
			TimeoutNs:     &shortTimeout,
		}})
	} else {
		t.Log("epoll_pwait2 parquet rows not observed; treating as unsupported-kernel path")
	}
}
