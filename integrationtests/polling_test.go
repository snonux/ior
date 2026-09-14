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
	for _, syscallName := range []string{"epoll_wait", "epoll_pwait", "poll", "ppoll", "select", "pselect6"} {
		expected = append(expected, ExpectedRow{
			Syscall:       syscallName,
			Comm:          "ioworkload",
			RetValAtLeast: &positive,
			IsError:       &notError,
			Bytes:         &zeroBytes,
			EpollOp:       &empty,
		})
	}
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
		}})
	} else {
		t.Log("epoll_pwait2 parquet rows not observed; treating as unsupported-kernel path")
	}
}
