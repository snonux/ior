package main

import "syscall"

// getppidBurstCalls is how many getppid calls getppidBurst makes. Each one
// costs ior two ring-buffer records (enter and exit), and the test that
// counts them (integrationtests, task f23) mirrors the figure.
const getppidBurstCalls = 1_500_000

// getppidBurst calls getppid in a tight loop and returns, so the process
// exits right behind the last call. The loop outruns ior's event loop, which
// is the point: a trace that stops on the target's exit can then stop with a
// backlog in rawCh and in the kernel ring buffer (when ior's liveness check
// sees the exit before the loop has caught up), and its end-of-run figures
// must still account for every record. getppid is used because it does no
// I/O and nothing else in the process calls it: the records produced are
// exactly two per call.
func getppidBurst() error {
	for range getppidBurstCalls {
		syscall.Getppid()
	}
	return nil
}
