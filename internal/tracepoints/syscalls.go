package tracepoints

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
)

// SEC("tracepoint/syscalls/sys_exit_openat")
var syscallRe = regexp.MustCompile(`sys_((enter|exit).*)"\)`)

func filterLines(lines []string) ([]string, error) {
	var syscalls []string

	for _, line := range lines {
		matches := syscallRe.FindStringSubmatch(line)
		if len(matches) < 1 {
			continue
		}
		syscalls = append(syscalls, matches[1])
	}

	return syscalls, nil
}

// Filter out all used syscall tracepoints from *.bpf.c
func usedSyscalls() ([]string, error) {
	var syscalls []string

	files, err := os.ReadDir(".")
	if err != nil {
		return syscalls, err
	}

	for _, file := range files {
		fileName := file.Name()
		if !strings.HasSuffix(fileName, ".bpf.c") {
			continue
		}
		content, err := os.ReadFile(fileName)
		if err != nil {
			return syscalls, err
		}
		syscalls_, err := filterLines(strings.Split(string(content), "\n"))
		if err != nil {
			return syscalls, err
		}
		syscalls = append(syscalls, syscalls_...)
	}

	return syscalls, nil
}

func AttachSyscalls(bpfModule *bpf.Module) error {
	syscalls, err := usedSyscalls()
	if err != nil {
		return err
	}
	for _, name := range syscalls {
		// Attach to tracepoint
		prog, err := bpfModule.GetProgram(fmt.Sprintf("handle_%s", name))
		if err != nil {
			return fmt.Errorf("Failed to get BPF program handle_%s: %v", name, err)
		}
		log.Println("Attached prog handle_" + name)
		if _, err = prog.AttachTracepoint("syscalls", fmt.Sprintf("sys_%s", name)); err != nil {
			return fmt.Errorf("Failed to attach to sys_%s tracepoint: %v", name, err)
		}
		log.Println("Attached tracepoint sys_" + name)
	}
	return nil
}
