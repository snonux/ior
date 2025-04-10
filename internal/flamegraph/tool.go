package flamegraph

import (
	"fmt"
	"ior/internal/flags"
	"os"
	"os/exec"
	"strings"
)

type Tool struct {
	collapsedFile string
	inverted      bool
}

func NewTool(collapsedFile string) Tool {
	return Tool{
		collapsedFile: collapsedFile,
	}
}

func (t Tool) WriteSVG() error {
	// TODO: Dynamically fill
	// args := []string{t.collapsedFile, "--nametype", "Path", "--hash"}
	args := []string{t.collapsedFile, "--hash"}

	if t.inverted {
		args = append(args, "--inverted")
	}

	args = append(args, "--title")
	args = append(args, fmt.Sprintf("I/O Traces (%s by %s)",
		strings.Join(flags.Get().CollapsedFields, ","), flags.Get().CountField,
	))

	cmd := exec.Command(flags.Get().FlamegraphTool, args...)

	outFile := strings.TrimSuffix(t.collapsedFile, ".collapsed") + ".svg"
	outFd, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer outFd.Close()

	cmd.Stdout = outFd
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
