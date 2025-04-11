package flamegraph

import (
	"fmt"
	"io"
	"ior/internal/flags"
	"os"
	"os/exec"
	"strings"

	"github.com/DataDog/zstd"
)

// Tool represents a utility for generating flamegraphs.
// It contains the path to the flamegraph tool, the arguments to be passed to it,
// and the output file where the generated flamegraph will be stored.
type Tool struct {
	flamegraphTool string   // Path to the flamegraph tool executable.
	args           []string // Arguments to be passed to the flamegraph tool.
	outFile        string   // Path to the output file where the flamegraph will be saved.
}

func NewTool(collapsedFile string) (Tool, error) {
	if strings.HasSuffix(collapsedFile, ".zst") {
		var err error
		collapsedFile, err = decompress(collapsedFile)
		if err != nil {
			return Tool{}, err
		}
	}

	t := Tool{
		flamegraphTool: flags.Get().FlamegraphTool,
		args:           []string{collapsedFile, "--hash"},
		outFile:        strings.TrimSuffix(collapsedFile, ".collapsed") + ".svg",
	}

	t.args = append(t.args, "--title")
	t.args = append(t.args, fmt.Sprintf("I/O Traces (%s by %s)",
		strings.Join(flags.Get().CollapsedFields, ","), flags.Get().CountField,
	))

	return t, nil
}

func (t Tool) WriteSVG() error {
	if _, err := os.Stat(t.outFile); err == nil {
		fmt.Println(t.outFile, "already exists!")
		return nil
	}
	cmd := exec.Command(t.flamegraphTool, t.args...)
	fmt.Println("Running", cmd)

	outFd, err := os.Create(t.outFile)
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

func decompress(compressedFile string) (string, error) {
	decompressedFile := strings.TrimSuffix(compressedFile, ".zst")

	file, err := os.Open(compressedFile)
	if err != nil {
		return decompressedFile, err
	}
	defer file.Close()

	decoder := zstd.NewReader(file)
	defer decoder.Close()

	decompressedFd, err := os.Create(decompressedFile)
	if err != nil {
		return decompressedFile, err
	}
	defer decompressedFd.Close()

	_, err = io.Copy(decompressedFd, decoder)
	if err != nil {
		return decompressedFile, err
	}

	return decompressedFile, nil
}
