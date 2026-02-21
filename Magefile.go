//go:build mage

// Magefile for ior targets: build, test, install, generate, clean, and BPF builds.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"go/format"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"ior/internal/generate"
)

const (
	binaryName           = "ior"
	defaultLibbpfgoPath  = "../libbpfgo"
	bpfSourcePath        = "internal/c/ior.bpf.c"
	bpfObjectPath        = "internal/c/ior.bpf.o"
	bpfOutputPath        = "ior.bpf.o"
	tracepointsCPath     = "internal/c/generated_tracepoints.c"
	tracepointsResult    = "internal/c/generated_tracepoints_result.txt"
	tracepointsResultNew = "internal/c/generated_tracepoints_result.txt.new"
	tracepointsGoPath    = "internal/tracepoints/generated_tracepoints.go"
	typesGoPath          = "internal/types/generated_types.go"
	typesHeaderPath      = "internal/c/types.h"
	VMLINUXPath          = "internal/c/vmlinux.h"
)

// Default builds the project.
func Default() {
	mg.Deps(Build)
}

// Build compiles the binary.
func Build() error {
	return sh.RunWithV(goEnv(), "go", "build", "-tags", "netgo", "-ldflags", "-w -extldflags \"-static\"",
		"-o", binaryName, "./cmd/ior/main.go")
}

// GoBuildRace compiles the binary with the race detector enabled.
func GoBuildRace() error {
	return sh.RunWithV(goEnv(), "go", "build", "-tags", "netgo", "-ldflags", "-w -extldflags \"-static\"",
		"-race", "-o", binaryName, "./cmd/ior/main.go")
}

// All builds the BPF object and the Go binary.
func All() error {
	mg.SerialDeps(BpfBuild, Build)
	return nil
}

// BpfBuild builds the BPF object and copies it to the repo root.
func BpfBuild() error {
	if err := ensureVMLINUX(); err != nil {
		return err
	}
	if err := buildBPFObject(); err != nil {
		return err
	}
	return sh.RunV("cp", "-v", bpfObjectPath, bpfOutputPath)
}

// Test runs the full test suite.
func Test() error {
	if err := sh.RunWithV(goEnv(), "go", "clean", "-testcache"); err != nil {
		return err
	}
	return sh.RunWithV(goEnv(), "go", "test", "./...", "-v", "-failfast")
}

// TestWithName runs a specific test by name.
func TestWithName() error {
	if err := sh.RunWithV(goEnv(), "go", "clean", "-testcache"); err != nil {
		return err
	}
	testName := os.Getenv("TEST_NAME")
	if testName == "" {
		testName = "TestEventloop"
	}
	return sh.RunWithV(goEnv(), "go", "test", "./...", "-run", "^"+testName+"$", "-v", "-failfast")
}

// Bench runs benchmarks.
func Bench() error {
	return sh.RunWithV(goEnv(), "go", "test", "./...", "-v", "-bench=.", "-run", "xxx")
}

// Generate regenerates all generated files.
func Generate() error {
	fmt.Println("Generating tracepoint and type artifacts...")
	mg.SerialDeps(GenerateTracepointsC, GenerateTracepointsGo, GenerateTypesGo)
	fmt.Println("Generation complete.")
	return nil
}

// GenerateTracepointsC regenerates the tracepoint handlers in C.
func GenerateTracepointsC() error {
	fmt.Println("Generating C tracepoints...")
	return generateTracepointsC(true, false)
}

// GenerateTracepointsCForce regenerates the tracepoint handlers in C, ignoring diffs.
func GenerateTracepointsCForce() error {
	fmt.Println("Generating C tracepoints (force)...")
	return generateTracepointsC(false, false)
}

// GenerateTracepointsCStdout prints the tracepoint handlers in C to stdout.
func GenerateTracepointsCStdout() error {
	fmt.Println("Generating C tracepoints (stdout)...")
	return generateTracepointsC(true, true)
}

// GenerateTracepointsGo regenerates the tracepoint list in Go.
func GenerateTracepointsGo() error {
	fmt.Println("Generating Go tracepoints list...")
	input, err := os.ReadFile(tracepointsCPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", tracepointsCPath, err)
	}
	output, err := generate.ExtractTracepoints(strings.NewReader(string(input)))
	if err != nil {
		return err
	}
	formatted, err := format.Source([]byte(output))
	if err != nil {
		return fmt.Errorf("format tracepoints go: %w", err)
	}
	if err := os.WriteFile(tracepointsGoPath, formatted, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tracepointsGoPath, err)
	}
	return nil
}

// GenerateTypesGo regenerates the Go types and constants.
func GenerateTypesGo() error {
	fmt.Println("Generating Go types...")
	input, err := readTypesInput()
	if err != nil {
		return err
	}
	structs, constants, err := generate.ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		return err
	}
	output := generate.GenerateTypesGo(structs, constants)
	output = generate.AddTypesImports(output)
	formatted, err := format.Source([]byte(output))
	if err != nil {
		return fmt.Errorf("format types go: %w", err)
	}
	if err := os.WriteFile(typesGoPath, formatted, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", typesGoPath, err)
	}
	return nil
}

// Install copies the binary into GOPATH/bin.
func Install() error {
	mg.Deps(Build)

	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}
		goPath = filepath.Join(home, "go")
	}

	binDir := filepath.Join(goPath, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return fmt.Errorf("ensure %s: %w", binDir, err)
	}

	dest := filepath.Join(binDir, binaryName)
	return sh.RunV("cp", "-v", binaryName, dest)
}

// Clean removes build artifacts.
func Clean() error {
	if err := removeFilesByName(binaryName); err != nil {
		return err
	}
	if err := removeFilesByPath(bpfOutputPath); err != nil {
		return err
	}
	if err := cleanBPFArtifacts(); err != nil {
		return err
	}
	return nil
}

// Mrproper removes build artifacts and generated output files.
func Mrproper() error {
	mg.SerialDeps(Clean)
	patterns := []string{"*.zst", "*.collapsed", "*.svg", "*profile", "*.pdf", "*.tmp", "palette.map"}
	for _, pattern := range patterns {
		if err := removeFilesByGlob(pattern); err != nil {
			return err
		}
	}
	return nil
}

// World runs clean, generate, test, and build targets.
func World() error {
	fmt.Println("World: cleaning...")
	if err := Clean(); err != nil {
		return err
	}
	fmt.Println("World: generating...")
	if err := Generate(); err != nil {
		return err
	}
	fmt.Println("World: running tests...")
	if err := Test(); err != nil {
		return err
	}
	fmt.Println("World: building... (BPF + Go)")
	if err := All(); err != nil {
		return err
	}
	fmt.Println("World: done.")
	return nil
}

// Prof generates CPU and memory profiling PDFs.
func Prof() error {
	if err := runShellCommand("go tool pprof -pdf ./ior ior.cpuprofile > cpuprofile.pdf"); err != nil {
		return err
	}
	if err := runShellCommand("go tool pprof -pdf ./ior ior.memprofile > memprofile.pdf"); err != nil {
		return err
	}
	return nil
}

func buildBPFObject() error {
	libbpfgo := libbpfgoPath()
	includeDir := filepath.Join(libbpfgo, "output")
	return sh.RunWithV(bpfEnv(), "clang", "-g", "-O2", "-Wall", "-fpie", "-target", "bpf",
		"-D__TARGET_ARCH_amd64", "-I"+includeDir, "-c", bpfSourcePath, "-o", bpfObjectPath)
}

func bpfEnv() map[string]string {
	return map[string]string{"CC": "clang"}
}

func cleanBPFArtifacts() error {
	for _, pattern := range []string{"internal/c/*.o", VMLINUXPath} {
		if err := removeFilesByGlob(pattern); err != nil {
			return err
		}
	}
	return nil
}

func ensureVMLINUX() error {
	if _, err := os.Stat(VMLINUXPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", VMLINUXPath, err)
	}

	output, err := sudoOutput("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
	if err != nil {
		return err
	}
	if err := os.WriteFile(VMLINUXPath, []byte(output), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", VMLINUXPath, err)
	}
	return nil
}

func generateTracepointsC(strict bool, toStdout bool) error {
	fmt.Println("Reading syscall format files...")
	formats, err := readSyscallFormats()
	if err != nil {
		return err
	}
	fmt.Println("Parsing syscall formats...")

	parsed, err := generate.ParseFormats(strings.NewReader(formats))
	if err != nil {
		return err
	}
	output := generate.GenerateTracepointsC(parsed)
	fmt.Println("Writing generated C tracepoints...")

	if toStdout {
		fmt.Print(output)
		return nil
	}

	if err := os.WriteFile(tracepointsCPath, []byte(output), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tracepointsCPath, err)
	}
	return writeTracepointsResult(output, strict)
}

func goEnv() map[string]string {
	libbpfgo := libbpfgoPath()
	cgoCflags := fmt.Sprintf("-I%s -I%s", filepath.Join(libbpfgo, "output"), filepath.Join(libbpfgo, "selftest", "common"))
	cgoLdflags := fmt.Sprintf("-lelf -lzstd %s", filepath.Join(libbpfgo, "output", "libbpf", "libbpf.a"))
	return map[string]string{
		"CGO_CFLAGS":  cgoCflags,
		"CGO_LDFLAGS": cgoLdflags,
		"GOARCH":      "amd64",
		"GOOS":        "linux",
		"LIBBPFGO":    libbpfgo,
	}
}

func libbpfgoPath() string {
	if libbpfgo := os.Getenv("LIBBPFGO"); libbpfgo != "" {
		return libbpfgo
	}
	return filepath.Clean(filepath.Join(repoRoot(), defaultLibbpfgoPath))
}

func readSyscallFormats() (string, error) {
	fmt.Println("Reading syscall format files with one sudo call...")
	output, err := sudoOutput("sh", "-c", "LC_ALL=C find /sys/kernel/tracing/events/syscalls -maxdepth 2 -mindepth 2 -name format | sort | xargs cat")
	if err != nil {
		return "", err
	}
	if output == "" {
		return "", fmt.Errorf("no syscall format files found")
	}
	return output, nil
}

func readTypesInput() (string, error) {
	parts := []string{typesHeaderPath, tracepointsCPath}
	var b strings.Builder
	for _, p := range parts {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", p, err)
		}
		b.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

func removeFilesByGlob(pattern string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob %s: %w", pattern, err)
	}
	for _, match := range matches {
		if err := removeFilesByPath(match); err != nil {
			return err
		}
	}
	return nil
}

func removeFilesByName(name string) error {
	return filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() == name {
			return removeFilesByPath(path)
		}
		return nil
	})
}

func removeFilesByPath(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

func repoRoot() string {
	root, err := os.Getwd()
	if err != nil {
		return "."
	}
	return root
}

func runShellCommand(command string) error {
	return sh.RunV("bash", "-c", command)
}

func sudoOutput(cmd string, args ...string) (string, error) {
	if os.Geteuid() == 0 {
		return sh.Output(cmd, args...)
	}
	return sh.Output("sudo", append([]string{cmd}, args...)...)
}

func writeTracepointsResult(output string, strict bool) error {
	result := extractTracepointReasons(output)
	if err := os.WriteFile(tracepointsResultNew, []byte(result), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tracepointsResultNew, err)
	}
	if _, err := os.Stat(tracepointsResult); errors.Is(err, os.ErrNotExist) {
		return sh.RunV("cp", tracepointsResultNew, tracepointsResult)
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", tracepointsResult, err)
	}
	if err := sh.RunV("diff", "-u", tracepointsResult, tracepointsResultNew); err != nil {
		if strict {
			return err
		}
	}
	return sh.RunV("cp", tracepointsResultNew, tracepointsResult)
}

func extractTracepointReasons(output string) string {
	var reasons []string
	reader := bufio.NewReader(strings.NewReader(output))
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			line = strings.TrimRight(line, "\n")
			if strings.HasPrefix(line, "/// ") {
				reasons = append(reasons, strings.TrimPrefix(line, "/// "))
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return ""
		}
	}
	if len(reasons) == 0 {
		return ""
	}
	sorted, err := sortLinesWithLocale(reasons)
	if err != nil {
		return strings.Join(reasons, "\n") + "\n"
	}
	return sorted
}

func sortLinesWithLocale(lines []string) (string, error) {
	cmd := exec.Command("sort")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
