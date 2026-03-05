//go:build mage

// Magefile for ior targets: build, test, install, generate, clean, and BPF builds.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"ior/internal/generate"
)

const (
	binaryName           = "ior"
	workloadBinaryName   = "ioworkload"
	defaultLibbpfgoPath  = "../libbpfgo"
	bpfSourcePath        = "internal/c/ior.bpf.c"
	bpfObjectPath        = "internal/c/ior.bpf.o"
	bpfOutputPath        = "ior.bpf.o"
	workloadSourcePath   = "./integrationtests/cmd/ioworkload"
	tracepointsCPath     = "internal/c/generated_tracepoints.c"
	tracepointsResult    = "internal/c/generated_tracepoints_result.txt"
	tracepointsResultNew = "internal/c/generated_tracepoints_result.txt.new"
	tracepointsGoPath    = "internal/tracepoints/generated_tracepoints.go"
	typesGoPath          = "internal/types/generated_types.go"
	typesHeaderPath      = "internal/c/types.h"
	VMLINUXPath          = "internal/c/vmlinux.h"
	benchProfilesDir     = "bench-profiles"
	integrationParallel  = "INTEGRATION_PARALLEL"
	integrationParallelE = "IOR_INTEGRATION_PARALLEL"
)

// Default builds the project.
func Default() {
	mg.Deps(Build)
}

// Build compiles the binary.
func Build() error {
	mg.Deps(BpfBuild)
	return sh.RunWithV(goEnv(), "go", "build", "-tags", "netgo", "-ldflags", "-w -extldflags \"-static\"",
		"-o", binaryName, "./cmd/ior/main.go")
}

// GoBuildRace compiles the binary with the race detector enabled.
func GoBuildRace() error {
	mg.Deps(BpfBuild)
	return sh.RunWithV(goEnv(), "go", "build", "-tags", "netgo", "-ldflags", "-w -extldflags \"-static\"",
		"-race", "-o", binaryName, "./cmd/ior/main.go")
}

// All builds the BPF object and the Go binary.
func All() error {
	mg.SerialDeps(Build)
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
	return sh.RunWithV(goEnv(), "go", "test", "./...", "-failfast", "-timeout=90m")
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
	isIntegration, err := isIntegrationTest(testName)
	if err != nil {
		return err
	}
	if isIntegration {
		mg.SerialDeps(All)
		if err := buildWorkloadBinary(); err != nil {
			return err
		}
		fmt.Println("Running integration test", testName, "(requires root)...")
		env := goEnv()
		forwardEnv(env, "HOME", "GOPATH", "GOMODCACHE", "PATH", "GOTOOLCHAIN")
		return runGoTestWithProgress(env,
			"./integrationtests/...",
			"-run", "^"+testName+"$",
			"-failfast",
			"-timeout=30m",
			"-count=1",
			"-json",
		)
	}
	return sh.RunWithV(goEnv(), "go", "test", "./...", "-run", "^"+testName+"$", "-v", "-failfast")
}

// Bench runs benchmarks.
func Bench() error {
	if err := sh.RunWithV(goEnv(), "go", "test", "./...", "-v", "-bench=.", "-run", "xxx"); err != nil {
		return err
	}
	fmt.Println("Running dedicated flamegraph benchmark suite...")
	return BenchFlame()
}

// PrReview runs a reproducible baseline for Codex-assisted PR reviews.
func PrReview() error {
	fmt.Println("Running PR review baseline: world + benchProf")
	if err := World(); err != nil {
		return err
	}
	return BenchProf()
}

// BenchProf runs pipeline benchmarks and writes timestamped pprof artifacts.
func BenchProf() error {
	if err := ensureBenchProfilesDir(); err != nil {
		return err
	}

	timestamp := benchTimestamp()
	cpuProfile := filepath.Join(benchProfilesDir, fmt.Sprintf("pipeline-%s-cpu.prof", timestamp))
	memProfile := filepath.Join(benchProfilesDir, fmt.Sprintf("pipeline-%s-mem.prof", timestamp))
	blockProfile := filepath.Join(benchProfilesDir, fmt.Sprintf("pipeline-%s-block.prof", timestamp))

	if err := sh.RunWithV(goEnv(), "go", "test", "./internal",
		"-run", "^$",
		"-bench", "^BenchmarkPipeline",
		"-benchmem",
		"-count=1",
		"-cpuprofile", cpuProfile,
		"-memprofile", memProfile,
		"-blockprofile", blockProfile,
	); err != nil {
		return err
	}

	fmt.Println("Profiles written:")
	fmt.Println(" ", cpuProfile)
	fmt.Println(" ", memProfile)
	fmt.Println(" ", blockProfile)
	fmt.Println("Analyze with:")
	fmt.Printf("  go tool pprof -http=:8080 %s\n", cpuProfile)
	fmt.Printf("  go tool pprof -http=:8080 %s\n", memProfile)
	fmt.Printf("  go tool pprof -http=:8080 %s\n", blockProfile)
	fmt.Println("Running flamegraph benchmark profiling...")
	return BenchFlameProf()
}

// BenchFlame runs flamegraph TUI benchmarks with benchmem and repeated samples.
func BenchFlame() error {
	return sh.RunWithV(goEnv(), "go", "test", "./internal/tui/flamegraph/", "-run", "^$", "-bench=.", "-benchmem", "-count=5")
}

// BenchFlameProf runs flamegraph benchmarks and writes CPU/memory profiles.
func BenchFlameProf() error {
	if err := sh.RunWithV(goEnv(), "go", "test", "./internal/tui/flamegraph/",
		"-run", "^$",
		"-bench=.",
		"-benchmem",
		"-count=1",
		"-cpuprofile=flame-cpu.prof",
		"-memprofile=flame-mem.prof",
	); err != nil {
		return err
	}
	fmt.Println("Flame profiles written:")
	fmt.Println("  flame-cpu.prof")
	fmt.Println("  flame-mem.prof")
	fmt.Println("Analyze with:")
	fmt.Println("  go tool pprof -http=:8080 flame-cpu.prof")
	fmt.Println("  go tool pprof -http=:8080 flame-mem.prof")
	return nil
}

// BenchFlameCmp compares flamegraph benchmark runs using benchstat (if installed).
func BenchFlameCmp() error {
	if err := ensureBenchProfilesDir(); err != nil {
		return err
	}
	if _, err := exec.LookPath("benchstat"); err != nil {
		fmt.Println("benchstat not found in PATH; install with:")
		fmt.Println("  go install golang.org/x/perf/cmd/benchstat@latest")
		return nil
	}

	baseline := filepath.Join(benchProfilesDir, "flame-baseline.txt")
	candidate := filepath.Join(benchProfilesDir, fmt.Sprintf("flame-%s.txt", benchTimestamp()))

	if _, err := os.Stat(baseline); errors.Is(err, os.ErrNotExist) {
		fmt.Println("No flame baseline found; creating:", baseline)
		if err := runFlameBenchToFile(baseline); err != nil {
			return err
		}
		fmt.Println("Baseline created. Re-run mage benchFlameCmp to compare.")
		return nil
	} else if err != nil {
		return err
	}

	if err := runFlameBenchToFile(candidate); err != nil {
		return err
	}

	fmt.Println("Comparing flame benchmark runs:")
	return sh.RunWithV(goEnv(), "benchstat", baseline, candidate)
}

// BenchCompare runs all benchmarks repeatedly and stores output for benchstat.
func BenchCompare() error {
	if err := ensureBenchProfilesDir(); err != nil {
		return err
	}

	outputFile := filepath.Join(benchProfilesDir, fmt.Sprintf("bench-%s.txt", benchTimestamp()))
	cmd := fmt.Sprintf("go test ./... -v -bench=. -run=xxx -benchmem -count=6 | tee %q", outputFile)
	if err := sh.RunWithV(goEnv(), "sh", "-c", cmd); err != nil {
		return err
	}

	fmt.Println("Bench output written to:", outputFile)
	fmt.Println("Compare snapshots with:")
	fmt.Println("  benchstat bench-profiles/bench-*.txt")
	return nil
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
	if err := removeFilesByPath(workloadBinaryName); err != nil {
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
	patterns := []string{"*.zst", "*.svg", "*profile", "*.pdf", "*.tmp", "palette.map"}
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

// IntegrationTest builds everything and runs integration tests in parallel.
func IntegrationTest() error {
	return runIntegrationTests(true)
}

// IntegrationTestSerial builds everything and runs integration tests serially.
func IntegrationTestSerial() error {
	return runIntegrationTests(false)
}

// IntegrationTestParallel builds everything and runs integration tests in parallel.
// Set INTEGRATION_PARALLEL to tune `go test -parallel` (default: NumCPU*2, minimum 1).
func IntegrationTestParallel() error {
	return runIntegrationTests(true)
}

func runIntegrationTests(parallel bool) error {
	mg.SerialDeps(All)
	if err := buildWorkloadBinary(); err != nil {
		return err
	}

	env := goEnv()
	forwardEnv(env, "HOME", "GOPATH", "GOMODCACHE", "GOTOOLCHAIN")

	timeout := "30m"
	if !parallel {
		timeout = "90m"
	}

	args := []string{
		"./integrationtests/...",
		"-failfast",
		"-timeout=" + timeout,
		"-count=1",
	}

	if parallel {
		parallelism, err := resolveIntegrationParallelism()
		if err != nil {
			return err
		}
		env[integrationParallelE] = "1"
		fmt.Printf("Running integration tests in parallel (requires root, parallel=%d)...\n", parallelism)
		args = append(args, "-parallel", strconv.Itoa(parallelism))
	} else {
		fmt.Println("Running integration tests serially (requires root)...")
	}

	args = append(args, "-json")
	return runGoTestWithProgress(env, args...)
}

func resolveIntegrationParallelism() (int, error) {
	parallel := strings.TrimSpace(os.Getenv(integrationParallel))
	if parallel == "" {
		// Conservative default for stability: high per-test process fan-out can
		// cause missed first events under heavy load.
		n := runtime.NumCPU()
		if n > 2 {
			n = 2
		}
		if n < 1 {
			n = 1
		}
		return n, nil
	}

	n, err := strconv.Atoi(parallel)
	if err != nil {
		return 0, fmt.Errorf("parse %s=%q: %w", integrationParallel, parallel, err)
	}
	if n < 1 {
		return 0, fmt.Errorf("%s must be >= 1, got %d", integrationParallel, n)
	}
	return n, nil
}

func buildWorkloadBinary() error {
	fmt.Println("Building ioworkload binary...")
	if err := sh.RunWithV(goEnv(), "go", "build", "-o", workloadBinaryName, workloadSourcePath); err != nil {
		return fmt.Errorf("build ioworkload: %w", err)
	}
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

func ensureBenchProfilesDir() error {
	if err := os.MkdirAll(benchProfilesDir, 0o755); err != nil {
		return fmt.Errorf("ensure %s: %w", benchProfilesDir, err)
	}
	return nil
}

func benchTimestamp() string {
	return time.Now().UTC().Format("20060102-150405")
}

func runFlameBenchToFile(outputFile string) error {
	cmd := fmt.Sprintf("set -o pipefail; go test ./internal/tui/flamegraph/ -run '^$' -bench=. -benchmem -count=5 | tee %q", outputFile)
	return sh.RunWithV(goEnv(), "bash", "-c", cmd)
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

func sudoRunWithEnv(env map[string]string, cmd string, args ...string) error {
	if os.Geteuid() == 0 {
		return sh.RunWithV(env, cmd, args...)
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	sudoArgs := make([]string, 0, 1+len(keys)+1+len(args))
	sudoArgs = append(sudoArgs, "env")
	for _, k := range keys {
		sudoArgs = append(sudoArgs, k+"="+env[k])
	}
	sudoArgs = append(sudoArgs, cmd)
	sudoArgs = append(sudoArgs, args...)
	return sh.RunV("sudo", sudoArgs...)
}

func forwardEnv(env map[string]string, keys ...string) {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}
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

type goTestEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

func runGoTestWithProgress(env map[string]string, args ...string) error {
	cmdArgs := append([]string{"test"}, args...)

	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.Command("go", cmdArgs...)
		cmd.Env = append(os.Environ(), envToList(env)...)
	} else {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		sudoArgs := make([]string, 0, 1+len(keys)+1+len(cmdArgs))
		sudoArgs = append(sudoArgs, "env")
		for _, k := range keys {
			sudoArgs = append(sudoArgs, k+"="+env[k])
		}
		sudoArgs = append(sudoArgs, "go")
		sudoArgs = append(sudoArgs, cmdArgs...)
		cmd = exec.Command("sudo", sudoArgs...)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	running := map[string]time.Time{}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if len(running) == 0 {
					fmt.Println("Integration tests still running... waiting for next test event")
					continue
				}
				names := make([]string, 0, len(running))
				for k := range running {
					names = append(names, k)
				}
				slices.Sort(names)
				fmt.Println("Integration tests running:", strings.Join(names, ", "))
			}
		}
	}()

	go func() {
		_, _ = io.Copy(os.Stderr, stderr)
	}()

	for scanner.Scan() {
		line := scanner.Bytes()
		var ev goTestEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			fmt.Println(string(line))
			continue
		}
		if ev.Test == "" {
			continue
		}
		key := ev.Package + "/" + ev.Test
		switch ev.Action {
		case "run":
			running[key] = time.Now()
			fmt.Println("RUN ", key)
		case "pass":
			delete(running, key)
			fmt.Println("PASS", key)
		case "fail":
			delete(running, key)
			fmt.Println("FAIL", key)
		case "skip":
			delete(running, key)
			fmt.Println("SKIP", key)
		case "output":
			msg := strings.TrimSpace(ev.Output)
			if msg != "" && shouldPrintTestLog(msg) {
				fmt.Println("LOG ", key, "-", msg)
			}
		}
	}
	close(done)
	if err := scanner.Err(); err != nil {
		return err
	}
	return cmd.Wait()
}

func envToList(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

func shouldPrintTestLog(msg string) bool {
	// Always keep error/failure lines.
	if strings.Contains(msg, "--- FAIL:") ||
		strings.Contains(msg, " FAIL ") ||
		strings.Contains(msg, "panic:") ||
		strings.Contains(strings.ToLower(msg), "error") ||
		strings.Contains(strings.ToLower(msg), "expected event not found") {
		return true
	}

	// Drop high-volume attach/debug noise from ior startup in integration tests.
	noisePrefixes := []string{
		"=== RUN",
		"___",
		"|_ _|",
		"| |",
		"|___",
		"v0.0.0",
		"libbpf:",
		"ShouldIAttachTracepoint called with ",
		"Attaching tracepoint ",
		"Attached prog handle_ ",
		"Attached tracepoint",
		"Attaching sys_",
		"Not attaching sys_",
		"Collecting flame graph stats",
		"Starting flamegraph worker",
		"Waiting for stats to be ready",
		"Stopping event loop",
		"Waiting for flamegraph",
		"Worker ",
		"Writing ",
		"Good bye...",
		"Statistics:",
		"duration:",
		"tracepoints:",
		"syscalls:",
		"syscalls after filter:",
	}
	for _, p := range noisePrefixes {
		if strings.HasPrefix(msg, p) {
			return false
		}
	}
	return true
}

func isIntegrationTest(testName string) (bool, error) {
	out, err := sh.OutputWith(goEnv(), "go", "test", "./integrationtests/...", "-list", ".")
	if err != nil {
		return false, fmt.Errorf("list integration tests: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == testName {
			return true, nil
		}
	}
	return false, nil
}
