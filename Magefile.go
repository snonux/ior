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
	clickhouseImage      = "clickhouse/clickhouse-server:latest"
	binaryName           = "ior"
	workloadBinaryName   = "ioworkload"
	defaultLibbpfgoPath  = "../libbpfgo"
	libbpfgoRequiredTag  = "v0.9.2-libbpf-1.5.1"
	bpfSourcePath        = "internal/c/ior.bpf.c"
	bpfObjectPath        = "internal/c/ior.bpf.o"
	bpfOutputPath        = "ior.bpf.o"
	workloadSourcePath   = "./cmd/ioworkload"
	tracepointsCPath     = "internal/c/generated_tracepoints.c"
	tracepointsResult    = "internal/c/generated_tracepoints_result.txt"
	tracepointsResultNew = "internal/c/generated_tracepoints_result.txt.new"
	tracepointsGoPath    = "internal/tracepoints/generated_tracepoints.go"
	typesGoPath          = "internal/types/generated_types.go"
	dockerBuildScript    = "scripts/build-with-docker.sh"
	dockerBuildScriptEl8 = "scripts/build-with-docker-el8.sh"
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

// All is an alias for Build (BPF object + Go binary).
func All() error {
	return Build()
}

// BuildDocker builds the ior binary inside a Rocky Linux 9 Docker container
// and writes the resulting static binary to the repo root.  The container
// image is built on the first run (~15-20 min) and reused thereafter.
// The Go version baked into the image is taken from go.mod automatically.
// Requires Docker and a host kernel with tracefs and BTF enabled.
// Pass --run to skip the image rebuild and only recompile ior.
func BuildDocker() error {
	return sh.RunV("bash", dockerBuildScript)
}

// BuildDockerEl8 builds the ior binary inside a Rocky Linux 8 Docker container
// and writes it as ior.el8 in the repo root, alongside the el9 ior binary
// produced by BuildDocker. Use this when targeting hosts with the older glibc
// shipped on RHEL/Rocky/Alma 8.  The container image is built on the first
// run (~15-20 min) and reused thereafter.
func BuildDockerEl8() error {
	return sh.RunV("bash", dockerBuildScriptEl8)
}

// BpfBuild builds the embedded BPF object used by the Go binary.
func BpfBuild() error {
	if err := ensureVMLINUX(); err != nil {
		return err
	}
	return buildBPFObject()
}

// BpfExport copies the built BPF object to the repo root for debug workflows.
func BpfExport() error {
	mg.Deps(BpfBuild)
	return sh.RunV("cp", "-v", bpfObjectPath, bpfOutputPath)
}

// Test runs the full test suite.
func Test() error {
	mg.Deps(BpfBuild)
	if err := sh.RunWithV(goEnv(), "go", "clean", "-testcache"); err != nil {
		return err
	}
	return sh.RunWithV(goEnv(), "go", "test", "./...", "-failfast", "-timeout=90m")
}

// TestRace runs the full test suite with the race detector enabled.
func TestRace() error {
	mg.Deps(BpfBuild)
	if err := sh.RunWithV(goEnv(), "go", "clean", "-testcache"); err != nil {
		return err
	}
	return sh.RunWithV(goEnv(), "go", "test", "./...", "-race", "-failfast", "-timeout=90m")
}

// Fmt runs gofmt -w on all Go source files to enforce canonical formatting.
func Fmt() error {
	return fmtGoFiles(false)
}

// FmtCheck verifies that all Go source files are gofmt-formatted.
// It exits with a non-zero status if any file needs reformatting,
// making it suitable for use as a CI gate (e.g. mage fmtCheck).
func FmtCheck() error {
	return fmtGoFiles(true)
}

// fmtGoFiles walks the repo tree and either formats or checks every .go file.
// When checkOnly is true, any file that needs reformatting is reported as an
// error without writing to disk. When false, files are rewritten in place.
func fmtGoFiles(checkOnly bool) error {
	var unformatted []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip vendor and hidden directories (e.g. .git).
		if d.IsDir() && (d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		formatted, err := format.Source(src)
		if err != nil {
			// Syntax errors are reported but don't abort the walk.
			fmt.Printf("gofmt: syntax error in %s: %v\n", path, err)
			return nil
		}
		if string(src) == string(formatted) {
			return nil
		}
		if checkOnly {
			unformatted = append(unformatted, path)
			return nil
		}
		return os.WriteFile(path, formatted, d.Type().Perm())
	})
	if err != nil {
		return err
	}
	if len(unformatted) > 0 {
		return fmt.Errorf("gofmt: %d file(s) need formatting:\n  %s\nRun `mage fmt` to fix.",
			len(unformatted), strings.Join(unformatted, "\n  "))
	}
	return nil
}

// TestWithName runs a specific test by name.
func TestWithName() error {
	mg.Deps(BpfBuild)
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
		if err := compileIntegrationTestBinary(env); err != nil {
			return err
		}
		return runIntegrationTestBinary(env,
			"-test.run", "^"+testName+"$",
			"-test.failfast",
			"-test.timeout=30m",
			"-test.count=1",
			"-test.v",
		)
	}
	return sh.RunWithV(goEnv(), "go", "test", "./...", "-run", "^"+testName+"$", "-v", "-failfast")
}

// Bench runs benchmarks.
func Bench() error {
	mg.Deps(BpfBuild)
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
	mg.Deps(BpfBuild)
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
	mg.Deps(BpfBuild)
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
// If the environment variable IOR_FORCE_GENERATE=1 is set,
// the C tracepoint generation will be forced even when it would cause a diff.
func Generate() error {
	fmt.Println("Generating tracepoint and type artifacts...")
	forceEnv := os.Getenv("IOR_FORCE_GENERATE")
	force := strings.EqualFold(forceEnv, "1") || strings.EqualFold(forceEnv, "yes") || forceEnv != ""
	if force {
		fmt.Println("Force generation enabled – ignoring diff checks.")
		mg.SerialDeps(GenerateTracepointsCForce, GenerateTracepointsGo, GenerateTypesGo)
	} else {
		mg.SerialDeps(GenerateTracepointsC, GenerateTracepointsGo, GenerateTypesGo)
	}
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
	kindsInput, err := os.ReadFile(tracepointsResult)
	if err != nil {
		return fmt.Errorf("read %s: %w", tracepointsResult, err)
	}
	output, err := generate.ExtractTracepointsWithKinds(
		strings.NewReader(string(input)),
		strings.NewReader(string(kindsInput)),
	)
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
	// *.prof covers flame-cpu.prof / flame-mem.prof written by benchFlameProf.
	patterns := []string{"*.zst", "*.svg", "*profile", "*.prof", "*.pdf", "*.tmp", "palette.map"}
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
// Set INTEGRATION_PARALLEL to tune `go test -parallel` (default: NumCPU, minimum 1).
func IntegrationTest() error {
	return runIntegrationTests(true)
}

// IntegrationTestSerial builds everything and runs integration tests one at a time.
func IntegrationTestSerial() error {
	return runIntegrationTests(false)
}

func compileIntegrationTestBinary(env map[string]string) error {
	return sh.RunWithV(env, "go", "test", "-c", "./integrationtests/...", "-o", "integrationtests.test")
}

func runIntegrationTestBinary(env map[string]string, args ...string) error {
	envList := make([]string, 0, len(env))
	for k, v := range env {
		envList = append(envList, k+"="+v)
	}
	slices.Sort(envList)

	cmd := exec.Command("./integrationtests.test", args...)
	cmd.Dir = "integrationtests"
	cmd.Env = append(os.Environ(), envList...)
	if os.Geteuid() == 0 {
		return cmd.Run()
	}
	sudoCmd := exec.Command("sudo", append([]string{"-n", "-E", "./integrationtests.test"}, args...)...)
	sudoCmd.Dir = "integrationtests"
	sudoCmd.Env = cmd.Env
	return sudoCmd.Run()
}

func runIntegrationTests(parallel bool) error {
	mg.SerialDeps(All)
	if err := buildWorkloadBinary(); err != nil {
		return err
	}

	env := goEnv()
	forwardEnv(env, "HOME", "GOPATH", "GOMODCACHE", "GOTOOLCHAIN")

	if err := compileIntegrationTestBinary(env); err != nil {
		return err
	}

	timeout := "30m"
	if !parallel {
		timeout = "90m"
	}

	args := []string{
		"-test.failfast",
		"-test.timeout=" + timeout,
		"-test.count=1",
	}

	if parallel {
		parallelism, err := resolveIntegrationParallelism()
		if err != nil {
			return err
		}
		env[integrationParallelE] = "1"
		fmt.Printf("Running integration tests in parallel (requires root, parallel=%d)...\n", parallelism)
		args = append(args, "-test.parallel", strconv.Itoa(parallelism))
	} else {
		fmt.Println("Running integration tests serially (requires root)...")
	}

	return runIntegrationTestBinary(env, args...)
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
	if err := ensureLibbpfgoStaticToolchain(); err != nil {
		return err
	}
	libbpfgo := libbpfgoPath()
	includeDir := filepath.Join(libbpfgo, "output")
	return sh.RunWithV(bpfEnv(), "clang", "-g", "-O2", "-Wall", "-fpie", "-target", "bpf",
		"-D__TARGET_ARCH_amd64", "-I"+includeDir, "-c", bpfSourcePath, "-o", bpfObjectPath)
}

func bpfEnv() map[string]string {
	return map[string]string{"CC": "clang"}
}

func ensureLibbpfgoStaticToolchain() error {
	libbpfgo := libbpfgoPath()
	requiredPaths := []string{
		filepath.Join(libbpfgo, "output"),
		filepath.Join(libbpfgo, "output", "libbpf", "libbpf.a"),
		filepath.Join(libbpfgo, "selftest", "common"),
	}
	for _, path := range requiredPaths {
		if _, err := os.Stat(path); err == nil {
			continue
		} else if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("missing libbpfgo static toolchain path %s\n%s", path, libbpfgoSetupHint(libbpfgo))
		} else {
			return fmt.Errorf("stat %s: %w", path, err)
		}
	}
	return nil
}

func libbpfgoSetupHint(libbpfgo string) string {
	return strings.Join([]string{
		fmt.Sprintf("expected a local libbpfgo checkout at %s pinned to %s", libbpfgo, libbpfgoRequiredTag),
		"rebuild the static toolchain with:",
		fmt.Sprintf("  git -C %s checkout %s", libbpfgo, libbpfgoRequiredTag),
		fmt.Sprintf("  git -C %s submodule update --init --recursive", libbpfgo),
		fmt.Sprintf("  make -C %s libbpfgo-static", libbpfgo),
	}, "\n")
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
	return sh.Output("sudo", append([]string{"-n", cmd}, args...)...)
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
	sudoArgs := make([]string, 0, 2+len(keys)+1+len(args))
	sudoArgs = append(sudoArgs, "-n", "env")
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

// ParquetValidate validates a Parquet file using clickhouse-local in Docker.
// Set PARQUET_FILE to override the default (latest *.parquet in repo root).
// Checks schema column presence, row count > 0, and basic sanity on seq/time_ns.
func ParquetValidate() error {
	path, err := resolveParquetFile()
	if err != nil {
		return err
	}
	if err := checkDockerAvailable(); err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve absolute path for %s: %w", path, err)
	}
	dir, file := filepath.Dir(abs), filepath.Base(abs)
	fmt.Printf("Validating parquet file: %s\n", abs)
	return runParquetChecks(dir, file)
}

// resolveParquetFile returns the parquet file path from PARQUET_FILE env or
// globs for the latest *.parquet in the repo root.
func resolveParquetFile() (string, error) {
	if path := os.Getenv("PARQUET_FILE"); path != "" {
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("PARQUET_FILE=%s: %w", path, err)
		}
		return path, nil
	}
	matches, err := filepath.Glob("*.parquet")
	if err != nil {
		return "", fmt.Errorf("glob *.parquet: %w", err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no *.parquet files found in repo root; set PARQUET_FILE to specify one")
	}
	// Use the last match (lexicographically latest, which matches timestamp-named files).
	return matches[len(matches)-1], nil
}

// checkDockerAvailable verifies that Docker is reachable via `docker info`.
func checkDockerAvailable() error {
	cmd := exec.Command("docker", "info")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker is not available (is the daemon running?): %w", err)
	}
	return nil
}

// runClickHouseQuery runs a SQL query against a parquet file using clickhouse-local
// in Docker. The file must be in dir; it is mounted read-only at /data inside the
// container. Returns the trimmed stdout output.
func runClickHouseQuery(dir, file, sql string) (string, error) {
	// Mount dir as /data read-only; pass the SQL via -q so no shell quoting is needed.
	out, err := sh.Output("docker", "run", "--rm",
		"-v", dir+":/data:ro",
		clickhouseImage,
		"clickhouse", "local", "-q", sql,
	)
	if err != nil {
		return "", fmt.Errorf("clickhouse query %q: %w", sql, err)
	}
	return strings.TrimSpace(out), nil
}

// expectedParquetColumns lists the column names that the parquet schema must
// contain. Keep in lockstep with parquet.Record (internal/parquet/schema.go).
var expectedParquetColumns = []string{
	"seq", "time_ns", "gap_ns", "latency_ns", "comm",
	"pid", "tid", "syscall", "family", "fd", "ret",
	"bytes", "address_space_bytes", "requested_sleep_ns",
	"file", "old_file", "is_error", "filter_epoch",
	"epoll_op", "epoll_target_fd", "epoll_events",
}

// parquetSchemaCheck verifies that all expectedParquetColumns appear in the
// DESCRIBE output of the parquet file, returning an error listing any missing ones.
func parquetSchemaCheck(dir, file, dataFile string) error {
	fmt.Println("--- Schema check ---")
	schemaOut, err := runClickHouseQuery(dir, file,
		fmt.Sprintf("DESCRIBE TABLE file('%s', Parquet)", dataFile))
	if err != nil {
		return err
	}
	fmt.Println(schemaOut)
	var missing []string
	for _, col := range expectedParquetColumns {
		if !strings.Contains(schemaOut, col) {
			missing = append(missing, col)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("schema check FAIL: missing columns: %s", strings.Join(missing, ", "))
	}
	fmt.Printf("Schema check PASS: all %d expected columns present\n\n", len(expectedParquetColumns))
	return nil
}

// parquetRowCountCheck asserts the file contains at least one row.
func parquetRowCountCheck(dir, file, dataFile string) error {
	fmt.Println("--- Row count check ---")
	countOut, err := runClickHouseQuery(dir, file,
		fmt.Sprintf("SELECT count(*) FROM file('%s', Parquet)", dataFile))
	if err != nil {
		return err
	}
	rowCount, err := strconv.ParseInt(strings.TrimSpace(countOut), 10, 64)
	if err != nil {
		return fmt.Errorf("parse row count %q: %w", countOut, err)
	}
	if rowCount <= 0 {
		return fmt.Errorf("row count check FAIL: got %d rows, expected > 0", rowCount)
	}
	fmt.Printf("Row count check PASS: %d rows\n\n", rowCount)
	return nil
}

// parquetSanityCheck validates seq monotonicity and a non-zero min(time_ns).
func parquetSanityCheck(dir, file, dataFile string) error {
	fmt.Println("--- Sanity check ---")
	sanityOut, err := runClickHouseQuery(dir, file,
		fmt.Sprintf("SELECT min(seq), max(seq), min(time_ns), countIf(is_error) FROM file('%s', Parquet)", dataFile))
	if err != nil {
		return err
	}
	fmt.Println(sanityOut)
	parts := strings.Split(sanityOut, "\t")
	if len(parts) != 4 {
		return fmt.Errorf("sanity check FAIL: unexpected output format (got %d tab-separated columns)", len(parts))
	}
	minSeq, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
	maxSeq, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
	minTimeNs, err3 := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("sanity check FAIL: could not parse numeric values from: %s", sanityOut)
	}
	if maxSeq <= minSeq {
		return fmt.Errorf("sanity check FAIL: seq not monotonically increasing (min=%d, max=%d)", minSeq, maxSeq)
	}
	if minTimeNs == 0 {
		return fmt.Errorf("sanity check FAIL: min(time_ns) is zero")
	}
	fmt.Printf("Sanity check PASS: seq range [%d, %d], min time_ns=%d, error_count=%s\n",
		minSeq, maxSeq, minTimeNs, strings.TrimSpace(parts[3]))
	return nil
}

// runParquetChecks runs schema, row-count, and sanity checks against the parquet file.
// dir is the absolute directory containing file (mounted at /data in the container).
func runParquetChecks(dir, file string) error {
	dataFile := "/data/" + file
	if err := parquetSchemaCheck(dir, file, dataFile); err != nil {
		return err
	}
	if err := parquetRowCountCheck(dir, file, dataFile); err != nil {
		return err
	}
	return parquetSanityCheck(dir, file, dataFile)
}

// --- Demo (VHS-driven TUI recordings) ---------------------------------------
//
// Demo regenerates GIFs and PNG screenshots under docs/tutorial/assets/ by
// running every VHS tape under docs/tutorial/tapes/. Each tape is wrapped by
// docs/tutorial/scripts/run-tape.sh which spins up the background workload
// generator. A sudo keep-alive loop keeps the sudo timestamp warm so no tape
// ever blocks on a password prompt.

const (
	demoDir         = "docs/tutorial"
	demoTapesDir    = "docs/tutorial/tapes"
	demoScriptsDir  = "docs/tutorial/scripts"
	demoRunTape     = "docs/tutorial/scripts/run-tape.sh"
	demoSudoKeepers = "docs/tutorial/scripts/sudo-keepalive.sh"
)

// Demo regenerates every demo asset (full ~14-tape run, ~10 minutes).
// Pre-flight: vhs + ttyd on PATH, sudo timestamp live (`sudo -v`).
// Safe to run in the background — VHS records headlessly with no real window.
func Demo() error {
	mg.SerialDeps(Build)
	if err := buildWorkloadBinary(); err != nil {
		return err
	}
	if err := ensureDemoTooling(); err != nil {
		return err
	}
	if err := ensureSudoTimestamp(); err != nil {
		return err
	}

	tapes, err := filepath.Glob(filepath.Join(demoTapesDir, "*.tape"))
	if err != nil {
		return fmt.Errorf("glob tapes: %w", err)
	}
	if len(tapes) == 0 {
		return fmt.Errorf("no tape files found under %s", demoTapesDir)
	}
	slices.Sort(tapes)

	stopKeepalive, err := startSudoKeepalive()
	if err != nil {
		return fmt.Errorf("start sudo keep-alive: %w", err)
	}
	defer stopKeepalive()

	fmt.Printf("Demo: regenerating %d tapes...\n", len(tapes))
	for i, tape := range tapes {
		fmt.Printf("Demo: [%d/%d] %s\n", i+1, len(tapes), tape)
		if err := sh.RunV(demoRunTape, tape); err != nil {
			return fmt.Errorf("tape %s: %w", tape, err)
		}
	}
	fmt.Println("Demo: done.")
	return nil
}

// DemoOne regenerates a single tape. Pass TAPE=07-stream-live (basename without
// .tape) or TAPE=docs/tutorial/tapes/07-stream-live.tape (full path).
func DemoOne() error {
	mg.SerialDeps(Build)
	if err := buildWorkloadBinary(); err != nil {
		return err
	}
	if err := ensureDemoTooling(); err != nil {
		return err
	}
	if err := ensureSudoTimestamp(); err != nil {
		return err
	}

	tape := os.Getenv("TAPE")
	if tape == "" {
		return fmt.Errorf("TAPE env var is required (e.g. TAPE=07-stream-live)")
	}
	resolved, err := resolveDemoTape(tape)
	if err != nil {
		return err
	}
	fmt.Printf("Demo: regenerating %s\n", resolved)
	return sh.RunV(demoRunTape, resolved)
}

// InstallDemoTools installs VHS via `go install` and ttyd via dnf. Idempotent.
func InstallDemoTools() error {
	if _, err := exec.LookPath("vhs"); err != nil {
		fmt.Println("InstallDemoTools: installing vhs via `go install`...")
		if err := sh.RunV("go", "install", "github.com/charmbracelet/vhs@latest"); err != nil {
			return fmt.Errorf("install vhs: %w", err)
		}
	} else {
		fmt.Println("InstallDemoTools: vhs already installed.")
	}
	if _, err := exec.LookPath("ttyd"); err != nil {
		fmt.Println("InstallDemoTools: installing ttyd via dnf (sudo)...")
		if err := sh.RunV("sudo", "dnf", "install", "-y", "ttyd"); err != nil {
			return fmt.Errorf("install ttyd: %w", err)
		}
	} else {
		fmt.Println("InstallDemoTools: ttyd already installed.")
	}
	if err := sh.RunV("vhs", "--version"); err != nil {
		return err
	}
	return sh.RunV("ttyd", "--version")
}

func ensureDemoTooling() error {
	for _, bin := range []string{"vhs", "ttyd"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("%s not on PATH (run `mage installDemoTools`)", bin)
		}
	}
	return nil
}

// ensureSudoTimestamp returns nil only if `sudo -n true` succeeds. Otherwise it
// asks the user to pre-warm sudo and aborts.
func ensureSudoTimestamp() error {
	if os.Geteuid() == 0 {
		return nil
	}
	if err := sh.Run("sudo", "-n", "true"); err != nil {
		return fmt.Errorf("sudo timestamp not warm — run `sudo -v` once and re-invoke this target")
	}
	return nil
}

// startSudoKeepalive launches the sudo-keepalive script in the background and
// returns a stop function that terminates it.
func startSudoKeepalive() (func(), error) {
	if os.Geteuid() == 0 {
		return func() {}, nil
	}
	cmd := exec.Command("bash", demoSudoKeepers)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
	}, nil
}

// resolveDemoTape accepts a bare tape stem ("07-stream-live") or a full path
// and returns the existing tape file under demo/tapes/.
func resolveDemoTape(tape string) (string, error) {
	candidates := []string{
		tape,
		filepath.Join(demoTapesDir, tape),
		filepath.Join(demoTapesDir, tape+".tape"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("tape not found: tried %v", candidates)
}
