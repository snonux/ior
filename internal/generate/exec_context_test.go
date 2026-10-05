package generate

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// execContextState tracks context aliases through the compiled probe's branches
// and stack spills. 0 is a scalar, 1 the original ctx and 2 a modified ctx.
// Helpers accept modified ctx addresses, but direct loads from them are illegal
// for a tracepoint program. This is the verifier rejection that broke CI;
// newer LLVM versions happened to avoid the offending optimization.
type execContextState struct {
	pc    int
	regs  [11]uint8
	stack [64]uint8
}

func TestExecProbeNeverDereferencesAModifiedContext(t *testing.T) {
	compiler := os.Getenv("IOR_TEST_BPF_CLANG")
	if compiler == "" {
		compiler = "clang"
	}
	libbpfgo := os.Getenv("LIBBPFGO")
	if libbpfgo == "" {
		libbpfgo = filepath.Join("..", "..", "..", "libbpfgo")
	}
	object := filepath.Join(t.TempDir(), "exec.o")
	cmd := exec.Command(compiler, "-g", "-O2", "-fpie", "-target", "bpf",
		"-D__TARGET_ARCH_amd64", "-I"+filepath.Join(libbpfgo, "output"),
		"-c", filepath.Join("..", "c", "ior.bpf.c"), "-o", object)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile production BPF probe: %v\n%s", err, output)
	}
	f, err := elf.Open(object)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	section := f.Section("tracepoint/sched/sched_process_exec")
	if section == nil {
		t.Fatal("compiled object has no exec probe")
	}
	code, err := section.Data()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkExecContextLoads(code, f.ByteOrder); err != nil {
		t.Fatal(err)
	}
}

func TestExecContextCheckerRejectsUnsafeLoads(t *testing.T) {
	// Each instruction is opcode, src/dst register byte, signed jump/stack
	// offset. Arithmetic uses immediate 16; helpers use id 1.
	tests := []struct {
		name string
		code []byte
		bad  bool
	}{
		{"empty", nil, true},
		{"truncated", []byte{0x95}, true},
		{"jump outside probe", execContextCode([3]int{0x05, 0, 20}), true},
		{"direct ctx load", execContextCode([3]int{0x61, 0x10, 16}, [3]int{0x95}), false},
		{"modified ctx", execContextCode([3]int{0x07, 0x01}, [3]int{0x61, 0x10}, [3]int{0x95}), true},
		{"move alias", execContextCode([3]int{0xbf, 0x16}, [3]int{0x07, 0x06}, [3]int{0x61, 0x60}, [3]int{0x95}), true},
		{"self move", execContextCode([3]int{0xbf, 0x11}, [3]int{0x07, 0x01}, [3]int{0x61, 0x10}, [3]int{0x95}), true},
		{"stack alias", execContextCode([3]int{0x7b, 0x1a, -8}, [3]int{0x79, 0xa6, -8}, [3]int{0x07, 0x06}, [3]int{0x61, 0x60}, [3]int{0x95}), true},
		{"conditional path", execContextCode([3]int{0x15, 0, 1}, [3]int{0x07, 0x01}, [3]int{0x61, 0x10}, [3]int{0x95}), true},
		{"loaded scalar", execContextCode([3]int{0x61, 0x16, 16}, [3]int{0x07, 0x06}, [3]int{0x61, 0x60}, [3]int{0x95}), false},
		{"helper address and clobber", execContextCode([3]int{0x07, 0x01}, [3]int{0x85}, [3]int{0x61, 0x10}, [3]int{0x95}), false},
		{"helper preserves alias", execContextCode([3]int{0xbf, 0x16}, [3]int{0x85}, [3]int{0x07, 0x06}, [3]int{0x61, 0x60}, [3]int{0x95}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkExecContextLoads(tt.code, binary.LittleEndian)
			if (err != nil) != tt.bad {
				t.Fatalf("checkExecContextLoads() = %v, want rejected=%v", err, tt.bad)
			}
		})
	}
}

func execContextCode(insns ...[3]int) []byte {
	code := make([]byte, len(insns)*8)
	for i, insn := range insns {
		slot := code[i*8 : (i+1)*8]
		slot[0], slot[1] = byte(insn[0]), byte(insn[1])
		binary.LittleEndian.PutUint16(slot[2:4], uint16(int16(insn[2])))
		binary.LittleEndian.PutUint32(slot[4:8], 16)
		if insn[0] == 0x85 {
			binary.LittleEndian.PutUint32(slot[4:8], 1)
		}
	}
	return code
}

func checkExecContextLoads(code []byte, order binary.ByteOrder) error {
	if len(code) == 0 || len(code)%8 != 0 {
		return fmt.Errorf("invalid exec probe instruction length: %d", len(code))
	}
	initial := execContextState{}
	initial.regs[1] = 1
	pending := []execContextState{initial}
	seen := make(map[execContextState]bool)
	for len(pending) > 0 {
		state := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[state] {
			continue
		}
		seen[state] = true
		if state.pc < 0 || state.pc >= len(code)/8 {
			return fmt.Errorf("exec probe jumps outside its instructions: %d", state.pc)
		}
		insn := code[state.pc*8 : (state.pc+1)*8]
		dst, src := int(insn[1]&15), int(insn[1]>>4)
		if dst >= len(state.regs) || src >= len(state.regs) {
			return fmt.Errorf("invalid exec probe register at %d", state.pc)
		}
		offset := int(int16(order.Uint16(insn[2:4])))
		if err := applyExecContextInstruction(&state, insn[0], dst, src, offset); err != nil {
			return err
		}
		pending = append(pending, nextExecContextStates(state, insn[0], offset)...)
	}
	return nil
}

func nextExecContextStates(state execContextState, op byte, offset int) []execContextState {
	var next []execContextState
	class := op & 7
	if class == 5 || class == 6 {
		switch op & 0xf0 {
		case 0x90: // exit
			return nil
		case 0x80: // call: r0-r5 are clobbered by the helper
			for i := 0; i <= 5; i++ {
				state.regs[i] = 0
			}
		default:
			branch := state
			branch.pc += offset + 1
			next = append(next, branch)
			if op&0xf0 == 0 { // unconditional jump
				return next
			}
		}
	}
	state.pc++
	if op == 0x18 { // second half of a 64-bit immediate
		state.pc++
	}
	return append(next, state)
}

func applyExecContextInstruction(state *execContextState, op byte, dst, src, offset int) error {
	switch op & 7 {
	case 0: // load immediate
		state.regs[dst] = 0
	case 1: // load memory
		if state.regs[src] == 2 {
			return fmt.Errorf("exec probe instruction %d dereferences a modified ctx", state.pc)
		}
		state.regs[dst] = 0
		if src == 10 && offset >= -512 && offset < 0 && op&0x18 == 0x18 {
			state.regs[dst] = state.stack[(offset+512)/8]
		}
	case 2, 3: // store immediate or register
		if dst == 10 && offset >= -512 && offset < 0 {
			value := uint8(0)
			if op&7 == 3 && op&0x18 == 0x18 {
				value = state.regs[src]
			}
			state.stack[(offset+512)/8] = value
		}
	case 4, 7: // ALU32/ALU64
		if op&0xf0 == 0xb0 { // mov
			value := uint8(0)
			if op&8 != 0 {
				value = state.regs[src]
			}
			state.regs[dst] = value
		} else if state.regs[dst] != 0 {
			state.regs[dst] = 2
		}
	}
	return nil
}
