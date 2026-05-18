package types

// AllSyscallFamilies returns the dashboard display order for broad syscall families.
func AllSyscallFamilies() []SyscallFamily {
	return []SyscallFamily{
		FamilyNetwork,
		FamilyMemory,
		FamilySignals,
		FamilySched,
		FamilyIPC,
		FamilyTime,
		FamilyProcess,
		FamilySecurity,
		FamilyFS,
		FamilyPolling,
		FamilyAIO,
		FamilyMisc,
	}
}

// IsFileSyscallFamily reports whether family belongs to file-system/syscall-fd views.
func IsFileSyscallFamily(family SyscallFamily) bool {
	return family == FamilyFS
}

// IsNonIOSyscallFamily reports whether family should appear in the Non-IO tab.
func IsNonIOSyscallFamily(family SyscallFamily) bool {
	return family != "" && !IsFileSyscallFamily(family)
}

// SyscallFamilyRank returns the stable display rank for a family.
func SyscallFamilyRank(family SyscallFamily) int {
	for idx, candidate := range AllSyscallFamilies() {
		if candidate == family {
			return idx
		}
	}
	return len(AllSyscallFamilies())
}
