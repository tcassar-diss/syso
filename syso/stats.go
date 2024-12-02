package syso

// Stat represents a single complete statistic about a system call
type Stat struct {
	SyscallNr uint64 `json:"syscall_nr"`
	Library   string `json:"library"`
	Pid       int32  `json:"pid"`
	Ppid      int32  `json:"ppid"`
	Timestamp uint64 `json:"timestamp"`
}

// MissedStats are counts and reasons why a syscall wasn't reported
//
// All represents a count of all system calls (processed or dropped).
type MissedStats struct {
	RingBufFull     uint64 `json:"ringbuf_full"`
	GetParentFailed uint64 `json:"get_parent_failed"`
	GetPTRegsFailed uint64 `json:"get_pt_regs_failed"`
	All             uint64 `json:"all"`
}

// TODO: figure out some way to have this generated from the macro in bpf/syso.bpf.c
const nSysoFailureTypes = 4
