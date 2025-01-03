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
// AllSyscalls represents a count of all system calls (processed or dropped).
type MissedStats struct {
	RingBufFull          uint64 `json:"ringbuf_full"`
	GetCurrentTaskFailed uint64 `json:"get_current_task_failed"`
	GetParentFailed      uint64 `json:"get_parent_failed"`
	GetPTRegsFailed      uint64 `json:"get_pt_regs_failed"`

	// AllSyscalls is the number of times the bpf program was invoked.
	AllSyscalls uint64 `json:"all_syscalls"`

	// RelevantSyscalls are syscalls which are made by the traced process or its children.
	RelevantSyscalls uint64 `json:"relevant_syscalls"`
	IgnorePID        uint64 `json:"follow_ignore_pid"`
	EmptyStacktrace  uint64 `json:"empty_stack_trace"`
}

const nSysoFailureTypes = int32(sysoFailureTypeFAILURE_TYPE_END)
