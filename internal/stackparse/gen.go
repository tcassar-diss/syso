package stackparse

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type syscall_trace_t stackparse ../../bpf/stackparse.bpf.c
