package syso

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type sc_event -type stack_trace_t -type failure_type syso ../bpf/syso.bpf.c
