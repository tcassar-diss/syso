package syso

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type sc_event syso ../bpf/syso.ebpf.c
