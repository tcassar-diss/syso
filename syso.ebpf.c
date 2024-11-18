//go:build exclude

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <stdbool.h>

#define N_MMAP 9
#define N_MUNMAP 11
#define N_MREMAP 25
#define N_BRK 12

struct sc_event {
    pid_t pid;
    u64 timestamp;
    u64 syscall_nr;
    u64 pc;
    bool dirty;
};

struct sc_event *unused __attribute__((unused));

// struct {
//  __uint(type, BPF_MAP_TYPE_ARRAY);
//  __uint(max_entries, 64);
// } ppid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} sc_events_map SEC(".maps");

// Guide for raw tracepoint handling: https://mozillazg.com/2022/05/ebpf-libbpf-raw-tracepoint-common-questions-en.html

SEC("raw_tp/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    pid_t calling_pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    unsigned long syscall_nr = ctx->args[1];
    
    volatile struct pt_regs *regs;
    regs = (struct pt_regs*)ctx->args[0];

    if (!regs) {
        return 0;
    }
    
    u64 t = bpf_ktime_get_ns();

    struct sc_event *e;
    e = bpf_ringbuf_reserve(&sc_events_map, sizeof(struct sc_event), 0);

    if (!e) {
        return 0;
    }

    e->pid = calling_pid;
    e->timestamp = t;
    e->syscall_nr = syscall_nr;
    e->dirty = (syscall_nr == N_MMAP) || (syscall_nr == N_MUNMAP) || (syscall_nr == N_MREMAP) || (syscall_nr == N_BRK);

    u64 ip;
    bpf_probe_read(&ip, sizeof(ip), &regs->ip);// todo
    
    bpf_ringbuf_submit(e, 0);

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
