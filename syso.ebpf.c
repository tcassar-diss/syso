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
    pid_t pid;  // userland tgid
    pid_t ppid; // userland ptgid
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
    __uint(max_entries, 1048576);
} sc_events_map SEC(".maps");

// Guide for raw tracepoint handling: https://mozillazg.com/2022/05/ebpf-libbpf-raw-tracepoint-common-questions-en.html

SEC("raw_tp/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    pid_t calling_tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct task_struct *p_task;
    bpf_probe_read(&p_task, sizeof(p_task), &task->real_parent);
    if (!p_task)
        return 0;

    pid_t ppid;
    bpf_probe_read(&ppid, sizeof(ppid), &p_task->tgid);

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

    e->pid = calling_tgid;
    e->ppid = ppid;
    e->timestamp = t;
    e->syscall_nr = syscall_nr;
    e->dirty = (syscall_nr == N_MMAP) || (syscall_nr == N_MUNMAP) || (syscall_nr == N_MREMAP) || (syscall_nr == N_BRK);

    u64 ip;
    bpf_probe_read(&ip, sizeof(ip), &regs->ip);// todo
    
    e->pc = ip;

    bpf_ringbuf_submit(e, 0);

    return 0;
}


char LICENSE[] SEC("license") = "GPL";
