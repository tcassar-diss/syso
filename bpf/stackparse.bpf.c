//go:build exclude
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Maximum number of frames to report */
#define MAX_STACK_DEPTH 100
#define MAX_SYSCALL_TRACE_ENTRIES 1024
/*
todos: (todo: remove)
    - report stack for each syscall
    - pull [PC] for each syscall
    - combine with naive for a program which

    for each syscall, log
        - stack
        - syscall number
        - timestamp
        - dirty
*/


/* from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf/progs/test_get_stack_rawtp.c?h=v5.2 */
struct syscall_trace_t {
    pid_t pid;
    int user_stack_size;
    __u64 user_stack[MAX_STACK_DEPTH];
    struct bpf_stack_build_id user_stack_buildid[MAX_STACK_DEPTH];
};

struct syscall_trace_t *unused_syscall_trace __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_SYSCALL_TRACE_ENTRIES);
} syscall_trace_map SEC(".maps");

SEC("raw_tp/sys_enter")
int syscall_stacktrace(struct bpf_raw_tracepoint_args *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
