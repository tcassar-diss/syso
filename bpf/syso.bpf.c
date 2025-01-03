//go:build exclude

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <stdbool.h>

// "Dirty" syscalls
#define N_MMAP 9
#define N_MUNMAP 11
#define N_MREMAP 25
#define N_BRK 12

#define MAX_STACK_RAWTP 64
#define MAX_RINGBUF_ENTRIES 4096 * 1024 * MAX_STACK_RAWTP  // must be a multiple of 4096, adjusted for new stack traces


enum failure_type {
    RINGBUF_FULL,
    GET_TASK_FAILED,
    GET_PARENT_FAILED,
    GET_PT_REGS_FAILED,
    ALL_SYSCALLS, /* ALL_SYSCALLS is the number of times that the raw_tp program is called: of these, only monitor syscalls from relevant TGIDs */
    RELEVANT_SYSCALLS, /* RELEVANT_SYSCALLS is the number of syscalls that were made by the target executable or its forks */
    IGNORE_WRONG_PID,
    EMPTY_STACKTRACE,
    FAILURE_TYPE_END,
};

#define N_FAILURE_TYPES FAILURE_TYPE_END

/*
Record the user stack for each syscall
(
    using code sample
    https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf/progs/test_get_stack_rawtp.c?h=v5.2
)
*/
struct stack_trace_t {
    int64_t user_stack_size;
    int64_t user_stack_buildid_size;
    __u64 user_stack[MAX_STACK_RAWTP];
};

struct sc_event {
    pid_t pid;  /* userland tgid */
    pid_t ppid; /* userland ptgid */
    u64 timestamp;
    u64 syscall_nr;
    u64 pc;
    struct stack_trace_t stacktrace;  /* cannot be a ptr or verifier complains */
    bool dirty;
};

struct sc_event *unused_sc_event __attribute__((unused));
enum failure_type *unused_failure_type __attribute__((unused));
struct stack_trace_t *unused_stack_trace __attribute__((unused));

/* follow_pid_map needs to be configured in userspace with the calling process's PID */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(pid_t));
	__uint(value_size, sizeof(bool));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} follow_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_RINGBUF_ENTRIES);
} sc_events_map SEC(".maps");


/* err_map needs to be configured in userspace, with all counts set to 0 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, N_FAILURE_TYPES);
    __uint(map_flags, 0);
} err_map SEC(".maps");


__always_inline void log_failure(enum failure_type failure) {
    u64 *p_count = bpf_map_lookup_elem(&err_map, &failure);
    if (!p_count)
        return;

    __sync_fetch_and_add(p_count, 1);
}


SEC("raw_tp/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    log_failure(ALL_SYSCALLS);

    pid_t parent_tgid;
    pid_t calling_tgid;
    unsigned long syscall_nr;
    u64 timestamp;
    struct stack_trace_t *usr_stacktrace;

    struct task_struct *task;
    struct task_struct *parent_task;

    volatile struct pt_regs *regs;
    struct sc_event *e;

    const bool tr = true;
    const bool fs = false;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        log_failure(GET_TASK_FAILED);
        return 1;
    }

    bpf_probe_read(&parent_task, sizeof(parent_task), &task->real_parent);
    if (!parent_task) {
        log_failure(GET_PARENT_FAILED);
        return 1;
    }

    bpf_probe_read(&parent_tgid, sizeof(parent_tgid), &parent_task->tgid);

    bool follow = bpf_map_lookup_elem(&follow_pid_map, &parent_tgid);
    if (!follow) {
        log_failure(IGNORE_WRONG_PID);
        return 0;
    }

    calling_tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_map_update_elem(&follow_pid_map, &calling_tgid, &tr, 0);

    regs = (struct pt_regs*)ctx->args[0];
    if (!regs) {
        log_failure(GET_PT_REGS_FAILED);
        return 1;
    }

    e = bpf_ringbuf_reserve(&sc_events_map, sizeof(struct sc_event), 0);
    if (!e) {
        log_failure(RINGBUF_FULL);
        return 1;
    }

    log_failure(RELEVANT_SYSCALLS);

    timestamp = bpf_ktime_get_ns();
    syscall_nr = ctx->args[1];

    e->pid = calling_tgid;
    e->ppid = parent_tgid;
    e->timestamp = timestamp;
    e->syscall_nr = syscall_nr;
    e->dirty = (syscall_nr == N_MMAP) || (syscall_nr == N_MUNMAP) || (syscall_nr == N_MREMAP) || (syscall_nr == N_BRK);

    int max_len, max_buildid_len;
    max_len = MAX_STACK_RAWTP * sizeof(__u64);
    max_buildid_len = MAX_STACK_RAWTP * sizeof(struct bpf_stack_build_id);

    e->stacktrace.user_stack_size = bpf_get_stack(ctx, e->stacktrace.user_stack, max_len,
					    BPF_F_USER_STACK);
    
    // todo: remove, redundant: will always be the top of the user stack
    u64 ip;
    bpf_probe_read(&ip, sizeof(ip), &regs->ip);

    e->pc = ip;

    bpf_ringbuf_submit(e, 0);

    return 0;
}


char LICENSE[] SEC("license") = "GPL";

