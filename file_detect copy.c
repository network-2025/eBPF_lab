#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/*
Event payload we define to send to user space.
- This is NOT a kernel-provided struct; it's our custom payload format.
- It will be delivered to user space as-is via a perf(per cpu) ring buffer (map).
 */
struct file_event_t {
    u32 pid;                  // using (bpf_get_current_pid_tgid() >> 32) yields TGID (process ID).
    u32 uid;                  // Caller’s UID. We use the lower 32 bits of bpf_get_current_uid_gid().
    char comm[TASK_COMM_LEN]; // Current task's command name. Up to 16 bytes (including NUL).
    char fname[256];          // File path passed to openat (read from user memory).
};

/*
BCC macro-BPF_PERF_OUTPUT: define a perf ring buffer map.
- Name: file_events
- The eBPF program pushes events into this buffer via perf_submit(),
- and user space (Python BCC) consumes them with open_perf_buffer().
*/
BPF_PERF_OUTPUT(file_events);

/*
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
- eBPF function attached to the sys_enter_openat tracepoint.
- 'args' here is a pointer to an auto-generated struct provided by BCC,
exposing the tracepoint fields (dfd, filename, flags, mode, etc.) as 'args->field_name
!!! The exact shape of this struct is derived from the kernel's tracepoint !!! 
    to find format metadata:
    sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
    or
    sudo bpftrace -lv 'tracepoint:syscalls:sys_enter_openat'
*/
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    // Allocate one event record on the eBPF stack (~280B, below the 512B stack limit).
    struct file_event_t evt = {};

    /*
    Fetch pid/tgid, uid/gid, and comm using eBPF helpers.
    bpf_get_current_pid_tgid():
    - returns 64 bits: upper 32 = TGID (thread group ID == process ID), lower 32 = PID (thread ID)
    - Here we store TGID into evt.pid (>> 32).
    If you need TID (thread ID), cast to (u32) to use the lower 32 bits.
    */
    evt.pid = bpf_get_current_pid_tgid() >> 32;

    /*
    bpf_get_current_uid_gid():
    - returns 64 bits: lower 32 = UID, upper 32 = GID
    - evt.uid is u32, so only the lower 32 bits (UID) are stored.
    */
    evt.uid = bpf_get_current_uid_gid();

    /*
    Copy current task's comm (process name) into evt.comm.
    - The helper guarantees NUL termination.
    */
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    /*
    Safely read the user pointer 'filename' passed to openat.
    - bpf_probe_read_user_str(): reads a NUL-terminated string from user memory.
    - Copies up to the given size and guarantees NUL termination.
    - Returns a negative error code on failure; here we just attempt the read.
    'args->filename' is a field from the *tracepoint struct*.
    (With kprobes, you would fetch arguments from registers instead.)
    (we can find the functions that can attach kprobes with command below.)
    sudo cat /sys/kernel/debug/tracing/available_filter_functions | less
    */
    bpf_probe_read_user_str(&evt.fname, sizeof(evt.fname), args->filename);

    /*
    Submit the collected event to the perf ring buffer.
    - Passing 'args' as the first argument is a common BCC convention for ctx(context pointer).
    - User space consumes it via b["file_events"].open_perf_buffer(...).
    */
    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
