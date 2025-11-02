# BCC (BPF Compiler Collection) Python bindings
from bcc import BPF

# --------------------------------------------------------------------
# 1) Load eBPF C source
#    - Read file_detect.c from the same directory.
#    - file_detect.c defines our struct file_event_t and
#      TRACEPOINT_PROBE(syscalls, sys_enter_openat).
#      - The kernel tracepoint provides the filename argument, and the
#        eBPF program sends events to a perf ring buffer.
# --------------------------------------------------------------------
with open("file_detect.c") as f:
    bpf_source = f.read()

# --------------------------------------------------------------------
# 2) Compile & load eBPF
#    - BCC uses LLVM/Clang to compile the C code and then loads the
#      resulting BPF program into the kernel.
# --------------------------------------------------------------------
b = BPF(text=bpf_source)

# --------------------------------------------------------------------
# 3) Attach the tracepoint
#    - For TRACEPOINT_PROBE(syscalls, sys_enter_openat) in C, the
#      function name in Python is "tracepoint__syscalls__sys_enter_openat".
#    - Some environments autoload, but here we attach explicitly.
# --------------------------------------------------------------------
# try:
#     b.attach_tracepoint(tp="syscalls:sys_enter_openat",
#                         fn_name="tracepoint__syscalls__sys_enter_openat")
# except Exception as e:
#     print(f"[!] Failed to attach tracepoint: {e}")
#     raise SystemExit(1)

# --------------------------------------------------------------------
# 4) Event callback
#    - The eBPF side defined BPF_PERF_OUTPUT(file_events), and pushes
#      struct file_event_t via file_events.perf_submit().
#    - b["file_events"].event(data) parses that C struct layout directly,
#      so we can access event.pid / event.uid / event.comm / event.fname.
# --------------------------------------------------------------------
def on_file_event(cpu, data, size):
    event = b["file_events"].event(data)

    # Safely convert C char arrays to Python strings
    comm  = event.comm.decode(errors="ignore")
    fname = event.fname.decode(errors="ignore").rstrip("\x00")

    # Watch target: detect access to /etc/shadow
    if fname == "/etc/shadow":
        print(f"[*] ALERT: /etc/shadow accessed! "
              f"(PID: {event.pid}, Proc: {comm}, UID: {event.uid})")
    else:
        # Informational log (remove if too noisy)
        print(f"[i] Skipped: {fname} "
              f"(PID: {event.pid}, Proc: {comm}, UID: {event.uid})")

# --------------------------------------------------------------------
# 5) Open perf buffer & polling loop
#    - Register the callback with open_perf_buffer().
#    - perf_buffer_poll() blocks and dispatches events to the callback.
#    - Keep looping so the program stays alive and processes events.
# --------------------------------------------------------------------
b["file_events"].open_perf_buffer(on_file_event)

print("[*] Monitoring for /etc/shadow access... (Press Ctrl+C to stop)")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[!] Detaching BPF program and exiting...")
finally:
    # Deleting 'b' lets BCC detach the tracepoint and clean up maps
    del b
    print("[*] BPF program detached successfully.")
