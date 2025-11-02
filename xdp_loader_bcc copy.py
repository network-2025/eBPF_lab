# =====================================================================================
# xdp_loader_bcc.py
#
# Function: Loads a C source file (xdp_ip_changer_kern.c), compiles it at runtime,
# and attaches the resulting eBPF program to the XDP hook of a user-specified network interface.
# Environment: This script uses the 'bcc' library.
#
# Prerequisites:
# 1. sudo apt-get install python3-bcc (or equivalent for your distribution)
# =====================================================================================

# The '#!/usr/bin/env python3' is a convention that tells the system to execute this script with python3.
#!/usr/bin/env python3

# =====================================================================================
# 1. Module Imports
# =====================================================================================
import time
import argparse
import sys
from bcc import BPF # Correctly importing the BCC library

parser = argparse.ArgumentParser(description="Load an eBPF XDP program to change IP addresses.")
parser.add_argument("-i", "--interface", required=True, help="Network interface to attach the XDP program to (e.g., eth0)")
args = parser.parse_args()

device = args.interface
c_file = "xdp_ip_changer_kern.c"
# This variable will hold our BPF object. We define it here to access it in the finally block.
b = None

try:
    # Use src_file to load the C source. BCC compiles it automatically in the background.
    b = BPF(src_file=c_file)
    # Load the specific function 'xdp_ip_changer' from the compiled source as an XDP program.
    fn = b.load_func("xdp_ip_changer", BPF.XDP)
    print(f"[*] Attaching XDP program from source ({c_file}) to device ({device})...")
    # Attach the loaded function to the XDP hook of the actual network device.
    # Once this function executes successfully, from this point on, every packet
    # coming into the device will pass through our eBPF program.
    b.attach_xdp(device, fn, 0)
    print(f"[*] Successfully attached!")
    print("[*] Press Ctrl+C to detach and exit.")
    # When the Python script exits, the eBPF program is automatically detached from the interface.
    # Therefore, we put the script into an infinite loop to keep the eBPF program running.
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    # This block is executed when the user presses Ctrl+C.
    print(f"\n[*] Detaching XDP program from device ({device})...")
except Exception as e:
    # This block is executed for any other unexpected errors.
    print(f"An error occurred: {e}", file=sys.stderr)
finally:
    # The `finally` block always executes to ensure the program is detached.
    # We call remove_xdp to clean up the attachment from the network device.
    if b:
        b.remove_xdp(device, 0)
    print("[*] Program detached. Exiting.")