/*
 * xdp_ip_changer_kern.c (BCC Compatible Version)
 *
 * Function: Uses an XDP hook to change the source IP address of all incoming IPv4
 * packets on a network interface to 1.1.1.1, and updates the L3/L4 checksums accordingly.
 * Environment: This code is written for use with the BCC (BPF Compiler Collection) framework.
 */

// The best way to find which header a specific struct (e.g., struct iphdr)
// belongs to is to search for the struct name on a Linux Kernel source code search
// website like Elixir Bootlin (https://elixir.bootlin.com).
#include <uapi/linux/bpf.h>      // Contains core BPF definitions (e.g., struct xdp_md, XDP_PASS).
#include <uapi/linux/if_ether.h> // For the Ethernet header (struct ethhdr) and protocol constants (ETH_P_IP).
#include <uapi/linux/ip.h>       // For the IPv4 header (struct iphdr).
#include <uapi/linux/tcp.h>      // For the TCP header (struct tcphdr).
#include <uapi/linux/udp.h>      // For the UDP header (struct udphdr).
#include <uapi/linux/in.h>       // For protocol number constants (IPPROTO_TCP, IPPROTO_UDP).
// Network communication uses big-endian as its standard, but most PC CPUs use little-endian.
// Therefore, a conversion is necessary when sending data over the network or interpreting packet data.
// The most accurate information on this concept can be found in the Linux man pages.
// Run the `man byteorder` command in your terminal.
// https://gcc.gnu.org/onlinedocs/gcc/Byte-Swapping-Builtins.html
// hton -> host to network
#ifndef bpf_hton_32
#define bpf_hton_32(x) __builtin_bswap32(x)
#endif
// define it using the compiler built-in to swap the byte order of a 32-bit value (Host to Network Long).
#ifndef bpf_hton_16
#define bpf_hton_16(x) __builtin_bswap16(x)
#endif
// define it using the compiler built-in to swap the byte order of a 16-bit value (Host to Network Short).
// Defines the new source IP address (1.1.1.1) as a constant.
// It is converted to network byte order at compile time using bpf_hton_32().
#define NEW_SADDR bpf_hton_32(0x01010101)


// =====================================================================================
// 4. Custom Checksum Update Function for Compatibility
// =====================================================================================
// Older kernels may not support modern helper functions like bpf_l3_csum_replace.
// By implementing the checksum update logic manually using the bpf_csum_diff helper,
// we can ensure compatibility with nearly all kernel versions.
//
// static: Restricts the scope of this function to the current file, preventing name collisions.
// inline: Suggests to the compiler that it should copy-paste the function code at the
//         call site instead of making a function call, optimizing performance and
//         bypassing the BPF Verifier's constraints on function calls.
// The behavior of `bpf_csum_diff`, the core of this function, is detailed in the BPF helper functions man page.
// Source: Run `man bpf-helpers` in your terminal and search for `bpf_csum_diff`.
// __sum16: A type representing a 16-bit checksum field.
// __be32: A type representing a 32-bit big-endian (network byte order) integer.
// __s64: A type representing a 64-bit signed integer.
/*
     Available in `man bpf-helpers`
       s64 bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32
       to_size, __wsum seed)

           Description
                   Compute a checksum difference, from the raw buffer
                   pointed by from, of length from_size (that must be a
                   multiple of 4), towards the raw buffer pointed by
                   to, of size to_size (same remark). An optional seed
                   can be added to the value (this can be cascaded, the
                   seed may come from a previous call to the helper).

                   This is flexible enough to be used in several ways:

                   • With from_size == 0, to_size > 0 and seed set to
                     checksum, it can be used when pushing new data.

                   • With from_size > 0, to_size == 0 and seed set to
                     checksum, it can be used when removing data from a
                     packet.

                   • With from_size > 0, to_size > 0 and seed set to 0,
                     it can be used to compute a diff. Note that
                     from_size and to_size do not need to be equal.

                   This helper can be used in combination with
                   bpf_l3_csum_replace() and bpf_l4_csum_replace(), to
                   which one can feed in the difference computed with
                   bpf_csum_diff().

           Return The checksum result, or a negative error code in
                   case of failure.
*/
static inline void csum_replace4(__sum16 *csum, __be32 from, __be32 to) {
    //Use bpf_csum_diff to calculate the checksum difference between the old value (from) and the new value (to).
    __s64 diff = bpf_csum_diff(&from, sizeof(from), &to, sizeof(to), 0);
    if (diff != 0) {
        // Step 2: Apply (add) the difference calculated in Step 1 to the actual checksum field (*csum).
        bpf_csum_diff(NULL, 0, csum, sizeof(__sum16), diff);
    }
}

/*
  Defined in include/uapi/linux/bpf.h
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    //Below access go through struct xdp_rxq_info
    __u32 ingress_ifindex;  //rxq->dev->ifindex
    __u32 rx_queue_index;   //rxq->queue_index

    __u32 egress_ifindex;   // txq->dev->ifindex
};
*/
/*
  Defined in include/uapi/linux/if_ether.h
struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];   // destination eth addr
    unsigned char   h_source[ETH_ALEN]; // source ether addr
    __be16          h_proto;            // packet type ID field
} __attribute__((packed)); */


// =====================================================================================
// 5. Main XDP Program Function
// =====================================================================================
// This is the main logic that is attached to the XDP hook and executed for each incoming packet.
int xdp_ip_changer(struct xdp_md *ctx) {
    // ctx is metadata passed by the kernel to the XDP program.
    // Get the start address (data) and end address (data_end) of the packet data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    // Ethernet Header Parsing and Validation
    // The outermost header of the packet is the Ethernet header.
    struct ethhdr *eth = data;

    // BPF Boundary Check: We must prevent the BPF program from accessing memory
    // beyond the end of the packet. The BPF Verifier will not load the program without such checks.
    // https://docs.cilium.io/en/stable/reference-guides/bpf/index.html
    // More details are in the document above, but for now, we just accept it as a requirement.
    // We must always check if "current pointer + size to read > end of data".
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_PASS; 
        // If the packet is shorter than an Ethernet header, don't process it and pass it to the kernel.
        // It could be an unknown protocol or a test packet, so let the upper layers handle it.
    }
    // If the Ethernet frame's protocol type is not IPv4 (0x0800), do not process it.
    // Use `bpf_hton_16` to compare with the network byte order value.
    if (eth->h_proto != bpf_hton_16(ETH_P_IP)) {
        return XDP_PASS;
    }
    // The IP header is located immediately after the Ethernet header.
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) { // Check if there's enough space for a minimal IP header (20 bytes).
        return XDP_PASS;
    }
    // The 'IHL' (Internet Header Length) field in the IP header specifies the header length in 4-byte words.
    // If IP options are included, the header can be longer than 20 bytes, so we must calculate the exact length.
    __u32 ip_header_len = ip->ihl * 4;
    if ((void *)ip + ip_header_len > data_end) { // Check if there's enough space for the actual calculated header length.
        return XDP_PASS;
    }
    __be32 old_saddr = ip->saddr; // Store the original IP address to use later for checksum calculation.
    __be32 new_saddr = NEW_SADDR;
    // Overwrite the source IP address with the new address.
    ip->saddr = new_saddr;
    // Update the L3 (IP) checksum. Since the IP address has changed, the checksum must also be changed.
    csum_replace4(&ip->check, old_saddr, new_saddr);
    // The L4 (TCP/UDP) checksum is calculated based on a Pseudo-header,
    // which includes the source/destination IP addresses. 
    // Therefore, if the IP address changes, the L4 checksum must also be recalculated.
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_header_len; // The TCP header is right after the IP header.
        if ((void *)tcp + sizeof(*tcp) <= data_end) {    // Check if there is space for the TCP header.
            csum_replace4(&tcp->check, old_saddr, new_saddr); // Update TCP checksum.
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_header_len; // The UDP header is right after the IP header.
        if ((void *)udp + sizeof(*udp) <= data_end) {    // Check if there is space for the UDP header.
            // The UDP checksum is optional and can be zero. Only update it if it's not zero.
            if (udp->check != 0) {
                csum_replace4(&udp->check, old_saddr, new_saddr); // Update UDP checksum.
            }
        }
    }

    // `XDP_PASS`: Means packet processing is complete, and this (modified) packet should
    // continue up to the kernel's network stack. To drop the packet, return `XDP_DROP`.
    /*
     Defined in include/uapi/linux/bpf.h
     enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
    };
    */
    return XDP_PASS;
}

// =====================================================================================
// 6. License Declaration
// =====================================================================================
// To be loaded into the kernel, an eBPF program must specify a GPL-compatible license.
// This is because some powerful BPF helper functions are restricted to programs
// that have a GPL license. In BCC, this is handled by declaring a `char LICENSE[]` variable.
//
// [Guideline] The licensing policy is explained in the BPF helper functions man page.
// Source: Run `man bpf-helpers` and check the 'LICENSE' section.
char LICENSE[] = "GPL";