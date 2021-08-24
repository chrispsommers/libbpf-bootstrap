// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Keysight Technologies
 * Based on kprobe.bpf.c by Facebook

   This example probes kernel Netlink messages and prints minimal info extracted form the message header.
   Further decoding could be performed e.g. using libnl.
   For an excellent description of Netlink message format, see:
   https://www.infradead.org/~tgr/libnl/doc/core.html#core_netlink_fundamentals
   https://man7.org/linux/man-pages/man7/netlink.7.html
 */

#include "vmlinux.h"
// #include "linux/netlink.h" // compile errors - too many redefines, duplicate types etc.
#include "netlink_defines.h"  // #defines only from "linux/netlink.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static const char netlink_msgtype[][24] = {
    "NETLINK_ROUTE",
    "NETLINK_UNUSED",
    "NETLINK_USERSOCK",
    "NETLINK_FIREWALL",
    "NETLINK_SOCK_DIAG",
    "NETLINK_NFLOG",
    "NETLINK_XFRM",
    "NETLINK_SELINUX",
    "NETLINK_ISCSI",
    "NETLINK_AUDIT",
    "NETLINK_FIB_LOOKUP",
    "NETLINK_CONNECTOR",
    "NETLINK_NETFILTER",
    "NETLINK_IP6_FW",
    "NETLINK_DNRTMSG",
    "NETLINK_KOBJECT_UEVENT",
    "NETLINK_GENERIC",
    "NETLINK_PLACEHOLDER",
    "NETLINK_SCSITRANSPORT",
    "NETLINK_ECRYPTFS",
    "NETLINK_RDMA",
    "NETLINK_CRYPTO",
    "NETLINK_SMC"
};

__always_inline
void dump_netlink(struct sock *ssk, struct sk_buff *skb, __u32 portid, int nonblock) {

    // get copy of Netlink msg hdr into our stack
    // cannot deref skb->data directly, use helper to copy its address into local var
    // see https://lists.iovisor.org/g/iovisor-dev/topic/invalid_mem_access_when/21385886
    struct nlmsghdr * nm_nlh_skb = (struct nlmsghdr *)(&skb->data);
    bpf_probe_read(&nm_nlh_skb, sizeof(nm_nlh_skb), &skb->data);
    // now copy skb->data into local copy of netlink msg hdr
    struct nlmsghdr nm_nlh;
    bpf_probe_read(&nm_nlh, sizeof(nm_nlh), nm_nlh_skb);

    bpf_printk("   ++ NETLINK nlmsghdr: {len=%d, type=%d, flags=%x}",
    nm_nlh.nlmsg_len, nm_nlh.nlmsg_type, nm_nlh.nlmsg_flags);

    switch(nm_nlh.nlmsg_type) {
        case NETLINK_ROUTE:
        case NETLINK_UNUSED:
        case NETLINK_USERSOCK:
        case NETLINK_FIREWALL:
        case NETLINK_SOCK_DIAG:
        case NETLINK_NFLOG:
        case NETLINK_XFRM:
        case NETLINK_SELINUX:
        case NETLINK_ISCSI:
        case NETLINK_AUDIT:
        case NETLINK_FIB_LOOKUP:
        case NETLINK_CONNECTOR:
        case NETLINK_NETFILTER:
        case NETLINK_IP6_FW:
        case NETLINK_DNRTMSG:
        case NETLINK_KOBJECT_UEVENT:
        case NETLINK_GENERIC:
        case NETLINK_SCSITRANSPORT:
        case NETLINK_ECRYPTFS:
        case NETLINK_RDMA:
        case NETLINK_CRYPTO:
        case NETLINK_SMC:
            bpf_printk("    ++ type=%d=%s", nm_nlh.nlmsg_type, netlink_msgtype[nm_nlh.nlmsg_type]);
            break;
        default:
            bpf_printk("    ++ type=%d UNKNOWN", nm_nlh.nlmsg_type);
    }

    // see https://www.infradead.org/~tgr/libnl/doc/core.html#core_msg_types
    if (nm_nlh.nlmsg_flags) {
        bpf_printk("    ++ FLAGS=0x%x:", nm_nlh.nlmsg_flags);

        if (nm_nlh.nlmsg_flags & NLM_F_REQUEST) {
            bpf_printk("     ++ RQST");
        }
        if (nm_nlh.nlmsg_flags & NLM_F_MULTI) {
            bpf_printk("     ++ MULTI");
        }
        if (nm_nlh.nlmsg_flags & NLM_F_ACK) {
            bpf_printk("     ++ ACK");
        }
        if (nm_nlh.nlmsg_flags & NLM_F_ECHO) {
            bpf_printk("     ++ ECHO");
        }
        if (nm_nlh.nlmsg_flags & NLM_F_DUMP_INTR) {
            bpf_printk("     ++ DUMP_INTR");
        }
        if (nm_nlh.nlmsg_flags & NLM_F_DUMP_FILTERED) {
            bpf_printk("     ++ DUMP_FILTERED");
        }

        // overloaded bit positions, context-dependent
        // first alternative is for GET requests, second is for NEW or SET requests
        if (nm_nlh.nlmsg_flags & NLM_F_DUMP) { // combination of NLM_F_ROOT|NLM_F_MATCH
            bpf_printk("     ++ DUMP");
        } else { // not combined, so check individual flags
            if (nm_nlh.nlmsg_flags & 0x100) {
                bpf_printk("     ++ ROOT or REPLACE or NONREC or CAPPED");
            }
            if (nm_nlh.nlmsg_flags & 0x200) {
                bpf_printk("     ++ MATCH or EXCL or ACK_TLVS");
            }
        }
        if (nm_nlh.nlmsg_flags & 0x400) {
            bpf_printk("     ++ ATOMIC or CREATE");
        }
        if (nm_nlh.nlmsg_flags & NLM_F_APPEND) {
            bpf_printk("APPEND");
        }
    }
    // Note, there are more flag bits defined but it require more message decoding to extract context,
    // because the bit positions are overloaded (e.g. 0x100,0x200,0x400 can have multiple meanings).
}

SEC("kprobe/netlink_unicast")
int BPF_KPROBE(netlink_unicast, struct sock *ssk, struct sk_buff *skb, __u32 portid, int nonblock)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_printk("> KPROBE netlink_unicast ENTER: {pid = %d, tid=%d, portid = %d}", pid, tid, portid);
    // print in hex too because portid may encode pid/tid in some cases, and also may appear as negative if in decimal
	bpf_printk("                                {pid = 0x%x, tid=0x%x, portid = 0x%x}", pid, tid, portid);
    dump_netlink(ssk, skb, portid, nonblock);
	return 0;
}

SEC("kretprobe/netlink_unicast")
int BPF_KRETPROBE(netlink_unicast_exit, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t tid = bpf_get_current_pid_tgid() & 0xffffffff;
    // print in hex too because portid may encode pid/tid in some cases, and also may appear as negative if in decimal
	bpf_printk("< KPROBE netlink_unicast EXIT:  {pid = %d, tid=%d, ret = %ld}", pid, tid, ret);
	return 0;
}

SEC("kprobe/netlink_broadcast")
int BPF_KPROBE(netlink_broadcast, struct sock *ssk, struct sk_buff *skb, __u32 portid, int nonblock)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_printk("> KPROBE netlink_broadcast ENTER: {pid = %d, tid=%d}", pid, tid);
    dump_netlink(ssk, skb, portid, nonblock);
	return 0;
}

SEC("kretprobe/netlink_broadcast")
int BPF_KRETPROBE(netlink_broadcast_exit, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_printk("< KPROBE netlink_broadcast_exit EXIT:  {pid = %d, tid=%d, ret = %ld}", pid, tid, ret);
	return 0;
}
