// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
// #include "linux/netlink.h" - too many redefines, types etc.
#include "netlink_defines.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

// SEC("kprobe/netlink_unicast")
// void dump_netlink(struct sock *ssk, struct sk_buff *skb, __u32 portid, int nonblock) {
//     struct nlmsghdr * nm_nlh = (struct nlmsghdr *)skb->data;

//     // const char *nlmsg_type_str;
//     // switch(nm_nlh->nlmsg_type) {
//     //     case NETLINK_ROUTE:     nlmsg_type_str = "NETLINK_ROUTE"; break;
//     //     default:                nlmsg_type_str = "UNKNOWN";
//     // }

//     bpf_printk(" ++ nlmsghdr: {len=%d, type=%d",
//         nm_nlh->nlmsg_len, nm_nlh->nlmsg_type);

//     switch(nm_nlh->nlmsg_type) {
//         case NETLINK_ROUTE:     bpf_printk("NETLINK_ROUTE"); break;
//         default:                bpf_printk("UNKNOWN");
//     }

//     // bpf_printk(" ++ nlmsghdr: {len=%d, type=%d=%s",
//     //     nm_nlh->nlmsg_len, nm_nlh->nlmsg_type, nlmsg_type_str);
// }

// See https://lore.kernel.org/bpf/20200910202718.956042-1-yhs@fb.com/
// static const char *type[] = {"NETLINK_ROUTE"};

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

        bpf_printk(" ++ NETLINK nlmsghdr: {len=%d, type=%d, flags=%x}",
        nm_nlh.nlmsg_len, nm_nlh.nlmsg_type, nm_nlh.nlmsg_flags);

    switch(nm_nlh.nlmsg_type) {
        case NETLINK_ROUTE:             bpf_printk(" ++ type=%d NETLINK_ROUTE", nm_nlh.nlmsg_type); break;
        case NETLINK_UNUSED:            bpf_printk(" ++ type=%d NETLINK_UNUSED", nm_nlh.nlmsg_type); break;
        case NETLINK_USERSOCK:          bpf_printk(" ++ type=%d NETLINK_USERSOCK", nm_nlh.nlmsg_type); break;
        case NETLINK_FIREWALL:          bpf_printk(" ++ type=%d NETLINK_FIREWALL", nm_nlh.nlmsg_type); break;
        case NETLINK_SOCK_DIAG:         bpf_printk(" ++ type=%d NETLINK_SOCK_DIAG", nm_nlh.nlmsg_type); break;
        case NETLINK_NFLOG:             bpf_printk(" ++ type=%d NETLINK_NFLOG", nm_nlh.nlmsg_type); break;
        case NETLINK_XFRM:              bpf_printk(" ++ type=%d NETLINK_XFRM", nm_nlh.nlmsg_type); break;
        case NETLINK_SELINUX:           bpf_printk(" ++ type=%d NETLINK_SELINUX", nm_nlh.nlmsg_type); break;
        case NETLINK_ISCSI:             bpf_printk(" ++ type=%d NETLINK_ISCSI", nm_nlh.nlmsg_type); break;
        case NETLINK_AUDIT:             bpf_printk(" ++ type=%d NETLINK_AUDIT", nm_nlh.nlmsg_type); break;
        case NETLINK_FIB_LOOKUP:        bpf_printk(" ++ type=%d NETLINK_FIB_LOOKUP", nm_nlh.nlmsg_type); break;
        case NETLINK_CONNECTOR:         bpf_printk(" ++ type=%d NETLINK_CONNECTOR", nm_nlh.nlmsg_type); break;
        case NETLINK_NETFILTER:         bpf_printk(" ++ type=%d NETLINK_NETFILTER", nm_nlh.nlmsg_type); break;
        case NETLINK_IP6_FW:            bpf_printk(" ++ type=%d NETLINK_IP6_FW", nm_nlh.nlmsg_type); break;
        case NETLINK_DNRTMSG:           bpf_printk(" ++ type=%d NETLINK_DNRTMSG", nm_nlh.nlmsg_type); break;
        case NETLINK_KOBJECT_UEVENT:    bpf_printk(" ++ type=%d NETLINK_KOBJECT_UEVENT", nm_nlh.nlmsg_type); break;
        case NETLINK_GENERIC:           bpf_printk(" ++ type=%d NETLINK_GENERIC", nm_nlh.nlmsg_type); break;
        case NETLINK_SCSITRANSPORT:     bpf_printk(" ++ type=%d NETLINK_SCSITRANSPORT", nm_nlh.nlmsg_type); break;
        case NETLINK_ECRYPTFS:          bpf_printk(" ++ type=%d NETLINK_ECRYPTFS", nm_nlh.nlmsg_type); break;
        case NETLINK_RDMA:              bpf_printk(" ++ type=%d NETLINK_RDMA", nm_nlh.nlmsg_type); break;
        case NETLINK_CRYPTO:            bpf_printk(" ++ type=%d NETLINK_CRYPTO", nm_nlh.nlmsg_type); break;
        case NETLINK_SMC:               bpf_printk(" ++ type=%d NETLINK_SMC", nm_nlh.nlmsg_type); break;
        default:                        bpf_printk(" ++ type=%d UNKNOWN", nm_nlh.nlmsg_type);
    }


    if (nm_nlh.nlmsg_flags) {
        bpf_printk("  ++ FLAGS=0x%x:", nm_nlh.nlmsg_flags);
        if (nm_nlh.nlmsg_flags & 0x01) {
            bpf_printk("   ++ RQST");
        }
        if (nm_nlh.nlmsg_flags & 0x08) {
            bpf_printk("   ++ ECHO");
        }
        if (nm_nlh.nlmsg_flags & 0x04) {
            bpf_printk("   ++ ACK");
        }
        if (nm_nlh.nlmsg_flags & 0x02) {
            bpf_printk("   ++ MULTI");
        }
        
        // TODO - only for GET requests, need to decode
        if (nm_nlh.nlmsg_flags & 0x800) {
            bpf_printk("   ++ DUMP");
        }
        if (nm_nlh.nlmsg_flags & 0x400) {
            bpf_printk("   ++ ATOMIC");
        }
        if (nm_nlh.nlmsg_flags & 0x200) {
            bpf_printk("   ++ MATCH");
        }
        if (nm_nlh.nlmsg_flags & 0x100) {
            bpf_printk("   ++ ROOT");
        }
    }
}

SEC("kprobe/netlink_unicast")
int BPF_KPROBE(netlink_unicast, struct sock *ssk, struct sk_buff *skb, __u32 portid, int nonblock)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_printk("> KPROBE netlink_unicast ENTER: {pid = %d, tid=%d}", pid, tid);
    dump_netlink(ssk, skb, portid, nonblock);

	return 0;
}

SEC("kretprobe/netlink_unicast")
int BPF_KRETPROBE(netlink_unicast_exit, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t tid = bpf_get_current_pid_tgid() & 0xffffffff;
	bpf_printk("< KPROBE netlink_unicast EXIT: {pid = %d, tid=%d, ret = %ld}", pid, tid, ret);
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
	bpf_printk("< KPROBE netlink_broadcast_exit EXIT: {pid = %d, tid=%d, ret = %ld}", pid, tid, ret);
	return 0;
}
