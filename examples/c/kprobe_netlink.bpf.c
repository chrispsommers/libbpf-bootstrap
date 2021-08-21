// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/netlink_unicast")
int BPF_KPROBE(netlink_unicast, struct sock *ssk, struct sk_buff *skb, __u32 portid, int nonblock)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE netlink_unicast pid = %d, portid=%08x\n", pid, portid);
	return 0;
}

SEC("kretprobe/netlink_unicast")
int BPF_KRETPROBE(netlink_unicast_exit, long ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE netlink_unicast_exit EXIT: pid = %d, ret = %ld\n", pid, ret);
	return 0;
}

SEC("kprobe/netlink_broadcast")
int BPF_KPROBE(netlink_broadcast, struct sock *ssk, struct sk_buff *skb, __u32 portid, int nonblock)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE netlink_broadcast pid = %d, portid=%08x\n", pid, portid);
	return 0;
}

SEC("kretprobe/netlink_broadcast")
int BPF_KRETPROBE(netlink_broadcast_exit, long ret)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE netlink_broadcast EXIT: pid = %d, ret = %ld\n", pid, ret);
	return 0;
}
