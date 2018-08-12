/*
 *  Copyright (C) 2018 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include "lib/probes/comm.h"

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(connect_events);

struct connect_event {
	u32 pid;
	u32 saddr;
	u32 daddr;
	u16 dport;
	u16 type;
	u64 sockaddr;
};

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk,
			   struct sockaddr_in __user *usin, int __user addr_len)
{
	u32 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &sk);

	struct connect_event event = {
		.pid = pid,
		.dport = usin->sin_port,
		.saddr = sk->__sk_common.skc_rcv_saddr,
		.daddr = usin->sin_addr.s_addr,
		.type = PROBE_ENTER_CONNECT,
		.sockaddr = (u64)sk,
	};

	connect_events.perf_submit(ctx, &event, sizeof(event));

	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;

	struct connect_event event = {
		.pid = pid,
		.type = PROBE_UNKNOWN,
	};

	skpp = currsock.lookup(&pid);
	if (skpp != NULL) {
		struct sock *sk = *skpp;

		event.saddr = sk->__sk_common.skc_rcv_saddr;
		event.daddr = sk->__sk_common.skc_daddr;
		event.dport = sk->__sk_common.skc_dport;
		event.type = PROBE_RETURN_CONNECT;
		event.sockaddr = (u64)sk;
	}

	connect_events.perf_submit(ctx, &event, sizeof(event));

skip:
	currsock.delete(&pid);

	return 0;
};

BPF_PERF_OUTPUT(comm_events);

int syscall__execve(struct pt_regs *ctx,
	const char __user *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;

	struct comm_event event = {
		.pid = tgid,
		.type = PROBE_ENTER_EXECUTE,
	};

	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	comm_events.perf_submit(ctx, &event, sizeof(event));

	return 0;
}

int syscall__exit(struct pt_regs *ctx)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;

	struct comm_event event = {
		.pid = tgid,
		.type = PROBE_ENTER_EXIT,
	};

	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	comm_events.perf_submit(ctx, &event, sizeof(event));

	return 0;
}
