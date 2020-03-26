/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_PROXY_H_
#define __LIB_PROXY_H_

#include "conntrack.h"

#if !(__ctx_is == __ctx_skb)
#error "Proxy redirection is only supported from skb context"
#endif

#define BPF__PROG_TYPE_sched_act__HELPER_bpf_skc_lookup_udp 1
#ifdef BPF__PROG_TYPE_sched_act__HELPER_bpf_skc_lookup_udp
#define HAVE_SKC_LOOKUP_FLAGS
#endif

static __always_inline int
assign_socket(struct __ctx_buff *ctx,
	      struct bpf_sock_tuple *tuple, __u32 len __maybe_unused,
	      __u8 nexthdr, bool established)
{
	struct bpf_sock *sk = NULL;
	int result = DROP_PROXY_LOOKUP_FAILED;

	/* Not perfect, but the same series that introduces lookup flags
	 * introduces the bpf_skc_lookup_udp() helper. */
#ifdef HAVE_SKC_LOOKUP_FLAGS
	//__u64 flags = established ? BPF_F_SKL_NO_LISTEN : BPF_F_SKL_NO_EST;
	//__u64 flags = established ? BPF_F_SKL_NO_LISTEN : 0;
	__u64 flags = 0;
#else
	__u64 flags = 0;
#endif

	switch (nexthdr) {
	case IPPROTO_TCP:
		//sk = skc_lookup_tcp(ctx, tuple, len, BPF_F_CURRENT_NETNS, flags);
		break;
#ifdef BPF__PROG_TYPE_sched_act__HELPER_bpf_skc_lookup_udp
	case IPPROTO_UDP:
		sk = sk_lookup_udp(ctx, tuple, len, BPF_F_CURRENT_NETNS, flags);
		break;
#endif
	default:
		return DROP_PROXY_UNKNOWN_PROTO;
	}
	if (!sk)
		goto out;

	if (nexthdr == IPPROTO_TCP) {
		if (established && sk->state == BPF_TCP_TIME_WAIT)
			goto release;
#ifndef HAVE_SKC_LOOKUP_FLAGS
		if (established && sk->state == BPF_TCP_LISTEN)
			goto release;
#endif
	}

	// TODO: Return real error code here
	result = sk_assign(ctx, sk, 0);
	cilium_dbg(ctx, DBG_SK_ASSIGN, -result, 0);
	if (result == 0)
		result = CTX_ACT_OK;
	else
		result = DROP_PROXY_SET_FAILED;
release:
	sk_release(sk);
out:
	return result;
}

static __always_inline __u32
combine_ports(__u16 dport, __u16 sport)
{
	return (bpf_ntohs(sport) << 16) | bpf_ntohs(dport);
}

static __always_inline int
ctx_redirect_to_proxy4(struct __ctx_buff *ctx, struct ipv4_ct_tuple *tuple,
		       __be16 proxy_port)
{
#ifdef ENABLE_IPV4
	struct bpf_sock_tuple *sk_tuple = (struct bpf_sock_tuple *)tuple;
	int result;
	__u16 port;

	/* tuple's mismatched dport/sport strikes again! */
	port = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = port;

	/* Look for established socket locally first */
	cilium_dbg3(ctx, DBG_SK_LOOKUP4,
		    sk_tuple->ipv4.saddr, sk_tuple->ipv4.daddr,
		    combine_ports(sk_tuple->ipv4.dport, sk_tuple->ipv4.sport));
	result = assign_socket(ctx, sk_tuple, sizeof(sk_tuple->ipv4),
			       tuple->nexthdr, true);
	if (result == CTX_ACT_OK) {
		 goto out;
	}

	/* If there's no established connection, locate the tproxy socket */
	sk_tuple->ipv4.dport = proxy_port;
	sk_tuple->ipv4.sport = 0;
	sk_tuple->ipv4.daddr = 0;
	sk_tuple->ipv4.saddr = 0;
	cilium_dbg3(ctx, DBG_SK_LOOKUP4,
		    sk_tuple->ipv4.saddr, sk_tuple->ipv4.daddr,
		     combine_ports(sk_tuple->ipv4.dport, sk_tuple->ipv4.sport));
	result = assign_socket(ctx, sk_tuple, sizeof(sk_tuple->ipv4),
			       tuple->nexthdr, false);

out:
	cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_POST, proxy_port);
	return result;
#else /* ENABLE_IPV4 */
	return DROP_PROXY_UNKNOWN_PROTO;
#endif /* ENABLE_IPV4 */
}

#endif /* __LIB_PROXY_H_ */
