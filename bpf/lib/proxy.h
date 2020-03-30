/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __LIB_PROXY_H_
#define __LIB_PROXY_H_

#include "conntrack.h"

#if !(__ctx_is == __ctx_skb)
#error "Proxy redirection is only supported from skb context"
#endif

/* TODO: Fix up this detection logic */
#define BPF__PROG_TYPE_sched_act__HELPER_bpf_sk_assign 1
#ifdef BPF__PROG_TYPE_sched_act__HELPER_bpf_sk_assign

#ifdef BPF__PROG_TYPE_sched_act__HELPER_bpf_skc_lookup_udp
#define HAVE_SKC_LOOKUP_FLAGS
#endif

/**
 * proxy_port_enchant
 * @proxy_port Port to add magic to
 *
 * Convert the specified port into a magic number for interaction with other
 * subsystems.
 */
static __always_inline __u32
proxy_port_enchant(__u32 proxy_port)
{
	return MARK_MAGIC_TO_PROXY | proxy_port << 16;
}

/**
 * proxy_port_disenchant
 * @magic Magic number to convert to proxy_port
 *
 * Convert the specified magic number back into a proxy port.
 */
static __always_inline __be16
proxy_port_disenchant(__u32 magic)
{
	if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY)
		return magic >> 16;
	return 0;
}

static __always_inline int
assign_socket_tcp(struct __ctx_buff *ctx,
		  struct bpf_sock_tuple *tuple, __u32 len, bool established)
{
#ifdef HAVE_SKC_LOOKUP_FLAGS
	__u64 flags = established ? BPF_F_SKL_NO_LISTEN : BPF_F_SKL_NO_EST;
#else
	__u64 flags = 0;
#endif
	int result = DROP_PROXY_LOOKUP_FAILED;
	struct bpf_sock *sk = NULL;

	sk = skc_lookup_tcp(ctx, tuple, len, BPF_F_CURRENT_NETNS, flags);
	if (!sk)
		goto out;

	if (established && sk->state == BPF_TCP_TIME_WAIT)
		goto release;
#ifndef HAVE_SKC_LOOKUP_FLAGS
	if (established && sk->state == BPF_TCP_LISTEN)
		goto release;
#endif

	result = sk_assign(ctx, sk, 0);
	cilium_dbg(ctx, DBG_SK_ASSIGN, -result, sk->family << 16 | ctx->protocol);
	if (result == 0)
		result = CTX_ACT_OK;
	else
		result = DROP_PROXY_SET_FAILED;
release:
	sk_release(sk);
out:
	return result;
}

static __always_inline int
assign_socket_udp(struct __ctx_buff *ctx,
		  struct bpf_sock_tuple *tuple, __u32 len,
		  bool established __maybe_unused)
{
#ifdef HAVE_SKC_LOOKUP_FLAGS
	//__u64 flags = established ? BPF_F_SKL_NO_LISTEN : BPF_F_SKL_NO_EST;
	// TODO: Fix bug in submit/bpf-skc-lookup-udp_v0.8 with established
	//__u64 flags = established ? BPF_F_SKL_NO_LISTEN : 0;
	__u64 flags = 0;
#else
	__u64 flags = 0;
#endif
	int result = DROP_PROXY_LOOKUP_FAILED;
	struct bpf_sock *sk = NULL;

	sk = sk_lookup_udp(ctx, tuple, len, BPF_F_CURRENT_NETNS, flags);
	if (!sk)
		goto out;

	result = sk_assign(ctx, sk, 0);
	cilium_dbg(ctx, DBG_SK_ASSIGN, -result, sk->family << 16 | ctx->protocol);
	if (result == 0)
		result = CTX_ACT_OK;
	else
		result = DROP_PROXY_SET_FAILED;
	sk_release(sk);
out:
	return result;
}

static __always_inline int
assign_socket(struct __ctx_buff *ctx,
	      struct bpf_sock_tuple *tuple, __u32 len,
	      __u8 nexthdr, bool established)
{
	/* Workaround: While the below functions are nearly identical in C
	 * implementation, the 'struct bpf_sock *' has a different verifier
	 * pointer type, which means we can't fold these implementations
	 * together. */
	switch (nexthdr) {
	case IPPROTO_TCP:
		return assign_socket_tcp(ctx, tuple, len, established);
	case IPPROTO_UDP:
		return assign_socket_udp(ctx, tuple, len, established);
	}
	return DROP_PROXY_UNKNOWN_PROTO;
}

static __always_inline __u32
combine_ports(__u16 dport, __u16 sport)
{
	return (bpf_ntohs(sport) << 16) | bpf_ntohs(dport);
}

/**
 * ctx_redirect_to_proxy4
 * @ctx Pointer to program context
 * @tuple Pointer to *scratch buffer* with packet tuple inside
 * @proxy_port Port to redirect traffic towards
 *
 * Prefetch the proxy socket and associate with the ctx. Must be run on TC
 * ingress. Will modify 'tuple'!
 */
static __always_inline int
ctx_redirect_to_proxy4(struct __ctx_buff *ctx, __be16 proxy_port,
		       struct bpf_sock_tuple *tuple, __u32 len, __u8 nexthdr)
{
#ifdef ENABLE_IPV4
	int result;

	/* Look for established socket locally first */
	cilium_dbg3(ctx, DBG_SK_LOOKUP4, tuple->ipv4.saddr, tuple->ipv4.daddr,
		    combine_ports(tuple->ipv4.dport, tuple->ipv4.sport));
	result = assign_socket(ctx, tuple, len, nexthdr, true);
	if (result == CTX_ACT_OK) {
		 goto out;
	}

	/* If there's no established connection, locate the tproxy socket */
	tuple->ipv4.dport = proxy_port;
	tuple->ipv4.sport = 0;
	tuple->ipv4.daddr = 0;
	tuple->ipv4.saddr = 0;
	cilium_dbg3(ctx, DBG_SK_LOOKUP4, tuple->ipv4.saddr, tuple->ipv4.daddr,
		    combine_ports(tuple->ipv4.dport, tuple->ipv4.sport));
	result = assign_socket(ctx, tuple, len, nexthdr, false);

out:
	cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_POST, proxy_port);
	return result;
#else /* ENABLE_IPV4 */
	return DROP_PROXY_UNKNOWN_PROTO;
#endif /* ENABLE_IPV4 */
}
#endif /* BPF__PROG_TYPE_sched_act__HELPER_bpf_sk_assign */

static __always_inline int
ct4_redirect_to_proxy(struct __ctx_buff *ctx __maybe_unused,
		      struct ipv4_ct_tuple *tuple __maybe_unused,
		       __be16 proxy_port __maybe_unused)
{
#ifdef BPF__PROG_TYPE_sched_act__HELPER_bpf_sk_assign
	struct bpf_sock_tuple *sk_tuple = (struct bpf_sock_tuple *)tuple;
	__u32 len = sizeof(sk_tuple->ipv4);
	__u8 nexthdr = tuple->nexthdr;
	__u16 port;

	/* tuple's mismatched dport/sport strikes again! */
	port = tuple->sport;
	tuple->sport = tuple->dport;
	tuple->dport = port;

	return ctx_redirect_to_proxy4(ctx, proxy_port, sk_tuple, len, nexthdr);
#else /* BPF__PROG_TYPE_sched_act__HELPER_bpf_sk_assign */
	return DROP_PROXY_UNKNOWN_PROTO;
#endif /* BPF__PROG_TYPE_sched_act__HELPER_bpf_sk_assign */
}

#endif /* __LIB_PROXY_H_ */
