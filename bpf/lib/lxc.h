/*
 *  Copyright (C) 2016-2019 Authors of Cilium
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
#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "utils.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "trace.h"
#include "csum.h"
#include "l4.h"

#define TEMPLATE_LXC_ID 0xffff

#ifndef DISABLE_SIP_VERIFICATION
static inline int is_valid_lxc_src_ip(struct ipv6hdr *ip6)
{
#ifdef ENABLE_IPV6
	union v6addr valid = {};

	BPF_V6(valid, LXC_IP);

	return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
#else
	return 0;
#endif
}

static inline int is_valid_lxc_src_ipv4(struct iphdr *ip4)
{
#ifdef ENABLE_IPV4
	return ip4->saddr == LXC_IPV4;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else
static inline int is_valid_lxc_src_ip(struct ipv6hdr *ip6)
{
	return 1;
}

static inline int is_valid_lxc_src_ipv4(struct iphdr *ip4)
{
	return 1;
}
#endif

static inline int __inline__
__skb_redirect_to_proxy(struct __sk_buff *skb, struct bpf_sock_tuple *tuple, __u32 len, __u8 nexthdr)
{
	struct bpf_sock *sk = NULL;

	switch (nexthdr) {
	case IPPROTO_TCP:
		sk = sk_lookup_tcp(skb, tuple, len, BPF_F_CURRENT_NETNS, 0);
	case IPPROTO_UDP:
		sk = sk_lookup_udp(skb, tuple, len, BPF_F_CURRENT_NETNS, 0);
	default:
		break;
	}
	if (!sk) {
		// TODO: Return real error code here
		return TC_ACT_SHOT;
	}

	skb->mark = MARK_MAGIC_TO_PROXY;
	skb_change_type(skb, PACKET_HOST); // Required ingress packets from overlay
	skb_set_socket(skb, sk);
	sk_release(sk);

	return TC_ACT_OK;
}

static inline int __inline__
skb_redirect_to_proxy4(struct __sk_buff *skb, struct ipv4_ct_tuple *tuple, __be16 proxy_port)
{
	struct bpf_sock_tuple *sk_tuple = (struct bpf_sock_tuple *)tuple;
	int result;

	tuple->dport = proxy_port;
	result = __skb_redirect_to_proxy(skb, sk_tuple, sizeof(sk_tuple->ipv4),
					 tuple->nexthdr);
	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_POST, proxy_port);

	return result;
}

static inline int __inline__
skb_redirect_to_proxy6(struct __sk_buff *skb, struct ipv6_ct_tuple *tuple, __be16 proxy_port)
{
	struct bpf_sock_tuple *sk_tuple = (struct bpf_sock_tuple *)tuple;
	int result;

	tuple->dport = proxy_port;
	result = __skb_redirect_to_proxy(skb, sk_tuple, sizeof(sk_tuple->ipv6),
					 tuple->nexthdr);
	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_POST, proxy_port);

	return result;
}

/**
 * tc_index_is_from_proxy - returns true if packet originates from ingress proxy
 */
static inline bool __inline__ tc_index_skip_proxy(struct __sk_buff *skb)
{
	volatile __u32 tc_index = skb->tc_index;
#ifdef DEBUG
	if (tc_index & TC_INDEX_F_SKIP_PROXY)
		cilium_dbg(skb, DBG_SKIP_PROXY, tc_index, 0);
#endif

	return tc_index & TC_INDEX_F_SKIP_PROXY;
}
#endif /* __LIB_LXC_H_ */
