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
#include "conntrack.h"
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

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
static inline int __inline__
__skb_redirect_to_proxy(struct __sk_buff *skb, struct bpf_sock_tuple *tuple, __u32 len, __u8 nexthdr)
{
	struct bpf_sock *sk = NULL;
	int result = DROP_PROXY_LOOKUP_FAILED;

	switch (nexthdr) {
	case IPPROTO_TCP:
		sk = sk_lookup_tcp(skb, tuple, len, BPF_F_CURRENT_NETNS, 0);
		break;
	case IPPROTO_UDP:
		sk = sk_lookup_udp(skb, tuple, len, BPF_F_CURRENT_NETNS, 0);
		break;
	}
	if (!sk) {
		// TODO: Return real error code here
		goto out;
	}

	skb->mark = MARK_MAGIC_TO_PROXY;
	skb_change_type(skb, PACKET_HOST); // Required ingress packets from overlay
	result = skb_set_socket(skb, sk, BPF_F_TPROXY) == 0 ? TC_ACT_OK : DROP_PROXY_SET_FAILED;
	sk_release(sk);
out:
	return result;
}

#ifdef ENABLE_IPV4
static inline int __inline__
skb_redirect_to_proxy4(struct __sk_buff *skb, struct ipv4_ct_tuple *tuple, __be16 proxy_port)
{
	struct bpf_sock_tuple *sk_tuple = (struct bpf_sock_tuple *)tuple;
	int result;
	__u16 port;

	/* tuple's mismatched dport/sport strikes again! */
	port = tuple->sport;
	tuple->dport = tuple->sport;
	tuple->sport = port;

	/* Look for established socket locally first */
	cilium_dbg3(skb, DBG_SK_LOOKUP4, sk_tuple->ipv4.saddr, sk_tuple->ipv4.daddr,
		(bpf_ntohs(sk_tuple->ipv4.dport) << 16) | bpf_ntohs(sk_tuple->ipv4.sport));
	result = __skb_redirect_to_proxy(skb, sk_tuple, sizeof(sk_tuple->ipv4),
					 tuple->nexthdr);
	if (result == TC_ACT_OK) {
		goto out;
	}

	/* If there's no established connection, locate the tproxy socket */
	sk_tuple->ipv4.dport = proxy_port;
	sk_tuple->ipv4.daddr = IPV4_GATEWAY;
	cilium_dbg3(skb, DBG_SK_LOOKUP4, sk_tuple->ipv4.saddr, sk_tuple->ipv4.daddr,
		(bpf_ntohs(sk_tuple->ipv4.dport) << 16) | bpf_ntohs(sk_tuple->ipv4.sport));
	result = __skb_redirect_to_proxy(skb, sk_tuple, sizeof(sk_tuple->ipv4),
					 tuple->nexthdr);

out:
	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_POST, proxy_port);
	return result;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static inline int __inline__
skb_redirect_to_proxy6(struct __sk_buff *skb, struct ipv6_ct_tuple *tuple, __be16 proxy_port)
{
	struct bpf_sock_tuple *sk_tuple = (struct bpf_sock_tuple *)tuple;
	int result;

	tuple->dport = proxy_port;
	// TODO: Fix up the tuple for proper lookup
	//tuple->daddr = jk
	result = __skb_redirect_to_proxy(skb, sk_tuple, sizeof(sk_tuple->ipv6),
					 tuple->nexthdr);
	cilium_dbg_capture(skb, DBG_CAPTURE_PROXY_POST, proxy_port);

	return result;
}
#endif /* ENABLE_IPV6 */
#endif /* defined(ENABLE_IPV4) || defined(ENABLE_IPV6) */

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
