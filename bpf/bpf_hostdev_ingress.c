// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/common.h"
#include "lib/proxy.h"
#include "lib/dbg.h"

__section("to-host")
int to_host(struct __ctx_buff *ctx)
{
	__u32 magic = ctx_load_meta(ctx, 0);
	int ret = CTX_ACT_OK;

	if ((magic & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {
		ctx->mark = ctx_load_meta(ctx, CB_ENCRYPT_MAGIC);
		set_identity(ctx, ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY));
	} else {
		__be16 proxy_port = proxy_port_disenchant(magic);

		if (proxy_port) {
			ret = ctx_redirect_to_proxy(ctx, proxy_port);
			/* TODO: Register drops */
			cilium_dbg_capture(ctx, DBG_CAPTURE_PROXY_POST, proxy_port);
		}
	}

	return ret;
}

BPF_LICENSE("GPL");
