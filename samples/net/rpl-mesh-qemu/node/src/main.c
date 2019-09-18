/*
 * Copyright (c) 2017 CPqD Foundation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>

#include <zephyr.h>
#include <kernel.h>
#include <limits.h>
#include <zephyr/types.h>


#include <net/net_pkt.h>
#include <net/net_core.h>

#include "ipv6.h"
#include "icmpv6.h"
#include "nbr.h"
#include "route.h"
#include "rpl.h"
#include "net_stats.h"

#define PKT_WAIT_TIME K_SECONDS(1)
int send_udp_send(void *data, int len);

int send_udp_send(void *data, int len)
{
	struct net_pkt *pkt;
	struct in6_addr *dst;
	const struct in6_addr *src;
	struct net_if *iface;
	int ret;

	u8_t dst_addr[16] = {254, 128, 0, 0, 0, 0,
			0, 0, 2, 16, 32, 48, 170, 170, 170, 170};
	iface = net_if_get_default();
	if (!iface) {
		printk("cannot get iface\n");
		return -1;
	}
	pkt = net_pkt_alloc_with_buffer(iface,
					sizeof(struct net_ipv6_hdr) +
					sizeof(struct net_udp_hdr) +
					len,
					AF_INET6, IPPROTO_UDP,
					PKT_WAIT_TIME);
	src = net_if_ipv6_get_ll(iface,
		NET_ADDR_PREFERRED);

	if (net_ipv6_create(pkt, src, dst_addr) ||
		net_udp_create(pkt, 8000, 8000)) {
		net_pkt_unref(pkt);
		return -2;
	}
	net_pkt_write(pkt, data, len);
	net_pkt_cursor_init(pkt);
	net_ipv6_finalize(pkt, IPPROTO_UDP);
	net_pkt_cursor_init(pkt);
	for (int i = 0; i < pkt->cursor.buf->size; i++) {
		printk("%x ", *(pkt->cursor.pos+i));
	}
	ret = net_send_data(pkt);
	if (ret >= 0) {
		net_stats_update_udp_sent(iface);
	}
	net_pkt_unref(pkt);
	return ret;
};


void main(void)
{
	printk("RPL node running\n");
	while (1) {
		int k;

		k_sleep(3000);
		u8_t dst_addr[16] = {254, 128, 0, 0, 0, 0, 0, 0,
			2, 16, 32, 48, 170, 170, 170, 170};
		printk(" TEST SEND\n");
		k = send_udp_send(dst_addr, 16);
		printk("%d\n", k);
	}
}
