/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _OFPI_APP_H
#define _OFPI_APP_H

#include <odp.h>
#include "api/ofp_types.h"
#include "api/ofp_pkt_processing.h"
#include "ofpi_in.h"
#include "ofpi_odp_compat.h"

struct ip_out {
	struct ofp_ifnet *dev_out;
	struct ofp_nh_entry *nh;
	struct ofp_ip *ip;
	struct ofp_nh_entry nh_vxlan;
	int out_port;
	uint32_t gw;
#ifdef OFP_PKT_FLOW_CACHE
    /* TODO: This is just l3 forward demo. Final solution should provide
     *       own flow cache context (pkt->user_ctx or pkt->buf_hdr.udata)
     */ 
	uint16_t vlan_in;
#endif
	uint16_t vlan;
	uint16_t vrf;
	uint8_t is_local_address;
};

enum ofp_return_code send_pkt_burst_out(struct ofp_ifnet *dev,
			odp_packet_t pkt);
enum ofp_return_code send_pkt_out(struct ofp_ifnet *dev,
			odp_packet_t pkt);
enum ofp_return_code send_pkt_loop(struct ofp_ifnet *dev,
			odp_packet_t pkt);

enum ofp_return_code ipv4_transport_classifier(odp_packet_t pkt,
			uint8_t ip_proto);
enum ofp_return_code ipv6_transport_classifier(odp_packet_t pkt,
			uint8_t ip6_nxt);

int ofp_send_pkt_burst_out_init_local(void);
int ofp_send_pkt_burst_out_term_local(void);

#endif /* _OFPI_APP_H */
