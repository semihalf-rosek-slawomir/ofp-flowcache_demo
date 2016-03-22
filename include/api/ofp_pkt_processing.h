/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_APP_H__
#define __OFP_APP_H__

#include <odp.h>
#include "ofp_types.h"
#include "ofp_init.h"

typedef enum ofp_return_code (*ofp_pkt_processing_func)(odp_packet_t pkt);

struct ofp_ifnet;

void *default_event_dispatcher(void *arg);

enum ofp_return_code ofp_packet_input(odp_packet_t pkt,
	odp_queue_t in_queue, ofp_pkt_processing_func pkt_func);

/* Packet Burst API for defered processing
 */
void ofp_packet_pre_rt_enq(odp_packet_t pkt);
void ofp_packet_input_enq(odp_packet_t pkt);
void ofp_packet_output_enq(odp_packet_t pkt);
void ofp_packet_post_rt_enq(odp_packet_t pkt, struct ofp_ifnet *dev);

/* Packet Burst API for immediate processing
 */
void ofp_packet_pre_rt_burst(odp_packet_t pkt_table[], size_t len,
    ofp_pkt_processing_func pkt_func);
void ofp_packet_output_burst(odp_packet_t pkt_table[], size_t len,
    ofp_pkt_processing_func pkt_func);

enum ofp_return_code ofp_eth_vlan_processing(odp_packet_t pkt);
enum ofp_return_code ofp_ipv4_processing(odp_packet_t pkt);
enum ofp_return_code ofp_ipv6_processing(odp_packet_t pkt);
enum ofp_return_code ofp_gre_processing(odp_packet_t pkt);
enum ofp_return_code ofp_arp_processing(odp_packet_t pkt);
enum ofp_return_code ofp_udp4_processing(odp_packet_t pkt);
enum ofp_return_code ofp_tcp4_processing(odp_packet_t pkt);

enum ofp_return_code ofp_send_frame(struct ofp_ifnet *dev, odp_packet_t pkt);
enum ofp_return_code ofp_send_pending_pkt_burst(void);

enum ofp_return_code ofp_ip_output(odp_packet_t pkt,
	struct ofp_nh_entry *nh_param);
struct ofp_ip_moptions;
struct inpcb;
enum ofp_return_code ofp_ip_output_opt(odp_packet_t pkt, odp_packet_t opt,
        struct ofp_nh_entry *nh_param, int flags,
	struct ofp_ip_moptions *imo, struct inpcb *inp);
enum ofp_return_code ofp_ip6_output(odp_packet_t pkt,
	struct ofp_nh6_entry *nh_param);

enum ofp_return_code ofp_sp_input(odp_packet_t pkt,
	struct ofp_ifnet *ifnet);

#endif /*__OFP_APP_H__*/
