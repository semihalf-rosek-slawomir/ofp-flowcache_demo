#ifndef __OFPI_PKT_FLOWCACHE_H__
#define __OFPI_PKT_FLOWCACHE_H__

#include <stdint.h>
#include "ofpi_pkt_processing.h"

/* TODO: This is just l3 forward demo. Final solution should provide
 *       more complex flow key. Some NIC's do flow hashing so it also
 *       could be used for better performance (under proper configs).
 */
struct flow_key {
//    uint32_t vrf;
    uint32_t ip_dst;
};

enum flow_type {

    /* TODO: This is just l3 forward demo. Final solution should provide
     *       all possible flow types, for example:
     *
     *  OFP_FLOW_ETH_IPV4_UDP_INPUT
     *  OFP_FLOW_ETH_IPV4_UDP_OUTPUT
     *  OFP_FLOW_ETH_IPV4_TCP_INPUT
     *  OFP_FLOW_ETH_IPV4_TCP_OUTPUT
     *
     *  and more (IPV6, GRE, VXLAN...)
     */ 
    OFP_FLOW_ETH_IPV4_FORWARD,
    OFP_FLOW_ETH_IPV4_TAG_FORWARD,
    OFP_FLOW_VETH_IPV4_FORWARD,
    OFP_FLOW_VETH_IPV4_UNTAG_FORWARD,
};

struct ether_header {
#if 0
    /* TODO: Some NIC's do additional packet alignments, so final
     *       solution could provide proper configs.
     */
    uint8_t __padding[6];
#endif
    uint8_t ether_dhost[OFP_ETHER_ADDR_LEN];
    uint8_t ether_shost[OFP_ETHER_ADDR_LEN];
	uint16_t ether_type;
};

struct ether_vlan_header {
#if 0
    /* TODO: Some NIC's do additional packet alignments, so final
     *       solution could provide proper configs.
     */
    uint8_t __padding[2];
#endif
	uint8_t evl_dhost[OFP_ETHER_ADDR_LEN];
	uint8_t evl_shost[OFP_ETHER_ADDR_LEN];
	uint16_t evl_encap_proto;
	uint16_t evl_tag;
	uint16_t evl_proto;
};

struct inet_header {
    uint8_t __padding[12];
    uint32_t ip_src;
    uint32_t ip_dst;
};

struct ipv4_out {
    struct ofp_ifnet *dev_out;
    struct ether_header ether_header;
    struct inet_header inet_header;
};

struct ipv4_out_vlan {
    struct ofp_ifnet *dev_out;
    struct ether_vlan_header ether_vlan_header;
    struct inet_header inet_header;
};

union flow_data {
    struct ipv4_out         ipv4_out;
    struct ipv4_out_vlan    ipv4_out_vlan;
};

struct flow_cache {
    struct flow_key key;
    enum  flow_type type;
    union flow_data data;
};

void ofp_flow_pre_rt_burst(odp_packet_t pkt_table[], size_t len);
void ofp_flow_output_burst(odp_packet_t pkt_table[], size_t len);

void ofp_flow_input_save(odp_packet_t pkt);
void ofp_flow_post_rt_save(odp_packet_t pkt, struct ip_out *odata);

int ofp_flow_init_global(void);
int ofp_flow_term_global(void);

#endif /* __OFPI_PKT_FLOWCACHE_H__ */
