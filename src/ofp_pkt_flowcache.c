#include "ofpi.h"
#include "ofpi_config.h"
#include "ofpi_debug.h"
#include "ofpi_util.h"
#include "ofpi_hash.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_pkt_flowcache.h"

#define prefetch_read_keep(_ptr) ({	\
	 __builtin_prefetch (_ptr, 0, 3); })

#define prefetch_read_stream(_ptr) ({	\
	 __builtin_prefetch (_ptr, 0, 0); })

#define prefetch_store_keep(_ptr) ({	\
	 __builtin_prefetch (_ptr, 1, 3); })

#define prefetch_store_stream(_ptr) ({	\
	 __builtin_prefetch (_ptr, 1, 0); })

#define FLOW_CACHE_SIZE     1024

#define SHM_NAME_FLOW "OfpFlowShMem"

struct ofp_flow_mem {
    struct flow_cache cache[FLOW_CACHE_SIZE] ODP_ALIGNED_CACHE;
};

//static __thread struct ofp_flow_mem *shm; /* TODO: investigate SIGSEGV */
static struct ofp_flow_mem *shm;

#if 0
static enum ofp_return_code pkt_continue(odp_packet_t pkt, struct flow_cache *cache)
{
    (void)pkt; /* not used */
    (void)cache; /* not used */

    return OFP_PKT_CONTINUE;
}
#endif

/* Enable align check (debug only) */
/* #define ALIGN_CHECK */

static enum ofp_return_code eth_ipv4_forward(odp_packet_t pkt, struct flow_cache *cache)
{
    struct ipv4_out *ipv4_out = &cache->data.ipv4_out;

/* TODO: Some NIC's do additional packet alignments, so final
 *       solution could provide proper configs. In addition 128bit
 *       vector operations could be used (NEON, SSE2)
 */
#if 0
    uint64_t *vect_dst = (uint64_t *)((uintptr_t)odp_packet_l2_ptr(pkt, NULL) - 6);
    uint64_t *vect_src = (uint64_t *)&ipv4_out->ether_header;

    *((uint64_t*)vect_dst + 0) = *((uint64_t*)vect_src + 0);
    *((uint64_t*)vect_dst + 1) = *((uint64_t*)vect_src + 1);
    *((uint32_t*)vect_dst + 4) = *((uint32_t*)vect_src + 4);
#else
    uint64_t *vect_dst = (uint64_t *)((uintptr_t)odp_packet_l2_ptr(pkt, NULL));
    uint64_t *vect_src = (uint64_t *)&ipv4_out->ether_header;

    *((uint64_t*)vect_dst + 0) = *((uint64_t*)vect_src + 0);
    *((uint32_t*)vect_dst + 2) = *((uint32_t*)vect_src + 2);
#endif

#ifdef ALIGN_CHECK
    if (((uintptr_t)vect_dst & 0x7) || ((uintptr_t)vect_src & 0x7))
        fprintf(stderr, "%s:%d: vect_dst=%p, vect_src=%p\n", __FILE__, __LINE__, vect_dst, vect_src);
#endif

    /* TODO: Check IP TTL
     */
    ofp_packet_post_rt_enq(pkt, ipv4_out->dev_out);

    return OFP_PKT_PROCESSED;
}

static enum ofp_return_code eth_ipv4_tag_forward(odp_packet_t pkt, struct flow_cache *cache)
{
    struct ipv4_out_vlan *ipv4_out = &cache->data.ipv4_out_vlan;

/* TODO: Some NIC's do additional packet alignments, so final
 *       solution could provide proper configs. In addition 128bit
 *       vector operations could be used (NEON, SSE2)
 */
#if 0
    uint64_t *vect_dst = (uint64_t *)((uintptr_t)odp_packet_l2_ptr(pkt, NULL) - 2);
    uint64_t *vect_src = (uint64_t *)&ipv4_out->ether_vlan_header;

    *((uint64_t*)vect_dst + 0) = *((uint64_t*)vect_src + 0);
    *((uint64_t*)vect_dst + 1) = *((uint64_t*)vect_src + 1);
    *((uint32_t*)vect_dst + 4) = *((uint32_t*)vect_src + 4);
#else
    uint64_t *vect_dst = (uint64_t *)((uintptr_t)odp_packet_l2_ptr(pkt, NULL));
    uint64_t *vect_src = (uint64_t *)&ipv4_out->ether_vlan_header;

    *((uint64_t*)vect_dst + 0) = *((uint64_t*)vect_src + 0);
    *((uint64_t*)vect_dst + 1) = *((uint64_t*)vect_src + 1);
#endif

#ifdef ALIGN_CHECK
    if (((uintptr_t)vect_dst & 0x7) || ((uintptr_t)vect_src & 0x7))
        fprintf(stderr, "%s:%d: vect_dst=%p, vect_src=%p\n", __FILE__, __LINE__, vect_dst, vect_src);
#endif

    /* TODO: Check IP TTL and headroom (proper headroom size could be guaranteed,
     *       by ODP/DPDK configuration under OFP performance compilation warnings).
     */
    ofp_packet_post_rt_enq(pkt, ipv4_out->dev_out);

    return OFP_PKT_PROCESSED;
}

static enum ofp_return_code veth_ipv4_forward(odp_packet_t pkt, struct flow_cache *cache)
{
    struct ipv4_out_vlan *ipv4_out = &cache->data.ipv4_out_vlan;

/* TODO: Some NIC's do additional packet alignments, so final
 *       solution could provide proper configs. In addition 128bit
 *       vector operations could be used (NEON, SSE2)
 */
#if 0
    uint64_t *vect_dst = (uint64_t *)((uintptr_t)odp_packet_l2_ptr(pkt, NULL) - 2);
    uint64_t *vect_src = (uint64_t *)&ipv4_out->ether_vlan_header;

    *((uint64_t*)vect_dst + 0) = *((uint64_t*)vect_src + 0);
    *((uint64_t*)vect_dst + 1) = *((uint64_t*)vect_src + 1);
    *((uint32_t*)vect_dst + 4) = *((uint32_t*)vect_src + 4);
#else
    uint64_t *vect_dst = (uint64_t *)((uintptr_t)odp_packet_l2_ptr(pkt, NULL));
    uint64_t *vect_src = (uint64_t *)&ipv4_out->ether_vlan_header;

    *((uint64_t*)vect_dst + 0) = *((uint64_t*)vect_src + 0);
    *((uint64_t*)vect_dst + 1) = *((uint64_t*)vect_src + 1);
#endif

#ifdef ALIGN_CHECK
    if (((uintptr_t)vect_dst & 0x7) || ((uintptr_t)vect_src & 0x7))
        fprintf(stderr, "%s:%d: vect_dst=%p, vect_src=%p\n", __FILE__, __LINE__, vect_dst, vect_src);
#endif

    /* TODO: Check IP TTL
     */
    ofp_packet_post_rt_enq(pkt, ipv4_out->dev_out);

    return OFP_PKT_PROCESSED;
}

static enum ofp_return_code veth_ipv4_untag_forward(odp_packet_t pkt, struct flow_cache *cache)
{
    struct ipv4_out *ipv4_out = &cache->data.ipv4_out;

/* TODO: Some NIC's do additional packet alignments, so final
 *       solution could provide proper configs. In addition 128bit
 *       vector operations could be used (NEON, SSE2)
 */
#if 0
    uint64_t *vect_dst = (uint64_t *)((uintptr_t)odp_packet_l2_ptr(pkt, NULL) - 6);
    uint64_t *vect_src = (uint64_t *)&ipv4_out->ether_header;

    *((uint64_t*)vect_dst + 0) = *((uint64_t*)vect_src + 0);
    *((uint64_t*)vect_dst + 1) = *((uint64_t*)vect_src + 1);
    *((uint32_t*)vect_dst + 4) = *((uint32_t*)vect_src + 4);
#else
    uint64_t *vect_dst = (uint64_t *)((uintptr_t)odp_packet_l2_ptr(pkt, NULL));
    uint64_t *vect_src = (uint64_t *)&ipv4_out->ether_header;

    *((uint64_t*)vect_dst + 0) = *((uint64_t*)vect_src + 0);
    *((uint32_t*)vect_dst + 2) = *((uint32_t*)vect_src + 2);
#endif

#ifdef ALIGN_CHECK
    if (((uintptr_t)vect_dst & 0x7) || ((uintptr_t)vect_src & 0x7))
        fprintf(stderr, "%s:%d: vect_dst=%p, vect_src=%p\n", __FILE__, __LINE__, vect_dst, vect_src);
#endif

    /* TODO: Check IP TTL
     */
    ofp_packet_post_rt_enq(pkt, ipv4_out->dev_out);

    return OFP_PKT_PROCESSED;
}

static enum ofp_return_code (*flow_handler[])(odp_packet_t, struct flow_cache *) = {

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
    [ OFP_FLOW_ETH_IPV4_FORWARD ] = eth_ipv4_forward,
    [ OFP_FLOW_ETH_IPV4_TAG_FORWARD ] = eth_ipv4_tag_forward,
    [ OFP_FLOW_VETH_IPV4_FORWARD ] = veth_ipv4_forward,
    [ OFP_FLOW_VETH_IPV4_UNTAG_FORWARD ] = veth_ipv4_untag_forward,
};

static inline uint16_t flow_hash(struct flow_key *key)
{
    /* TODO: This is just single flow demo. Final solution should
     *       implement proper hash function or use hw acceleration
     *       if possible (NEON, SSE2 or NIC flow hashing).
     */
#if 0
    return (uint16_t)(ofp_hashlittle(key, sizeof(*key), 0) & (FLOW_CACHE_SIZE - 1));
#else
    (void)key; /* not used */
    return 0;
#endif
}

static inline struct flow_cache *flow_cache_read(struct flow_key *key)
{
    /* TODO: investigate SIGSEGV */
    return &shm->cache[flow_hash(key)];
}

static inline enum ofp_return_code ofp_flow_pre_rt_process(odp_packet_t pkt)
{
    struct ofp_ip *ip;
    struct flow_key key;
    struct flow_cache *cache;

    ip = odp_packet_l3_ptr(pkt, NULL);
    key.ip_dst = ip->ip_dst.s_addr;

    cache = flow_cache_read(&key);

    //if (odp_likely(!memcmp(&cache->key, &key, sizeof(key))))
    if (odp_likely(cache->key.ip_dst == key.ip_dst)) {

        /* TODO: Handle other flow types, for example:
         *
         *  eth_ipv4_udp_input( ... )
         *  eth_ipv4_tcp_input( ... )
         */
        return flow_handler[cache->type](pkt, cache);
    }

    return OFP_PKT_CONTINUE;
}

static inline void ofp_flow_pre_rt_single(odp_packet_t pkt)
{
	//TODO: OFP_DEBUG_PACKET(OFP_DEBUG_PKT_RECV_NIC, pkt, ifnet->port);

    if (odp_unlikely(ofp_flow_pre_rt_process(pkt) != OFP_PKT_PROCESSED)) {

        ofp_packet_pre_rt_enq(pkt);
        return;
    }

	//TODO: OFP_DEBUG_PACKET(OFP_DEBUG_PKT_SEND_NIC, pkt, dev->port);
}

void ofp_flow_pre_rt_burst(odp_packet_t pkt_table[], size_t len)
{
    size_t i, n;

    if (odp_unlikely(len < 2)) {
        ofp_flow_pre_rt_single(pkt_table[0]);
        return;
    }

    i = 0; n = len - 2;
    while (i < n) {

        prefetch_store_stream(odp_packet_l2_ptr(pkt_table[i+2],NULL));
        ofp_flow_pre_rt_single(pkt_table[i]);

        i++;
    }
    ofp_flow_pre_rt_single(pkt_table[i]);
    ofp_flow_pre_rt_single(pkt_table[i+1]);
}

void ofp_flow_output_burst(odp_packet_t pkt_table[], size_t len)
{
    /* TODO: Handle other flow types, for example:
     *
     *  eth_ipv4_udp_output( ... )
     *  eth_ipv4_tcp_output( ... )
     */
    (void) pkt_table;
    (void) len;
}

static void save_eth_ipv4_forward(odp_packet_t pkt, struct ip_out *odata)
{
    /* TODO: This is just demo. Final code should be optimized if possible
     *       (branch misses, cache misses, alignments, vector processing).
     *       However, this is slow path only (flow cache miss)
     */
    struct ofp_ip *ip;
    struct flow_key key;
    struct flow_cache *cache;

    struct ipv4_out *ipv4_out;
    struct ofp_ether_header *eth;

    ip = odp_packet_l3_ptr(pkt, NULL);
    key.ip_dst = ip->ip_dst.s_addr;

    cache = flow_cache_read(&key);
    cache->key.ip_dst = key.ip_dst;
    cache->type = OFP_FLOW_ETH_IPV4_FORWARD;

    ipv4_out = &cache->data.ipv4_out;

    eth = odp_packet_l2_ptr(pkt, NULL);
    ipv4_out->dev_out = odata->dev_out;
    ofp_copy_mac(ipv4_out->ether_header.ether_dhost, eth->ether_dhost);
    ofp_copy_mac(ipv4_out->ether_header.ether_shost, eth->ether_shost);
    ipv4_out->ether_header.ether_type = eth->ether_type;
    ipv4_out->inet_header.ip_src = ip->ip_src.s_addr;
}

static void save_eth_ipv4_tag_forward(odp_packet_t pkt, struct ip_out *odata)
{
    /* TODO: This is just demo. Final code should be optimized if possible
     *       (branch misses, cache misses, alignments, vector processing).
     *       However, this is slow path only (flow cache miss)
     */
    struct ofp_ip *ip;
    struct flow_key key;
    struct flow_cache *cache;

    struct ipv4_out_vlan *ipv4_out;
    struct ofp_ether_vlan_header *veth;

    ip = odp_packet_l3_ptr(pkt, NULL);
    key.ip_dst = ip->ip_dst.s_addr;

    cache = flow_cache_read(&key);
    cache->key.ip_dst = key.ip_dst;
    cache->type = OFP_FLOW_ETH_IPV4_TAG_FORWARD;

    ipv4_out = &cache->data.ipv4_out_vlan;

    veth = odp_packet_l2_ptr(pkt, NULL);
    ipv4_out->dev_out = odata->dev_out;
    ofp_copy_mac(ipv4_out->ether_vlan_header.evl_dhost, veth->evl_dhost);
    ofp_copy_mac(ipv4_out->ether_vlan_header.evl_shost, veth->evl_shost);
    ipv4_out->ether_vlan_header.evl_encap_proto = veth->evl_encap_proto;
    ipv4_out->ether_vlan_header.evl_tag = veth->evl_tag;
    ipv4_out->ether_vlan_header.evl_proto = veth->evl_proto;
    ipv4_out->inet_header.ip_src = ip->ip_src.s_addr;
}

static void save_veth_ipv4_forward(odp_packet_t pkt, struct ip_out *odata)
{
    /* TODO: This is just demo. Final code should be optimized if possible
     *       (branch misses, cache misses, alignments, vector processing).
     *       However, this is slow path only (flow cache miss)
     */
    struct ofp_ip *ip;
    struct flow_key key;
    struct flow_cache *cache;

    struct ipv4_out_vlan *ipv4_out;
    struct ofp_ether_vlan_header *veth;

    ip = odp_packet_l3_ptr(pkt, NULL);
    key.ip_dst = ip->ip_dst.s_addr;

    cache = flow_cache_read(&key);
    cache->key.ip_dst = key.ip_dst;
    cache->type = OFP_FLOW_VETH_IPV4_FORWARD;

    ipv4_out = &cache->data.ipv4_out_vlan;

    veth = odp_packet_l2_ptr(pkt, NULL);
    ipv4_out->dev_out = odata->dev_out;
    ofp_copy_mac(ipv4_out->ether_vlan_header.evl_dhost, veth->evl_dhost);
    ofp_copy_mac(ipv4_out->ether_vlan_header.evl_shost, veth->evl_shost);
    ipv4_out->ether_vlan_header.evl_encap_proto = veth->evl_encap_proto;
    ipv4_out->ether_vlan_header.evl_tag = veth->evl_tag;
    ipv4_out->ether_vlan_header.evl_proto = veth->evl_proto;
    ipv4_out->inet_header.ip_src = ip->ip_src.s_addr;
}

static void save_veth_ipv4_untag_forward(odp_packet_t pkt, struct ip_out *odata)
{
    /* TODO: This is just demo. Final code should be optimized if possible
     *       (branch misses, cache misses, alignments, vector processing).
     *       However, this is slow path only (flow cache miss)
     */
    struct ofp_ip *ip;
    struct flow_key key;
    struct flow_cache *cache;

    struct ipv4_out *ipv4_out;
    struct ofp_ether_header *eth;

    ip = odp_packet_l3_ptr(pkt, NULL);
    key.ip_dst = ip->ip_dst.s_addr;

    cache = flow_cache_read(&key);
    cache->key.ip_dst = key.ip_dst;
    cache->type = OFP_FLOW_VETH_IPV4_UNTAG_FORWARD;

    ipv4_out = &cache->data.ipv4_out;

    eth = odp_packet_l2_ptr(pkt, NULL);
    ipv4_out->dev_out = odata->dev_out;
    ofp_copy_mac(ipv4_out->ether_header.ether_dhost, eth->ether_dhost);
    ofp_copy_mac(ipv4_out->ether_header.ether_shost, eth->ether_shost);
    ipv4_out->ether_header.ether_type = eth->ether_type;
    ipv4_out->inet_header.ip_src = ip->ip_src.s_addr;
}

void ofp_flow_input_save(odp_packet_t pkt)
{
    /* TODO: Save other flow types, for example:
     *
     *  save_eth_ipv4_udp_input( ... )
     *  save_eth_ipv4_tcp_input( ... )
     */
    (void) pkt;
}

void ofp_flow_post_rt_save(odp_packet_t pkt, struct ip_out *odata)
{
    /* TODO: This is just demo. Final code should be optimized if possible
     *       (branch misses, cache misses, alignments, vector processing).
     *       However, this is slow path only (flow cache miss)
     */
    if (odata->vlan_in) {

        if (odata->vlan)
            save_veth_ipv4_forward(pkt, odata);
        else
            save_veth_ipv4_untag_forward(pkt, odata);
    }
    else {

        if (odata->vlan)
            save_eth_ipv4_tag_forward(pkt, odata);
        else
            save_eth_ipv4_forward(pkt, odata);
    }

    /* TODO: Save other flow types, for example:
     *
     *  save_eth_ipv4_udp_output( ... )
     *  save_eth_ipv4_tcp_output( ... )
     */
}

static int ofp_flow_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_FLOW, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_flow_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_FLOW) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

int ofp_flow_init_global(void)
{
	HANDLE_ERROR(ofp_flow_alloc_shared_memory());

    OFP_INFO("Flow Cache Initialized.");
	return 0;
}

int ofp_flow_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_flow_free_shared_memory(), rc);

	return rc;
}
