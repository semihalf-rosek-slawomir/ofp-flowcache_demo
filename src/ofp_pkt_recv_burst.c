#include "ofpi.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_pkt_flowcache.h"
#include "ofpi_stat.h"

#define OFP_PKT_PRE_RT_BURST_SIZE   (2 * OFP_PKT_RX_BURST_SIZE)
#define OFP_PKT_POST_RT_BURST_SIZE  (2 * OFP_PKT_RX_BURST_SIZE)
#define __FLAGS __thread

static __FLAGS uint32_t pkt_pre_rt_cnt = 0;
static __FLAGS uint32_t pkt_post_rt_cnt = 0;
static __FLAGS odp_packet_t pkt_pre_rt_tbl[OFP_PKT_PRE_RT_BURST_SIZE];
static __FLAGS odp_packet_t pkt_post_rt_tbl[OFP_PKT_POST_RT_BURST_SIZE];
static __FLAGS struct ofp_ifnet *dev_output;

void ofp_packet_pre_rt_enq(odp_packet_t pkt)
{
    /* TODO: This is just single flow demo. Final code should support
     *       multiple producers
     */
    pkt_pre_rt_tbl[pkt_pre_rt_cnt++] = pkt;
}

void ofp_packet_input_enq(odp_packet_t pkt)
{
    /* TODO: implement local input */
    (void) pkt;
}

void ofp_packet_output_enq(odp_packet_t pkt)
{
    /* TODO: implement local output */
    (void) pkt;
}

void ofp_packet_post_rt_enq(odp_packet_t pkt, struct ofp_ifnet *dev)
{
    /* TODO: This is just single flow demo. Final code should support
     *       multiple producers and multiple output ports
     */
    pkt_post_rt_tbl[pkt_post_rt_cnt++] = pkt;
    dev_output = dev;
}

void ofp_packet_pre_rt_burst(odp_packet_t pkt_table[], size_t len,
    ofp_pkt_processing_func pkt_func)
{
	OFP_UPDATE_PACKET_STAT(rx_fp, len);

#ifdef OFP_PKT_FLOW_CACHE
    ofp_flow_pre_rt_burst(pkt_table, len);
#else
    /* TODO: This is just workaround for flow cache disabled.
     *       Final code should implement real burst processing.
     */
    size_t i = 0;
    for (; i < len; i++ )
        ofp_packet_pre_rt_enq(pkt_table[i]);
#endif

    if ((OFP_PKT_POST_RT_BURST_SIZE / 2) <= pkt_post_rt_cnt)
    {
		size_t ret = (size_t)odp_pktio_send(ofp_port_pktio_get(dev_output->port), pkt_post_rt_tbl, pkt_post_rt_cnt);

		for (; ret < pkt_post_rt_cnt; ret++)
			odp_packet_free(pkt_post_rt_tbl[ret]);

        pkt_post_rt_cnt = 0;
    }

    if ((OFP_PKT_PRE_RT_BURST_SIZE / 2) <= pkt_pre_rt_cnt)
    {
        /* TODO: This is legacy slow path (flow cache disabled or miss).
         *       Final code should implement real burst processing.
         */
        size_t i = 0;

        for (; i < pkt_pre_rt_cnt; i++ )
            ofp_packet_input(pkt_pre_rt_tbl[i], ODP_QUEUE_INVALID, pkt_func);

        pkt_pre_rt_cnt = 0;
    }
}

void ofp_packet_output_burst(odp_packet_t pkt_table[], size_t len,
    ofp_pkt_processing_func pkt_func)
{
    /* TODO: implement local burst output */
    (void) pkt_table;
    (void) len;
    (void) pkt_func;
}
