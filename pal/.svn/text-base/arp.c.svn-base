#include <unistd.h>
#include <arpa/inet.h>

#include <rte_ethdev.h>
#include "conf.h"
#include "arp.h"
#include "netif.h"
#include "skb.h"
#include "pktdef.h"
#include "thread.h"
#include "vnic.h"
#include "ipgroup.h"
#include "jiffies.h"
#include "pal_ip_cell.h"
#include "vtep.h"

static int pal_send_pkt_arp(struct sk_buff *skb, unsigned port_id);

int l2_enabled(void)
{
	return g_pal_config.arp.l2_enabled;
}

void pal_enable_l2(__unused int tid)
{
	/* do neighbor lookup if arp is enabled */
	pal_send_pkt = pal_send_pkt_arp;
}

/*
 * @brief Build ether header and transmit a packet, this function differs from the one
 *        with _gw suffix in the way that it does arp resolution
 * @param port_id Port used to transmit the packet
 * @param skb The packet to be sent
 * @param txq_id The id of tx queue to be used for transmit
 * @return 0 on success, -1 on failure
 * @note Before calling this function, skb->data must point to the ip header,
 *       skb->data_len and skb->pkt_len must be set properly
 */
static int pal_send_pkt_arp(struct sk_buff *skb, unsigned port_id)
{
	int i;
	unsigned txq_id = pal_cur_thread_conf()->txq[port_id];
	struct eth_hdr *eth;
	struct rte_mbuf *mbuf = &skb->mbuf;

	eth = (struct eth_hdr *)skb_push(skb, sizeof(struct eth_hdr));
	/* TODO: implement this function */
	PAL_PANIC("pal_send_pkt_arp. this function is not implemented\n");

	pal_cur_thread_conf()->stats.ports[port_id].tx_pkts++;
	pal_cur_thread_conf()->stats.ports[port_id].tx_bytes += skb_len(skb);

	if(skb->dump)
		pal_dump_pkt(skb, 2000);

	for(i = 0; i < 3; i++) {
		if(rte_eth_tx_burst(port_id, txq_id, &mbuf, 1) == 1) {
			return 0;
		}
	}

	pal_cur_thread_conf()->stats.ports[port_id].tx_err++;

	return -1;
}

/*
 * swap the source and destination ip address
 */
static inline void swap_arp_ip(uint32_t *src, uint32_t *dest)
{
	uint32_t tmp = *src;
	*src = *dest;
	*dest = tmp;

	return;
}

/*
 *
 */
static int reply_arp(struct sk_buff *skb, unsigned port_id)
{
	int i;
	struct eth_hdr *eth = skb_eth_header(skb);
	struct arp_hdr *arp = skb_arp_header(skb);

	/* with an arp request, we first swap the src ip and dest ip of pkt */
	swap_arp_ip(&arp->src_ip, &arp->dst_ip);

	/* then write dest_mac with src mac of pkt */
	mac_copy(arp->dst_mac, arp->src_mac);
	mac_copy(eth->dst, eth->src);

	/* change the arp option to arp reply*/
	arp->ar_op = pal_htons(PAL_ARPOP_REPLY);

	/* read the dev's mac, and write it to src mac*/
	mac_copy(eth->src, pal_port_conf(port_id)->mac);
	mac_copy(arp->src_mac, pal_port_conf(port_id)->mac);

	/* set the interface the pkt to be sent*/
	skb->send_if = skb->recv_if;

	pal_cur_thread_conf()->stats.arp.tx_reply++;

	skb_push(skb, (unsigned long)skb_data(skb) - (unsigned long)skb_eth_header(skb));
	/* send the packet */
	for(i = 0; i < 4; i++) {
		if(pal_send_raw_pkt(skb, port_id) == 0)
			return 0;
	}

	pal_cur_thread_conf()->stats.arp.tx_reply_err++;

	return -1;
}


/*
 * Handles incoming arp packets.
 */
int arp_handler(struct sk_buff *skb)
{
	int ret = -1;
	int is_reply = 0;
	struct pal_dip *dip, *sip;
	struct arp_hdr *arp = skb_arp_header(skb);
	struct port_conf *port;
	int update_gw = 0;
	int diff_mac;

	if (arp->ar_op == pal_htons_constant(PAL_ARPOP_REPLY)) {
		is_reply = 1;
		pal_cur_thread_conf()->stats.arp.rx_reply++;
	} else if (arp->ar_op == pal_htons_constant(PAL_ARPOP_REQUEST)) {
		pal_cur_thread_conf()->stats.arp.rx_request++;
	} else {
		pal_cur_thread_conf()->stats.arp.unknown_op++;
		PAL_DEBUG("Arp pakcet not reply or request\n");
		goto free_out;
	}

	dip = pal_ipg_find_ip(arp->dst_ip);
	if (dip == NULL) {
		pal_cur_thread_conf()->stats.arp.unknown_dst++;
		goto free_out;
	}

	if (dip->port != skb->recv_if) {
		pal_cur_thread_conf()->stats.arp.port_err++;
		PAL_DEBUG("Arp packet got from wrong port\n");
		goto putdip_out;
	}

	switch (dip->type) {
	case PAL_DIP_USER:
		if (is_reply) {
			ret = 0;
			goto putdip_out;
		}

		if (reply_arp(skb, dip->port) == 0) {
			/* skb is already freed */
			pal_ipg_put_ip(dip->ip);
			return 0;
		}

		break;

	case PAL_DIP_VNIC:	/* IP of VNIC */
		/* Note: arp request for vnics are replied by vnic */
		sip = pal_ipg_find_ip(arp->src_ip);
		if(sip != NULL) {
			if(sip->type == PAL_DIP_GW && sip->port == skb->recv_if) {
				update_gw = 1;
			}/* else if(sip->type == PAL_DIP_NEIGHBOR) {
				TODO: update neighbor arp
			}*/

			pal_ipg_put_ip(sip->ip);
		}

		/* fall through */

	case PAL_DIP_GW: 	/* IP of gateway */
		/* gratuitous arp sent by gateway */
		if(arp->src_ip == arp->dst_ip && (!is_reply)) {
			update_gw = 1;
		}

		if(update_gw){
			port = pal_port_conf(skb->recv_if);
			diff_mac = memcmp(arp->src_mac, port->gw_mac, 6);

			if(diff_mac){
				PAL_LOG(" port %d gateway mac change from "
					MACPRINT_FMT" to "MACPRINT_FMT"\n",
					skb->recv_if, MACPRINT(port->gw_mac),
					MACPRINT(arp->src_mac));
				mac_copy(port->gw_mac, arp->src_mac);
			}
			port->gw_mac_valid = 1;
		}
		/* fall through */

	case PAL_DIP_NEIGHBOR:
		/* TODO: handle gratuitous ARP from neighbor */
		ret = 0;
		skb_push(skb, sizeof(struct eth_hdr));
//		PAL_DEBUG("send arp packet to vnic\n");
		if(pal_send_to_vnic(dip->port, skb) == 0) {
            pal_skb_free(skb);
			pal_ipg_put_ip(dip->ip);
			return 0;
		}
		break;

	default:
		pal_cur_thread_conf()->stats.arp.unknown_dst++;
		PAL_DEBUG("Arp not for us "NIPQUAD_FMT"\n", NIPQUAD(dip->ip));
		break;
	}

putdip_out:
	pal_ipg_put_ip(dip->ip);

free_out:
	pal_skb_free(skb);

	return ret;
}

static int send_arp_request(unsigned port_id, uint8_t *smac,
                                       uint32_t dip, uint32_t sip)
{
	struct eth_hdr *eth;
	struct sk_buff *skb;
	struct arp_hdr *arp;

	skb = (struct sk_buff *)pal_skb_alloc(g_pal_config.arp.skb_slab);
	if(skb == NULL) {
		PAL_DEBUG("alloc skb failed\n");
		return -1;
	}

	skb_reset_eth_header(skb);

	eth = skb_eth_header(skb);
	memset(eth->dst, 0xff, 6);
	memcpy(eth->src, smac, 6);
	eth->type = pal_htons(PAL_ETH_ARP);

	arp = (struct arp_hdr *)(eth + 1);
	arp->ar_hrd = pal_htons(0x01);
	arp->ar_pro = pal_htons(PAL_ETH_IP);
	arp->ar_hln = 0x06;
	arp->ar_pln = 0x04;
	arp->ar_op = pal_htons(PAL_ARPOP_REQUEST);
	arp->src_ip = sip;
	arp->dst_ip = dip;
	memcpy(arp->src_mac, smac, 6);
	memset(arp->dst_mac, 0, 6);

	pal_cur_thread_conf()->stats.arp.tx_request++;

	skb_set_pkt_len(skb, sizeof(*eth) + sizeof(*arp));

	if(pal_send_raw_pkt(skb, port_id) != 0) {
		PAL_DEBUG("Failed to send arp request\n");
		pal_cur_thread_conf()->stats.arp.tx_request_err++;
		pal_skb_free(skb);
		return -1;
	}

	return 0;
}

/* init arp configurations. This function is called no matter whether l2
 * neighbor access is enabled, as we still need to resolve gateway mac */
int pal_arp_init(void)
{
	int n_mbuf;
	struct pal_slab *arp_slab;

	/* use NETIF_NB_TXD because the driver would only free mbufs when
	 * the tx ring is full. which means if we have less mbufs than
	 * tx descriptors, the mbufs may be drained */
	if(l2_enabled())
		n_mbuf = NETIF_NB_TXD * pal_phys_port_count();
	else
		n_mbuf = 10 * pal_phys_port_count();
	arp_slab = pal_skb_slab_create_numa("arp_skb_slab", n_mbuf,
			pal_tid_to_numa(g_pal_config.arp.tid));
	if(arp_slab == NULL)
		PAL_PANIC("create skb slab for arp thread failed\n");

	g_pal_config.arp.skb_slab = arp_slab;

	/* TODO: init l2 neighbor table here if arp is enabled */

	return 0;
}

/* should only be called once on start up. */
static int solicit_all_gw_mac(void)
{
	unsigned port_id, retry, remains;
	struct port_conf *port;
	uint32_t sip;
	const unsigned retry_max = 10;

	/* clear valid bit of mac address of all gateways */
	for(port_id = 0; port_id < PAL_MAX_PORT; port_id++) {
		port = pal_port_conf(port_id);
		if(port == NULL)
			continue;

		port->gw_mac_valid = 0;
	}

	/* do the solicit job */
	for(retry = 0; retry < retry_max; retry++) {
		remains = 0;

		for(port_id = 0; port_id < PAL_MAX_PORT; port_id++) {
			port = pal_port_conf(port_id);
			if(port == NULL || port->gw_mac_valid)
				continue;

            sip = port->vnic_ip;
			if(send_arp_request(port_id, port->mac, port->gw_ip,
				         sip) < 0) {
				return -1;
			}
			remains++;
		}

		/* mac addresses of all gateways are valid */
		if(remains == 0)
			break;

		/* wait for gateway to response */
		usleep(500000);
	}

	if(retry >= retry_max)
		return -1;

	return 0;
}

/* debug only */
static void __unused dump_cpu_usage(void)
{
	int tid;
	struct pal_cpu_stats stats;
	static uint64_t last_dump;

	if (jiffies - last_dump < HZ)
		return;
	last_dump = jiffies;

	pal_get_cpu_usage(&stats);

	PAL_FOR_EACH_WORKER (tid) {
		PAL_DEBUG("worker %d usage: %lu\n", tid, stats.cpu_usage[tid]);
	}

	PAL_FOR_EACH_RECEIVER (tid) {
		PAL_DEBUG("receiver %d usage: %lu\n", tid, stats.cpu_usage[tid]);
	}
	PAL_DEBUG("\n");
}

int arp_loop(__unused void *data)
{
	int port_id;
	struct timespec ts, tsrem;
	/* sleep 1 jiffiy each time, but no more than 1 ms */
	const long sleep_nsec = HZ < 1000?1000000:(1000000000 / HZ);

	BUILD_BUG_ON(HZ > 1000000000);

	/*wait 1 sec to enable bonding NIC work*/
	sleep(1);

	if(solicit_all_gw_mac() < 0) {
		for(port_id = 0; port_id < PAL_MAX_PORT; port_id++) {
			if(pal_port_conf(port_id) == NULL ||
				pal_port_conf(port_id)->gw_mac_valid)
				continue;
                PAL_LOG("solicit gateway "NIPQUAD_FMT" of port %d failed\n",
				NIPQUAD(pal_port_conf(port_id)->gw_ip),
				pal_port_conf(port_id)->port_id);
		}
        /* TODO: comment this temporarily to for testing */
        //PAL_PANIC("solicit gateway mac failed\n");
	}

	while(1) {
		update_jiffies();

		if(l2_enabled()) {
			/* TODO: do arp handling */
		}

		ts.tv_sec = 0;
		ts.tv_nsec = sleep_nsec;
		while(nanosleep(&ts, &tsrem) < 0 && errno == EINTR) {
			ts = tsrem;
		}
	}

	return 0;
}

static int nn_reply_arp(struct sk_buff *skb, struct ip_cell_info *info)
{
	struct eth_hdr *eth = skb_eth_header(skb);
	struct arp_hdr *arp = skb_arp_header(skb);

	/* with an arp request, we first swap the src ip and dest ip of pkt */
	swap_arp_ip(&arp->src_ip, &arp->dst_ip);

	/* then write dest_mac with src mac of pkt */
	mac_copy(arp->dst_mac, arp->src_mac);
	mac_copy(eth->dst, eth->src);

	/* change the arp option to arp reply*/
	arp->ar_op = pal_htons(PAL_ARPOP_REPLY);

	/* read the dev's mac, and write it to src mac*/
	memcpy(eth->src, info->eth_addr,6);
	memcpy(arp->src_mac, info->eth_addr,6);

	skb_push(skb, (unsigned long)skb_data(skb) - (unsigned long)skb_eth_header(skb));

	pal_cur_thread_conf()->stats.arp.tx_reply++;

	/* send the packet */
	if(pal_send_raw_pkt(skb,skb->recv_if) == 0)
		return 0;

	pal_cur_thread_conf()->stats.arp.tx_reply_err++;
	pal_skb_free(skb);
	return -EFAULT;
}

static void update_gw_mac(struct sk_buff *skb,struct arp_hdr *arp)
{
	int diff_mac;
	struct port_conf *port;

	port = pal_port_conf(skb->recv_if);
	diff_mac = memcmp(arp->src_mac, get_nn_gw_mac(), 6);
	if(diff_mac){
		PAL_LOG(" port %d gateway mac change from "
			MACPRINT_FMT" to "MACPRINT_FMT"\n",
			skb->recv_if, MACPRINT(get_nn_gw_mac()),
			MACPRINT(arp->src_mac));
		memcpy(get_nn_gw_mac(), arp->src_mac,6);
	}
	port->gw_mac_valid = 1;
}

/*
* Handles incoming external network arp packets.
*/
int rcv_pkt_ext_arp_process(struct sk_buff *skb)
{
	int is_reply = 0;
	int update_gw = 0;
	struct arp_hdr *arp;
	struct ip_cell_info info;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct arp_hdr))))
		goto drop;

	arp = skb_arp_header(skb);
	if (arp->ar_op == pal_htons_constant(PAL_ARPOP_REPLY)) {
		is_reply = 1;
		pal_cur_thread_conf()->stats.arp.rx_reply++;
	} else if (arp->ar_op == pal_htons_constant(PAL_ARPOP_REQUEST)){
		pal_cur_thread_conf()->stats.arp.rx_request++;
	} else {
		pal_cur_thread_conf()->stats.arp.unknown_op++;
		PAL_DEBUG("Arp pakcet not reply or request\n");
		goto drop;
	}

	if(unlikely(find_ip_cell_info(arp->dst_ip,&info) < 0)) {
		pal_cur_thread_conf()->stats.arp.unknown_dst++;
		goto drop;
	}
    switch(info.type) {
	case EXT_GW_IP:
        if (is_reply) {
            goto drop;
        }else
            nn_reply_arp(skb, &info);
        break;
    case LOCAL_IP:
        skb_push(skb, sizeof(struct eth_hdr));
        struct ip_cell_info info_tmp;
        if (!find_ip_cell_info(arp->src_ip, &info_tmp))
        {
            if (info_tmp.type == GATEWAY_IP) {
                update_gw_mac(skb, arp);
            }
        }
        pal_send_to_vnic(skb->recv_if, skb);
        goto drop;
    case FLOATING_IP:
	case VTEP_IP:
        goto drop;

	case GATEWAY_IP:
		/* gratuitous arp sent by gateway */
		if(arp->src_ip == arp->dst_ip && (!is_reply)) {
			update_gw = 1;
		}

		if(update_gw) {
			update_gw_mac(skb,arp);
		}

		pal_skb_free(skb);
		break;
	default:
		pal_cur_thread_conf()->stats.arp.unknown_dst++;
		goto drop;
		break;
	}
	return 0;

drop:
	pal_skb_free(skb);
	return -EFAULT;
}

void nn_arp_init(uint32_t gw_ip)
{
	set_nn_gw_ip(gw_ip);
}
