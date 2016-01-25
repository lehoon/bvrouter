#include <unistd.h>
#include <string.h>
#include <rte_ethdev.h>

#include "vtep.h"

#include "fifo.h"
#include "cpu.h"
#include "receiver.h"
#include "utils.h"
#include "malloc.h"
#include "netif.h"
#include "skb.h"
#include "pktdef.h"
#include "ipgroup.h"
#include "arp.h"
#include "ip.h"
#include "vnic.h"
#include "thread.h"
#include "pal_phy_vport.h"
#include "pal_vxlan.h"
#include "pal_ip_cell.h"
#include "route.h"


/* size of packet queues used by receiver and worker. 8K */
#define PAL_PKTQ_SIZE	(1UL << 13)

#define PAL_RCV_BURST	32

/*
 * @brief Initialize packet dispatch queues
 */
static int disq_init_numa(int numa)
{
	int i;
	int w_tid, r_tid;
	int qcnt, qid;
	unsigned n_worker, n_receiver;
	char name[PAL_FIFO_NAME_MAX];
	int arp = 0;
	int worker_cnt;
	struct numa_conf *numa_conf = g_pal_config.numa[numa];
	struct pal_fifo **qarray;

	if(l2_enabled() && pal_tid_to_numa(g_pal_config.arp.tid) == numa)
		arp = 1;
	/* note this "worker_cnt" includes arp thread */
	worker_cnt = numa_conf->n_worker + arp;

	/* qcnt can be 0 as applications may only run ctl process on a numa */
	qcnt = worker_cnt * numa_conf->n_receiver;
	if(qcnt == 0)
		return 0;
	qarray = pal_malloc(qcnt * sizeof(struct pal_fifo *));
	if(qarray == NULL)
		PAL_PANIC("alloc dispatch queue array failed\n");

	PAL_DEBUG("Alloc packet queues and assign them to receiver/worker " \
	                                                "on numa %u\n", numa);

	/*
	 * The dispatch q assign logic is described as follows:
	 * For X receivers and Y workers on one numa, alloc X * Y queues first.
	 * Each q must be assigned to one receiver and one worker.
	 * For Nth receiver and Mth worker, we assign qid (N * Y + M) to them.
	 * N, M and qid all start from 0.
	 */

	/* alloc m * n fifos first */
	for(i = 0; i < qcnt; i++) {
		snprintf(name, sizeof(name), "pktq_%u@%u", i, numa);
		qarray[i] = pal_fifo_create_spsc(name, PAL_PKTQ_SIZE, numa);
		if(qarray[i] == NULL) {
			PAL_PANIC("create pktq %u on numa %u failed\n", i, numa);
			return -1;
		}
	}
	PAL_DEBUG("    Alloced %u(%u * %u) queues\n", qcnt,
	                        worker_cnt, numa_conf->n_receiver);

	/* assign pktq to each worker and receiver*/
	n_receiver = 0;
	PAL_FOR_EACH_RECEIVER(r_tid) {
		if(numa != pal_tid_to_numa(r_tid)) {
			continue;
		}

		/* do the assign job */
		n_worker = 0;
		/* DONOT use PAL_FOR_EACH_WORKER here cause we are also handling
		 * arp thread */
		PAL_FOR_EACH_THREAD(w_tid) {
			if(numa != pal_tid_to_numa(w_tid) ||
				(pal_thread_mode(w_tid) != PAL_THREAD_WORKER &&
				(arp == 0 || pal_thread_mode(w_tid) != PAL_THREAD_ARP)))
				continue;
			qid = worker_cnt * n_receiver + n_worker;
			pal_thread_conf(r_tid)->pkt_q[w_tid] = qarray[qid];
			pal_thread_conf(w_tid)->pkt_q[r_tid] = qarray[qid];
			PAL_DEBUG("    assign packet fifo %u to receiver %u, " \
			           "and worker %u\n", qid, r_tid, w_tid);
			n_worker++;
		}

		n_receiver++;
	}

	return 0;

}


/*
 * initialize dispatch queues used by receiver, worker and arp thread
 */
void pal_disq_init(void)
{
	int numa;

	PAL_FOR_EACH_NUMA(numa) {
		disq_init_numa(numa);
	}
}

extern struct rte_mbuf * ip_frag_reassemble_packet(struct sk_buff *skb,struct ip_hdr  *iph);

/*
* distinguish whether it is a vxlan packet or non-vxlan packet and deliver it
* to proper process function.
*/
static inline int __bvrouter rcv_pkt_ipv4_process(struct sk_buff *skb)
{
	struct ip_hdr  *iph;
	struct udp_hdr * udphdr;
	int is_vxlan = NO_VXLAN;
	uint32_t len ;

	/*check ip sum*/
	if(unlikely(!skb_ip_csum_ok(skb)))
		goto drop;

	/*check ip header len*/
	if (unlikely(!pskb_may_pull(skb, sizeof(struct ip_hdr))))
		goto drop;
	iph = skb_ip_header(skb);
	if (unlikely(!pskb_may_pull(skb, ((iph->ihl) << 2))))
		goto drop;

	/*check ip total len*/
	len = pal_ntohs(iph->tot_len);
	if (unlikely((skb_len(skb) < len) || (len < (uint32_t)(iph->ihl*4)))) {
		goto drop;
	}

    /*dst for local ip send to vnic*/
    if(is_local_ip(iph->daddr)) {
        skb_push(skb, sizeof(struct eth_hdr));
        pal_send_to_vnic(skb->recv_if, skb);
	    goto drop;
    }

	/* if it is a fragmented packet and dest for vtep ip(vxlan pkt or vxlan fragment pkt),
	    then try to reassemble. */
	if (unlikely(ip_is_fragment(iph)) && is_vtep_ip(iph->daddr)) {
		struct rte_mbuf *m;
		struct rte_mbuf *mo;
		uint8_t port_out;

		m = &skb->mbuf;
		port_out = skb->recv_if;
		skb_push(skb, sizeof(struct eth_hdr));

		/* process this fragment. */
		mo = ip_frag_reassemble_packet(skb,iph);
		if (mo == NULL){/* no packet to send out. */
			return -1;
		}

		/* we have our packet reassembled. */
		if (mo != m) {
			m = mo;
            /*ip frag reassemble will set PKT_TX_IP_CKSUM, set it back*/
            m->ol_flags &= (~PKT_TX_IP_CKSUM);
		}

		skb = (struct sk_buff *)m;
		skb->recv_if = port_out;
		skb_reset_eth_header(skb);
		skb_pull(skb, sizeof(struct eth_hdr));
		skb_reset_network_header(skb);
		iph = skb_ip_header(skb);
	}

	skb_pull(skb, ((iph->ihl) << 2));
	skb_reset_l4_header(skb);

	/*Tcp and ICMP need check csum*/
	if((iph->protocol != PAL_IPPROTO_UDP)){
		if (unlikely(!skb_l4_csum_ok(skb)))
			goto drop;
	}else{/*Udp protocl may do not need csum ,if udp->check = 0*/
		if (unlikely(!(pskb_may_pull(skb, sizeof(struct udp_hdr))))){
				goto drop;
		}

		udphdr = skb_udp_header(skb);
		if(udphdr->check != 0){
			if (unlikely(!skb_l4_csum_ok(skb)))
				goto drop;
		}

		/* To test whether it is a vxlan packet or non-vxlan packet  */
		is_vxlan = is_vxlan_packet(iph,udphdr);
	}

	if(is_vxlan == IS_VXLAN){
	 	/*internal network process*/
	 	rcv_int_network_pkt_process(skb);
	}else{
		/*external network process*/
		rcv_ext_network_pkt_process(skb);
	 }

	return 0;

drop:
	pal_skb_free(skb);
	return -EFAULT;
}

/* this function frees packet in any case */
int  __bvrouter l2_handler(struct sk_buff *skb)
{
	struct eth_hdr *eth = skb_eth_header(skb);

	if(unlikely(skb_len(skb) < sizeof(struct eth_hdr))) {
		PAL_DEBUG("skb len %u < ethernet header", skb_len(skb));
		pal_cur_thread_conf()->stats.ports[skb->recv_if].trunc_pkts++;
		pal_skb_free(skb);
		return -1;
	}

	skb_pull(skb, sizeof(struct eth_hdr));
	skb_reset_network_header(skb);

	switch(eth->type) {
	case pal_htons_constant(PAL_ETH_ARP):
			pal_cur_thread_conf()->stats.arp.rx_pkts++;
			pal_cur_thread_conf()->stats.arp.rx_bytes += skb_l2_len(skb);

		#ifndef VXLAN_TUNNEL
			arp_handler(skb);
		#else
			rcv_pkt_ext_arp_process(skb);
		#endif

		break;

	case pal_htons_constant(PAL_ETH_IP):
			pal_cur_thread_conf()->stats.ip.rx_pkts++;
			pal_cur_thread_conf()->stats.ip.rx_bytes += skb_l2_len(skb);

		if ((eth->dst[0] & 0x1) == 0) {
			#ifndef VXLAN_TUNNEL
				/* unicast packet, handle with normal processedure */
				ip_handler(skb);
			#else
				rcv_pkt_ipv4_process(skb);
			#endif
		} else {
			/* multicast/broadcast and not arp, send to vnic */
			skb_push(skb, sizeof(struct eth_hdr));
			pal_send_to_vnic(skb->recv_if, skb);
	        pal_skb_free(skb);
		}
		break;

	default:
		pal_cur_thread_conf()->stats.ports[skb->recv_if].unknown_pkts++;
		pal_cur_thread_conf()->stats.ports[skb->recv_if].unknown_bytes +=
					skb_l2_len(skb);
		pal_skb_free(skb);
		break;
	}

	return 0;
}

/*
* @brief init main data struct of l2 framwork.
*/
void l2_init(uint32_t vtep_ip,uint32_t local_ip,uint8_t *vtep_mac,uint32_t gw_ip)
{
	vport_net_init();
	phy_net_init();
	vxlan_dev_net_init();

	vtep_init(vtep_ip,vtep_mac, local_ip);
	nn_arp_init(gw_ip);
}

extern void ip_frag_reassemble_init(int numa_id);
void l2_slab_init(int numa_id)
{
	vxlan_slab_init(numa_id);
	vxlan_fdb_slab_init(numa_id);
	vxlan_arp_slab_init(numa_id);
	vxlan_skb_slab_init(numa_id);
	phy_vport_slab_init(numa_id);
	ip_cell_slab_init(numa_id);
	route_slab_init(numa_id);
	ip_frag_reassemble_init(numa_id);

	ip_cell_add(get_vtep_ip(),VTEP_IP,NULL);
    ip_cell_add(get_local_ip(),LOCAL_IP,NULL);
	ip_cell_add(get_nn_gw_ip(),GATEWAY_IP,NULL);
}

/*
 * @brief Dispatch packet to cresponding worker or handle it ourself
 */
int dispatch_pkt(struct sk_buff *skb, const struct pal_dip *dip)
{
	int worker;
	struct pal_ipgroup *ipg;

	ipg = dip->ipg;

	worker = ipg->scheduler(skb, dip);
	if (worker != pal_thread_id()) {
		skb->private_data = ipg->handler;
		pal_cur_thread_conf()->stats.ip.dispatch_ppl++;
		if (pal_fifo_enqueue_sp(pal_dispatch_fifo(worker), skb) != 0) {
			pal_cur_thread_conf()->stats.ip.dispatch_ppl_err++;
			return -1;
		}
	} else {
		pal_cur_thread_conf()->stats.ip.dispatch_rtc++;
		ipg->handler(skb);
	}
	/* PAL_DEBUG("packet dispatched to worker %u\n", worker); */

	return 0;
}

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3
int __bvrouter receiver_loop(__unused void *arg)
{
	int i, j;
	int n_port;
	int n_rx;
	unsigned port_id;
	struct thread_conf *thconf = pal_cur_thread_conf();
	unsigned sleep = thconf->sleep;
	uint8_t rxqs[PAL_MAX_PORT];
	struct port_conf *ports[PAL_MAX_PORT];
	struct sk_buff *skbs[PAL_RCV_BURST];

	for (i = 0; i < PAL_MAX_PORT; i++) {
		rxqs[i] = thconf->rxq[i];
	}

	/*
	 * Reorganize the queue ids without holes, so that the traverse process
	 * can be more efficent
	 */
	for (i = n_port = 0; i < pal_phys_port_count(); i++) {
		if (!pal_port_enabled(i) || pal_port_numa(i) != pal_numa_id()
				|| pal_port_conf(i)->vnic_ip == 0)
			continue;
		ports[n_port++] = pal_port_conf(i);
	}

	pal_cpu_idle();
	while (1) {
		for (i = 0; i < n_port; i++) {
            /*to reduce the flush port frequency, every 64*32 pkts flush once*/
            #define PAL_TX_FLUSH_COUNT 64
            thconf->flush_count++;

			/*Freeing ip fragment packpet will use the  frequency  32*1*/
			rte_ip_frag_free_death_row(&thconf->ip_reassemble_config.death_row,
						PREFETCH_OFFSET);

            if(unlikely(thconf->flush_count == PAL_TX_FLUSH_COUNT)) {
                pal_flush_port();
                thconf->flush_count = 0;
            }
			port_id = ports[i]->port_id;

			n_rx = rte_eth_rx_burst(port_id, rxqs[port_id],
			              (struct rte_mbuf **)skbs, PAL_RCV_BURST);
			if (n_rx == 0) {
				if(unlikely(sleep))
					usleep(sleep);
				continue;
			}

			pal_cpu_work();
			thconf->stats.ports[port_id].rx_pkts += n_rx;

			for (j = 0; j < n_rx; j++) {
				thconf->stats.ports[port_id].rx_bytes += skb_len(skbs[j]);
			//	rte_prefetch0((void *)skbs[j]);
				skb_reset_eth_header(skbs[j]);
				skbs[j]->recv_if = port_id;
				l2_handler(skbs[j]);
			}
			pal_cpu_idle();
		}

		if (thconf->cmd) {
			pal_cpu_work();
			pal_thread_handle_cmd(thconf->cmd, thconf->cmd_arg);
			thconf->cmd = 0;
			pal_cpu_idle();
		}
	}

	return 0;
}

