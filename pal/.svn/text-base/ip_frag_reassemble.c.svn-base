#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <rte_kni.h>
#include <rte_ethdev.h>
#include <rte_eth_bond.h>

#include "pal_error.h"
#include "vtep.h"
#include "pal_netif.h"
#include "pal_spinlock.h"
#include "pal_ip_frag_reassemble.h"

static pal_rwlock_t	fragment_table_lock;

static struct rte_ip_frag_tbl *frag_tbl = NULL;

static uint32_t max_flow_num = DEF_FLOW_NUM;
static uint32_t max_flow_ttl = DEF_FLOW_TTL;

extern int ip_fragment_send(struct sk_buff *skb);
/*
*  Fragment the packet , and then send it. 
*  Please Notes that the skb->data must be the pointer of iph_hdr.
*/
int ip_fragment_send(struct sk_buff *skb)
{
	int32_t i,len;
	uint8_t port_out;		
	struct eth_hdr *eth;
	struct rte_mbuf *m;
	struct ip_fragment_conf *qconf = &(pal_cur_thread_conf()->ip_fragment_config);
	struct fragment_rx_queue *rxq;
	struct sk_buff *skbp;

	m = &skb->mbuf;
	port_out = skb->recv_if;
	rxq = &qconf->rxqueue;
		
	len = rte_ipv4_fragment_packet(m,
			&qconf->tx_mbuf.m_table[0],
			(uint16_t)(MBUF_TABLE_SIZE),
			IPV4_MTU_DEFAULT,
			rxq->direct_pool, rxq->indirect_pool);

	/* Free input packet */
	rte_pktmbuf_free(m);

	/* If we fail to fragment the packet */
	if (unlikely (len < 0))
		return -EFAULT;

	for (i = 0; i < len; i ++) {
		m = qconf->tx_mbuf.m_table[i];
		m->pkt.vlan_macip.f.l2_len = sizeof(struct eth_hdr);
		skbp = (struct sk_buff *)m;
		skbp->recv_if = port_out;

		skb_push(skbp, sizeof(*eth));
		skb_reset_eth_header(skbp);
		eth = skb_eth_header(skbp);
		eth->type = pal_htons(PAL_ETH_IP);
		mac_copy(eth->dst, get_nn_gw_mac());
		mac_copy(eth->src, get_vtep_mac());

		/* Transmit packets , do not care it's correct*/
		pal_send_batch_pkt(skbp, skbp->recv_if);
	}	
	
	qconf->tx_mbuf.len = 0;

	return 0;	
}

extern  struct rte_mbuf * ip_frag_reassemble_packet(struct sk_buff *skb,struct ip_hdr  *iph);

/*
*  This function either return a pointer to valid mbuf that contains reassembled packet, or NULL
*  (if the packet canot be reassembled for some reason)
*/
 struct rte_mbuf * ip_frag_reassemble_packet(struct sk_buff *skb,struct ip_hdr  *iph)
{
	struct rte_mbuf *m = NULL;		
	struct rte_mbuf *mo = NULL;
	struct rte_ip_frag_death_row *dr = NULL;
	struct ip_reassemble_conf *qconf = &(pal_cur_thread_conf()->ip_reassemble_config);

	m = &skb->mbuf;	
	dr = &(qconf->death_row);
	
	/* prepare mbuf: setup l2_len/l3_len. */
	m->pkt.vlan_macip.f.l2_len = sizeof(struct eth_hdr);
	m->pkt.vlan_macip.f.l3_len = sizeof(struct ip_hdr);

	/* All update/lookup operations on Fragmen Table are not thread safe.
	*  So, we need use lock to protect it.*/
	pal_rwlock_write_lock(&fragment_table_lock);
	mo = rte_ipv4_frag_reassemble_packet(frag_tbl, dr, m, rte_rdtsc(), 
				(struct ipv4_hdr *)iph);
	pal_rwlock_write_unlock(&fragment_table_lock);
	
	return mo;
}

/*create Fragmen Table*/
static int setup_frg_tbl(int numa_id)
{
	uint64_t frag_cycles;
	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S *
		max_flow_ttl;

	if ((frag_tbl = rte_ip_frag_table_create(max_flow_num,
			IP_FRAG_TBL_BUCKET_ENTRIES, max_flow_num, frag_cycles,
			numa_id)) == NULL) {
		PAL_PANIC("ip_frag_tbl_create failed\n");
		return -1;
	}
	
	return 0;
}

extern void ip_frag_reassemble_init(int numa_id);
/* 
*  Init Fragmen Table and lock, etc.
*/
void ip_frag_reassemble_init(int numa_id)
{
	pal_rwlock_init(&fragment_table_lock);

	setup_frg_tbl(numa_id);
}
