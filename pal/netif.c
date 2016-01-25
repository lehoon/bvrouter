#include <rte_kni.h>
#include <rte_ethdev.h>
#include <rte_eth_bond.h>
#include "thread.h"
#include "pktdef.h"
#include "netif.h"
#include "skb.h"
#include "utils.h"
#include "malloc.h"
#include "cpu.h"
#include "ipgroup.h"
#include "vnic.h"
#include "bonding.h"
#include "jiffies.h"
#include "receiver.h"
/* Number of mbufs in mempool that is created */
#define NB_RX_MBUF		(8192 * 16)

enum pal_port_type {
	PAL_PORT_PHYS = 0, /* physical ports, default value */
	PAL_PORT_VLAN,     /* vlan ports, add and strip vlan tag automically */
};

static int pal_send_pkt_gw(struct sk_buff *skb, unsigned port_id);

/* function used to send a packet */
int (* pal_send_pkt)(struct sk_buff *skb, unsigned port_id) = pal_send_pkt_gw;

/*
 * @brief Build ether header and transmit a packet to gatewayt
 * @param port_id Port used to transmit the packet
 * @param skb The packet to be sent
 * @param txq_id The id of tx queue to be used for transmit
 * @return 0 on success, -1 on failure
 * @note Before calling this function, skb->data must point to the ip header,
 *       skb->data_len and skb->pkt_len must be set properly
 */
static int pal_send_pkt_gw(struct sk_buff *skb, unsigned port_id)
{
	int i;
	unsigned txq_id = pal_cur_thread_conf()->txq[port_id];
	struct eth_hdr *eth;
	struct port_conf *port = pal_port_conf(port_id);
	struct rte_mbuf *mbuf = &skb->mbuf;

	eth = (struct eth_hdr *)skb_push(skb, sizeof(struct eth_hdr));
	mac_copy(eth->src, port->mac);
	mac_copy(eth->dst, port->gw_mac);
	eth->type = pal_htons_constant(PAL_ETH_IP);

	pal_cur_thread_conf()->stats.ports[port_id].tx_pkts++;
	pal_cur_thread_conf()->stats.ports[port_id].tx_bytes += skb_len(skb);

	if (skb->dump)
		pal_dump_pkt(skb, 2000);

	for (i = 0; i < 3; i++) {
		if (rte_eth_tx_burst(port_id, txq_id, &mbuf, 1) == 1) {
			return 0;
		}
	}

	pal_cur_thread_conf()->stats.ports[port_id].tx_err++;

	return -1;
}

/*
 * @brief Transmit a packet from a specified port.
 *        Data to be sent starts from skb->data, and ends at skb-data + skb_len(skb)
 * @param port_id Port used to transmit the packet
 * @param skb The packet to be sent
 * @param txq_id The id of tx queue to be used for transmit
 * @return 0 on success, -1 on failure
 * @note For logical ports, caller must use the same queue id as the cresponding
 *       physical port.
 */
int pal_send_raw_pkt(struct sk_buff *skb, unsigned port_id)
{
	unsigned txq_id = pal_cur_thread_conf()->txq[port_id];
	struct rte_mbuf *mbuf;

	pal_cur_thread_conf()->stats.ports[port_id].tx_pkts++;
	pal_cur_thread_conf()->stats.ports[port_id].tx_bytes += skb_len(skb);

	mbuf = &skb->mbuf;
	if (rte_eth_tx_burst(port_id, txq_id, &mbuf, 1) == 1) {
		return 0;
	}

	pal_cur_thread_conf()->stats.ports[port_id].tx_err++;

	return -1;
}


/*
 * @brief Transmit batch packets from a specified port.
 * @param port_id Port used to transmit the packet
 * @param skb The packet to be sent
 * @param txq_id The id of tx queue to be used for transmit
 * @return 0 on success,  > 0 for failure send pkts
 * @note For logical ports, caller must use the same queue id as the cresponding
 *       physical port.
 */
int pal_send_batch_pkt(struct sk_buff *skb, unsigned port_id)
{
	struct rte_mbuf *mbuf = &skb->mbuf;
    unsigned n, i, error = 0;
    unsigned txq_id = pal_cur_thread_conf()->txq[port_id];
	pal_cur_thread_conf()->stats.ports[port_id].tx_pkts++;
	pal_cur_thread_conf()->stats.ports[port_id].tx_bytes += skb_len(skb);
    unsigned *len = &pal_cur_thread_conf()->tx_mbuf[port_id].len;
    struct rte_mbuf **buffer = pal_cur_thread_conf()->tx_mbuf[port_id].m_table;
    buffer[(*len)++] = mbuf;
    if(unlikely(*len == MAX_PKT_SEND_BURST)) {
	    n = rte_eth_tx_burst(port_id, txq_id, buffer, MAX_PKT_SEND_BURST);

        for (i = n; i < MAX_PKT_SEND_BURST; i++) {
        /*failed to send MAX_PKT_BURST pkts,try to send the rest one by one*/
            if ( 1 != rte_eth_tx_burst(port_id, txq_id, &buffer[i], 1))
            {
                error++;
                rte_pktmbuf_free(buffer[i]);
		    }
        }
        *len = 0;
        pal_cur_thread_conf()->tx_mbuf[port_id].last_send = jiffies;

	}
	pal_cur_thread_conf()->stats.ports[port_id].tx_err += error;
	return error;
}

/*
 * @brief flush port txq buffer in case some pkts never got send.
 * @flush base on jiffies.
 */
void pal_flush_port(void)
{
    unsigned i, j, txq_id, n, len;
    struct rte_mbuf **buffer = NULL;
    for(i = 0; i < PAL_MAX_PORT; i++)
    {
        len = pal_cur_thread_conf()->tx_mbuf[i].len;
        if(0 == len) {
            continue;
        }
        txq_id = pal_cur_thread_conf()->txq[i];
        buffer = pal_cur_thread_conf()->tx_mbuf[i].m_table;

        n =  rte_eth_tx_burst(i, txq_id, buffer, len);
        for (j = n; j < len; j++) {
        /*if can not send the pkts in a batch,try to send one by one*/
            if( 1 != rte_eth_tx_burst(i, txq_id, &buffer[j], 1))
            {
                pal_cur_thread_conf()->stats.ports[i].tx_err++;
                rte_pktmbuf_free(buffer[j]);
            }
        }
        pal_cur_thread_conf()->tx_mbuf[i].len = 0;

        //pal_cur_thread_conf()->tx_mbuf[i].last_send = jiffies;
    }
}



/*
 * link-status-changing(LSC) callback
 */
static void pal_lsc_callback(uint8_t port_id, enum rte_eth_event_type type,
	__unused void *param)
{
	struct rte_eth_link link;
	struct port_conf *port = pal_port_conf(port_id);

	if (type == RTE_ETH_EVENT_INTR_LSC) {
		PAL_LOG("LSC Port:%u Link status changed\n", port_id);
		rte_eth_link_get(port_id, &link);
		/* rte_eth_link_get_nowait(port_id, &link); */
		if (link.link_status) {
			port->status = 1;
			PAL_LOG("LSC Port:%u Link Up - speed %u Mbps - %s\n",
				port_id, (unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
				("full-duplex") : ("half-duplex"));
		} else {
			port->status = 0;
			PAL_LOG("LSC Port:%u Link Down\n", port_id);
		}
	}
}

/*
 * @brief Initialize receive queues of a physical NIC port and assign each
 *        rxq to a receiver
 * @param port_id Id of the port to be initialized
 * @param rxq Number of rx queues to be created
 * @return 0 on success, -1 on failure
 */
static int pal_port_rxq_init(unsigned port_id, unsigned n_rxq)
{
	int ret;
	int numa;
	int receiver;
	unsigned rxq;
	char name[RTE_RING_NAMESIZE];
	struct rte_mempool *pktmbuf_pool;
	struct rte_mempool *pktmbuf_pools[PAL_MAX_RECEIVER] = {NULL,};
	struct rte_eth_rxconf rx_conf = {
		.rx_thresh = {
			.pthresh = 8,   /* Ring prefetch threshold */
			.hthresh = 8,   /* Ring host threshold */
			.wthresh = 4,   /* Ring writeback threshold */
		},
		.rx_free_thresh = 0,    /* Immediately free RX descriptors */
		.rx_drop_en = 1,
	};

	if(n_rxq > PAL_MAX_RECEIVER)
		PAL_PANIC("%d receivers, beycond %d\n",n_rxq,PAL_MAX_RECEIVER);

	numa = pal_port_numa(port_id);
	if (numa < 0)
		PAL_PANIC("port %u numa invalid: %d\n", port_id, numa);

	/* Setup receive queues and assign them to receivers */
	for (rxq = 0; rxq < n_rxq; rxq++) {
		snprintf(name, RTE_RING_NAMESIZE, "port_%u_pool_%u", port_id, rxq);
		/* Use SC/MP pools, because the packets may be freed by workers */
		pktmbuf_pool = rte_mempool_create(name, NB_RX_MBUF, MBUF_SIZE,
				0, sizeof(struct rte_pktmbuf_pool_private),
				rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init,
				NULL, numa, MEMPOOL_F_SC_GET);
		if (pktmbuf_pool == NULL)
			PAL_PANIC("Could not initialise mbuf pool %u\n", rxq);

		ret = rte_eth_rx_queue_setup(port_id, rxq, NETIF_NB_RXD,
		        rte_eth_dev_socket_id(port_id), &rx_conf, pktmbuf_pool);
		if (ret < 0)
			PAL_PANIC("Could not setup up RX queue %u for "
			                 "port%u (%d)\n", rxq, port_id, ret);
		pktmbuf_pools[rxq] = pktmbuf_pool;
	}

	rxq = 0;
	PAL_FOR_EACH_RECEIVER (receiver) {
		if (pal_tid_to_numa(receiver) != numa)
			continue;

		pal_thread_conf(receiver)->rxq[port_id] = rxq;
		pal_thread_conf(receiver)->ip_fragment_config.rxqueue.direct_pool = pktmbuf_pools[rxq];
		PAL_DEBUG("port %u, Rxq %u assigned to receiver %u\n",
		                                      port_id, rxq, receiver);
		rxq++;
	}

	return 0;
}

/*
 * @brief Initialize transmit queues of a physical NIC port and assign the last
 *        tx queues to receiver and arp thread. The first txq_user queues are
 *        reserved for apps
 * @param port_id Id of the port to be initialized
 * @param txq_user Number of tx queues reserved for app. Ids of these queues are
 *        always 0 - *txq_user-1*
 * @param txq Number of total tx queues to be created.
 * @return 0 on success, -1 on failure
 */
static int pal_port_txq_init(unsigned port_id, unsigned n_txq)
{
	int ret;
	int numa;
	int tid;
	unsigned txq;
	struct rte_eth_txconf tx_conf = {
		.tx_thresh = {
			.pthresh = 36,  /* Ring prefetch threshold */
			.hthresh = 0,   /* Ring host threshold */
			.wthresh = 0,   /* Ring writeback threshold */
		},
		.tx_free_thresh = 0,    /* Use PMD default values */
		.tx_rs_thresh = 0,      /* Use PMD default values */
	};

	numa = pal_port_numa(port_id);
	if (numa < 0) {
		PAL_PANIC("port %u numa invalid: %d\n", port_id, numa);
		return -1;
	}

	for (txq = 0; txq < n_txq; txq++) {
		ret = rte_eth_tx_queue_setup(port_id, txq, NETIF_NB_TXD,
		                      rte_eth_dev_socket_id(port_id), &tx_conf);
		if (ret < 0)
			PAL_PANIC("Could not setup up TX queue %u for "
			              "port%u (%d)\n", txq, port_id, ret);
	}

	/* assign txq queues to all threads */
	txq = 0;
	PAL_FOR_EACH_THREAD (tid) {
		//if (pal_tid_to_numa(tid) != numa)
		//	continue;

		/* reserve the first *tx_user* txqs for app */
		pal_thread_conf(tid)->txq[port_id] = txq;
		PAL_DEBUG("port %u, Txq %u assigned to thread %d\n",
		                      port_id, txq, tid);
		txq++;
	}

	return 0;
}

/*
 * Initialise a single port on an Ethernet device.
 * This function allocates a tx ring for each thread.
 */
static int pal_port_init(unsigned port_id, uint32_t ip, uint32_t gw,
                                           uint32_t netmask, uint8_t *mac,
					   uint8_t slaves_cnt, uint8_t *slaves)
{
	int i;
	int ret;
	int numa = rte_eth_dev_socket_id(port_id);
	unsigned rxq, txq;
	/* TODO optimize the paramerters */
	struct rte_eth_conf port_conf;
	struct port_conf *port;

	BUILD_BUG_ON(PAL_MAX_PORT > 127);
	/* since we alloc a txq for each thread, if number of threads is
	 * larger than QUEUE_STAT_CNTRS, we cannot get stats of some tx queues
	 */
	BUILD_BUG_ON(PAL_MAX_THREAD > RTE_ETHDEV_QUEUE_STAT_CNTRS);
	/* headroom too small. enlarge RTE_PKTMBUF_HEADROOM in your dpdk config */
	BUILD_BUG_ON(PAL_PKT_HEADROOM < (int)64);
	/* set RTE_PKTBUF_HEADROOM in you dpdk config to 2-byte aligned
	 * but not 4-byte aligned so that ip headers of received pkts are
	 * 4-byte aligned */
	BUILD_BUG_ON(RTE_PKTMBUF_HEADROOM % 4 == 0 ||
	            RTE_PKTMBUF_HEADROOM % 2 != 0);

	if (g_pal_config.numa[numa] == NULL) {
		PAL_PANIC("Enabled port %u on numa %d, but no threads on this numa\n",
			port_id, numa);
	}

	/* TODO: check whether netmask is valid,
	 *       check whether ip and gw are in the same subnet. etc. */
	if (ip == 0 || gw == 0 || netmask == 0)
		PAL_PANIC("ip or gw or netmask is 0 for port %du\n", port_id);

	/* ip and gw must be in the same subnet */
	if ((ip & netmask) != (gw & netmask))
		PAL_PANIC("ip and gw are not in the same subnet\n");

	/* alloc configuration strucutre first */
	port = (struct port_conf *)pal_zalloc_numa(sizeof(* port), numa);
	if (port == NULL)
		PAL_PANIC("alloc port conf failed\n");
	g_pal_config.port[port_id] = port;
	port->numa = numa;
	port->port_id = port_id;
	port->port_type = PAL_PORT_PHYS;
	port->vnic_ip = ip;
	port->gw_ip = gw;
	port->netmask = netmask;

	if (ipg_add_ip(get_pal_ipg(numa), ip, port_id, PAL_DIP_VNIC, 0) < 0)
		PAL_PANIC("add gateway ip of port %u failed\n", port_id);

	if (ipg_add_ip(get_pal_ipg(numa), gw, port_id, PAL_DIP_GW, 0) < 0)
		PAL_PANIC("add gateway ip of port %u failed\n", port_id);

	/* header_split, hw_vlan_filter, hw_vlan_extend, jumbo_frame are disabled */
	memset(&port_conf, 0, sizeof(port_conf));
	if(slaves_cnt == 0)
	{
	  port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	  port_conf.rxmode.hw_ip_checksum = 1;   /* IP/TCP/UDP csum offload */
	  port_conf.rxmode.hw_vlan_strip = 1;    /* Hw vlan strip */
	  port_conf.rxmode.hw_strip_crc = 1;     /* CRC stripped by hardware */
	  port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
	  port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IPV4 | ETH_RSS_IPV4_TCP | \
						  ETH_RSS_IPV4_UDP;
	  /* TODO: use default settings for fdir currently. reconsider these
	   * settings later */
	  port_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
	  port_conf.intr_conf.lsc = 1;
	}else{
	  	port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
		port_conf.rxmode.hw_ip_checksum = 1;   /* IP/TCP/UDP csum offload */
	  	port_conf.rxmode.hw_vlan_strip = 1;    /* Hw vlan strip */
	  	port_conf.rxmode.hw_strip_crc = 1;     /* CRC stripped by hardware */
	  	port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
		port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	  	port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IPV4 | ETH_RSS_IPV4_TCP | \
						  ETH_RSS_IPV4_UDP;
	}

	/* one rxq for each receiver. one txq for each thread */
	rxq = g_pal_config.numa[numa]->n_receiver;
	txq = g_pal_config.sys.n_thread;
	port->n_rxq = rxq;
	port->n_txq = txq;

	if(slaves_cnt > 0)
	{
		int idx;
		for (idx = 0; idx < slaves_cnt; idx++){
			ret = rte_eth_dev_configure(slaves[idx], rxq, txq, &port_conf);
			if (ret < 0)
				PAL_PANIC("Could not configure port %u (%d)\n", (unsigned)slaves[idx], ret);
		}
	}

	/* Initialise device and RX/TX queues */
	PAL_LOG("Initialising port %u, %u rxq, %u txq\n", (unsigned)port_id, rxq, txq);
	ret = rte_eth_dev_configure(port_id, rxq, txq, &port_conf);
	if (ret < 0)
		PAL_PANIC("Could not configure port %u (%d)\n", (unsigned)port_id, ret);

	/*
	 * register link-status-changing(LSC) interrupt handler
	 */
	if(slaves_cnt == 0)
	{
	    rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC,
	                                  pal_lsc_callback, NULL);
	}else{
	    //TODO: delete these code when Fortille is ok for bonding
	}

	/* Setup receive queues */
	pal_port_rxq_init(port_id, rxq);

	/* Setup transmit queuess */
	pal_port_txq_init(port_id, txq);

	if(slaves_cnt > 0)
	{
		add_slaves_to_bonded_device(port_id, slaves, slaves_cnt);
	}

	for (i = 0; i < 6; i++) {
		if (mac[i] != 0) {
			memcpy(port->mac, mac, 6);
			break;
		}
	}
	if (i == 6) {
		rte_eth_macaddr_get(port_id, (struct ether_addr *)port->mac);
        memcpy(mac, port->mac, 6);
    }
	/* The device is ready, start it */

   //PAL_LOG("mac addr %x:%x:%x:%x:%x:%x",port->mac[0],port->mac[1],port->mac[2],port->mac[3],port->mac[4],
   // port->mac[5]);

    //l2_init(port->vnic_ip, port->mac, port->gw_ip);
	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		PAL_PANIC("Could not start port%u (%d)\n", (unsigned)port_id, ret);

	/*
	 * enable promiscuous mode to receive packets for vnic
	 */
	/* TODO: set vnic mac to nic mac and disable promiscuous mode */
	rte_eth_promiscuous_enable(port_id);

	return 0;
}


/*
 * @brief init all nic ports
 * @note panics on failure.
 */
void pal_ports_init(struct pal_config *conf)
{
	int n_port = 0;
	int idx;
	char port_name[RTE_KNI_NAMESIZE];
	int socketid = 0;

	for(idx=0; idx < PAL_MAX_PORT; idx++)
	{
		if(conf->port[idx].ip != 0)
		{
			if(conf->port[idx].slaves_cnt == 0)
			{
				conf->port[idx].port_id = idx;
			}else{
				memset(port_name,0, RTE_KNI_NAMESIZE);
				socketid = rte_eth_dev_socket_id(conf->port[idx].slaves[0]);
				snprintf(port_name, RTE_KNI_NAMESIZE, "bond_%u",idx);
				conf->port[idx].port_id = create_bonded_device(port_name,
						BONDING_MODE_BALANCE, socketid);
				rte_eth_bond_xmit_policy_set(conf->port[idx].port_id,BALANCE_XMIT_POLICY_LAYER34);
				if(conf->port[idx].port_id <= 0)
				{
					PAL_PANIC("Cannot creat the bonding interface:%s", port_name);
				}
			}
		}
	}

	if (PAL_MAX_PORT < (rte_eth_dev_count())) {
		PAL_PANIC("PAL_MAX_PORT(%d) < dev_count(%d)\n", PAL_MAX_PORT,
		          rte_eth_dev_count());
	}

	g_pal_config.sys.n_physport = rte_eth_dev_count();
	g_pal_config.sys.n_port = rte_eth_dev_count();
	for (idx = 0; idx < g_pal_config.sys.n_physport; idx++) {
		if (conf->port[idx].ip == 0)
			continue;
		pal_port_init(conf->port[idx].port_id, conf->port[idx].ip,
		                       conf->port[idx].gw_ip,
		                       conf->port[idx].netmask,
		                       conf->port[idx].mac,
							   conf->port[idx].slaves_cnt,
							   conf->port[idx].slaves);
		if (!vnic_enabled())
			continue;

		snprintf(pal_port_conf(conf->port[idx].port_id)->name, RTE_KNI_NAMESIZE,
		                                     "vnic%u", idx);
		pal_vnic_create(conf->port[idx].port_id, pal_thread_conf(g_pal_config.vnic.tid)->cpu);
		n_port++;
	}

	pal_dump_vnic_create();

	if (n_port == 0)
		PAL_PANIC("no port enabled, what am I doing here? I quit :)");

	/* check whether application initialized some ports which do not exist */
	for (; idx < PAL_MAX_PORT; idx++) {
		if (conf->port[idx].ip != 0) {
			PAL_PANIC("port %d does not exist\n", idx);
		}
	}
}


void pal_port_get_stats(int port_id, struct pal_port_hw_stats *stats)
{
	unsigned i;
	struct rte_eth_stats dpdk_stats;

	rte_eth_stats_get(port_id, &dpdk_stats);

	#define COPY(member) \
		stats->member = dpdk_stats.member
	COPY(ipackets);
	COPY(opackets);
	COPY(ibytes);
	COPY(obytes);
	COPY(ierrors);
	COPY(oerrors);
	COPY(imcasts);
	COPY(rx_nombuf);
	COPY(fdirmatch);
	COPY(fdirmiss);

	#undef COPY

	BUILD_BUG_ON(PAL_MAX_THREAD > RTE_ETHDEV_QUEUE_STAT_CNTRS);
	#define COPY(member) \
		for (i = 0; i < ARRAY_SIZE(stats->member); i++) { \
			stats->member[i] = dpdk_stats.member[i]; \
		}
	COPY(q_ipackets);
	COPY(q_opackets);
	COPY(q_ibytes);
	COPY(q_obytes);
	COPY(q_errors);

	#undef COPY
}
