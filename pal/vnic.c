#include <sys/epoll.h>
#include <sys/socket.h>
//#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if_arp.h>

#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_spinlock.h>

#include "vnic.h"
#include "conf.h"
#include "netif.h"
#include "thread.h"
#include "cpu.h"

#define KNI_PKT_BURST_SZ 32

/* number of mbufs for a vnic. should be greater than 1024, which
 * is the size of tx ring of kni */
#define PAL_VNIC_NB_MBUF	(PAL_MAX_THREAD * 1024)

int vnic_enabled(void)
{
	return g_pal_config.vnic.tid != PAL_MAX_THREAD;
}

void pal_enable_vnic(int tid)
{
	g_pal_config.vnic.tid = tid;
}

static void kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

/*
 * send a packet to vnic.
 * Note1: this function can only be called by pal, cause now we only allocate
 *       rxqs for receivers.
 * Note2: this packet is copied, so the original packet is not freed in any case
 */
int pal_send_to_vnic(unsigned vnic_id, struct sk_buff *skb)
{
	struct thread_conf *thconf = pal_cur_thread_conf();
	struct port_conf *port = pal_port_conf(vnic_id);
	unsigned rxq = thconf->rxq[vnic_id];
	struct sk_buff *skb2;

	thconf->stats.tap.totap_pkts++;
	thconf->stats.tap.totap_bytes += skb_l2_len(skb);

	skb2 = skb_clone(skb, port->vnic_skbpool, 2000);

	if (skb2 != NULL) {
		if (rte_kni_tx_burst(port->vnic,
				(struct rte_mbuf **)&skb2, 1, rxq) == 1) {
			return 0;
		} else {
			pal_skb_free(skb2);
		}
	}

	thconf->stats.tap.totap_err_pkts++;
	thconf->stats.tap.totap_err_bytes += skb_l2_len(skb);
	PAL_DEBUG("send to vnic %d failed\n", vnic_id);
	return -1;
}


/* set ip and mac attributes of vnic */
static void set_vnic_attr(char *name, uint32_t ip, uint32_t netmask)
{
	/* TODO: set mac */
	struct ifreq ifr;
	uint8_t *char_addr;
	struct sockaddr *addr_sock = NULL;
	int udp_fd = socket(PF_INET, SOCK_DGRAM, 0);

	if (udp_fd < 0)
		PAL_PANIC("set vnic attr failed: udp_sock_create\n");

	/* set ip address */
	memset(&ifr, 0, sizeof(ifr));
	sprintf(ifr.ifr_name, "%s", name);
	char_addr = (uint8_t *)&ip;

	addr_sock = &ifr.ifr_addr;
	addr_sock->sa_family = AF_INET;
	memcpy((uint8_t *)addr_sock + offsetof(struct sockaddr_in, sin_addr),
					char_addr, sizeof(ip));
	if (ioctl(udp_fd, SIOCSIFADDR, (void *)&ifr) < 0)
		PAL_PANIC("set vnic addr error\n");

	/* set netmask */
	char_addr = (uint8_t *)&netmask;
	memset(&ifr, 0, sizeof(ifr));
	sprintf(ifr.ifr_name, "%s", name);

	/* use sockaddr directly, zhangjian mod */
	addr_sock = &ifr.ifr_netmask;
	addr_sock->sa_family = AF_INET;
	memcpy((char *)addr_sock + offsetof(struct sockaddr_in, sin_addr),
				char_addr, sizeof(netmask));
	if (ioctl(udp_fd, SIOCSIFNETMASK, (void *)&ifr) < 0)
		PAL_PANIC("set vnic netmask error\n");

	close(udp_fd);
}

 /*
  * @brief Create a vnic interface for a specified physical port
  * @param port_id Id of the physical port
  * @param core_id Id of core on which kni kernel thread runs. Note this is
  *        not the VNIC thread
  * @param name Name of this interface
  */
 int pal_vnic_create(int port_id, unsigned core_id)
 {
     unsigned phys_port = port_id;
     struct rte_kni *kni;
     struct rte_kni_conf conf;
     struct rte_eth_dev_info dev_info;
     struct rte_mempool *mbuf_pool;
     char mbuf_name[RTE_RING_NAMESIZE];
     struct port_conf *port = pal_port_conf(port_id);

     if (!vnic_enabled()) {
         PAL_ERROR("Vnic not enabled\n");
         return -1;
     }

     if (port->vnic) {
         PAL_ERROR("vnic for port %d already created\n", port_id);
         return -1;
     }

     if (port_id >= PAL_MAX_PORT || port == NULL) {
         PAL_ERROR("invliad port_id to create vnic: %d\n", port_id);
         return -1;
     }

     /* Clear conf at first */
     memset(&conf, 0, sizeof(conf));
     strncpy(conf.name, port->name, RTE_KNI_NAMESIZE);
     conf.core_id = core_id;
     conf.force_bind = 1;
     conf.mbuf_size = MBUF_SIZE;
     conf.nb_rxq = port->n_rxq;
     /*
      * The first KNI device associated to a port
      * is the master, for multiple kernel thread
      * environment.
      */

     memset(&dev_info, 0, sizeof(dev_info));
     rte_eth_dev_info_get(phys_port, &dev_info);
     conf.addr = dev_info.pci_dev->addr;
     conf.id = dev_info.pci_dev->id;

     snprintf(mbuf_name, sizeof(mbuf_name), "vnic_%d", port_id);
     /* we have only one tx queue, so set MEMPOOL_F_SC_GET flag */
     mbuf_pool = rte_mempool_create(mbuf_name, PAL_VNIC_NB_MBUF, MBUF_SIZE,
             0,
             sizeof(struct rte_pktmbuf_pool_private),
             rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,
             port->numa, 0);
     if (mbuf_pool == NULL) {
         PAL_ERROR("Alloc mbuf_pool for vnic %d failed\n", port_id);
         return -1;
     }
     port->vnic_skbpool = (struct pal_slab *)mbuf_pool;

     kni = rte_kni_alloc(mbuf_pool, &conf, NULL);
     if (!kni) {
         PAL_ERROR("Fail to create kni for port: %d\n", port_id);
         return -1;
     }

     port->vnic = kni;

     set_vnic_attr(port->name, port->vnic_ip, port->netmask);

     return 0;
 }


int pal_dump_vnic_create(void)
{
	struct rte_kni *kni;
	struct rte_kni_conf conf;
	struct rte_mempool *mbuf_pool;

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));
	strncpy(conf.name, "dump0", RTE_KNI_NAMESIZE);
	conf.force_bind = 1;
	conf.mbuf_size = MBUF_SIZE;
	conf.core_id = pal_thread_conf(g_pal_config.vnic.tid)->cpu;

	/* create an rxq for each thread, maybe some of them are never used.
	 * Note: If you dump packet both in workers and receivers, there
	 * may be an out-of-order problem, because different threads have
	 * different queues.
	 */
	conf.nb_rxq = g_pal_config.sys.n_thread;

	/* we have only one tx queue, so set MEMPOOL_F_SC_GET flag */
	mbuf_pool = rte_mempool_create("dump0",
			PAL_VNIC_NB_MBUF, MBUF_SIZE,
			0, sizeof(struct rte_pktmbuf_pool_private),
			rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,
			rte_socket_id(), 0);
	if(mbuf_pool == NULL) {
		PAL_PANIC("Alloc mbuf_pool for dump vnic failed\n");
		return -1;
	}
	g_pal_config.vnic.dump_pool = (struct pal_slab *)mbuf_pool;

	kni = rte_kni_alloc(mbuf_pool, &conf, NULL);
	if (!kni)
		PAL_PANIC("Fail to create dump vnic\n");

	g_pal_config.sys.dump_vnic = kni;

	return 0;
}


/*
 * @brief Dump a packet by sending it to dump vnic.
 * @note The packet is copied
 */
int pal_dump_pkt(const struct sk_buff *skb, uint16_t size)
{
	struct sk_buff *skb2;
	unsigned dumpq = pal_cur_thread_conf()->dump_q;

	skb2 = skb_clone(skb, g_pal_config.vnic.dump_pool, size);
	if (skb2 == NULL)
		return -1;

	if (rte_kni_tx_burst(g_pal_config.sys.dump_vnic,
		        (struct rte_mbuf **)&skb2, 1, dumpq) == 1) {
		return 0;
	}

	pal_skb_free(skb2);

	PAL_DEBUG("send to dump vnic failed\n");
	return -1;

}



/* bring up a vnic */
void pal_bring_up_nic(const char *name)
{
	int udp_fd = socket(PF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

	if (udp_fd < 0)
		PAL_PANIC("bring vnic failed: udp_sock_create\n");

	memset(&ifr, 0, sizeof(ifr));
	sprintf(ifr.ifr_name, "%s", name);
	if (ioctl(udp_fd, SIOCGIFFLAGS, (void *) &ifr) < 0)
		PAL_PANIC("get vnic flags error\n");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(udp_fd, SIOCSIFFLAGS, (void *) &ifr) < 0)
		PAL_PANIC("set vnic up error\n");

	close(udp_fd);
}

int vnic_loop(__unused void *data)
{
	unsigned i, j, num;
	unsigned nb_tx, nb_kni, nopkt;
	unsigned port_id;
	struct {
		unsigned port_id;
		struct rte_kni *pkni;
        uint16_t txq;
	} vnic[PAL_MAX_PORT];
	struct rte_mbuf *pkts_burst[KNI_PKT_BURST_SZ];

	nb_kni = 0;
	for(i = 0; i < PAL_MAX_PORT; i++) {
		if(pal_port_conf(i) == NULL ||
			pal_port_conf(i)->vnic == NULL)
			continue;
		vnic[nb_kni].port_id = i;
		vnic[nb_kni].pkni = pal_port_conf(i)->vnic;
        vnic[nb_kni].txq = pal_cur_thread_conf()->txq[i];
		nb_kni++;
	}

	while(1) {
		nopkt = 1;
		/* do not handle dump vnic in the loop. Because it's only used
		 * to receive pakcets, we don't send packet from this vnic.*/
		for (i = 0; i < nb_kni; i++) {
			rte_kni_handle_request(vnic[i].pkni);

			/* Burst rx from kni */
			num = rte_kni_rx_burst(vnic[i].pkni, pkts_burst, KNI_PKT_BURST_SZ);
			if (num == 0 || unlikely(num > KNI_PKT_BURST_SZ))
				continue;

			port_id = vnic[i].port_id;
			nopkt = 0;

			pal_cur_thread_conf()->stats.ports[port_id].tx_pkts += num;
			pal_cur_thread_conf()->stats.tap.fromtap_pkts += num;
			for(j = 0; j < num; j++) {
				pal_cur_thread_conf()->stats.ports[port_id].tx_bytes +=
						rte_pktmbuf_pkt_len(pkts_burst[j]);
				pal_cur_thread_conf()->stats.tap.fromtap_bytes +=
						rte_pktmbuf_pkt_len(pkts_burst[j]);
				//pal_dump_pkt((struct sk_buff *)pkts_burst[j]);
			}


			/* Burst tx to eth */
			nb_tx = rte_eth_tx_burst(port_id, vnic[i].txq, pkts_burst, (uint16_t)num);
			if (unlikely(nb_tx < num)) {
				/* Free mbufs not tx to NIC */
				PAL_DEBUG("Kni %u received %u pkts, dropped %u\n",
				                             i, num, num - nb_tx);
				kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
				pal_cur_thread_conf()->stats.ports[port_id].tx_err += num - nb_tx;
			}
		}

		/* handle control request for dump vnic */
		rte_kni_handle_request(g_pal_config.sys.dump_vnic);

		/* sleep a while if there is no packet */
		if(nopkt)
			usleep(1000);
	}

	return 0;
}

