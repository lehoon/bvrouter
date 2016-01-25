#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <assert.h>

#include <rte_eth_bond.h>
#include <arpa/inet.h>

#include "main.h"
#include "pal_phy_vport.h"
#include "pal_ip_cell.h"
#include "../vtep.h"
#include "pal_error.h"
#include "pal_l2_ctl.h"
#include "pal_utils.h"


extern 	int l2_handler(struct sk_buff *skb);
extern void nn_l2_main_loop(void);
/* main processing loop */
void nn_l2_main_loop(void)
{
	struct sk_buff *skbs[MAX_PKT_BURST];
	unsigned lcore_id;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;

	lcore_id = rte_lcore_id();
	qconf = &Lcore_queue_conf[lcore_id];
	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);
	for (i = 0; i < qconf->n_rx_port; i++) {
		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);
	}

	while (1) {
		for (i = 0; i < qconf->n_rx_port; i++) {
			portid = qconf->rx_port_list[i];

			nb_rx = rte_eth_rx_burst((uint8_t) portid, 0,
					 (struct rte_mbuf **)skbs, MAX_PKT_BURST);

			for (j = 0; j < nb_rx; j++) {
				skb_reset_eth_header(skbs[j]);
				skbs[j]->recv_if = portid;
				l2_handler(skbs[j]);
			}
		}
	}
}

extern void l2_init_test(uint32_t vtep_ip,uint8_t *vtep_mac,uint32_t gw_ip);
extern void nn_arp_init(uint32_t gw_ip);

extern void phy_vport_test(void);
extern 	void int_vport_test(void);
extern int route_test(void);

static void *vport_test_thread(void *arg){
	arg = NULL;	
	sleep(2);

	do{
		usleep(1000*100);
		//phy_vport_test();
		int_vport_test();
		//route_test();
	}while(1);
	
    return NULL;
}

static pthread_t ntid;

void l2_init_test(uint32_t vtep_ip,uint8_t *vtep_mac,uint32_t gw_ip)
{	
	vport_net_init();
	phy_net_init();
	vxlan_dev_net_init();

	vtep_init(vtep_ip,vtep_mac);
	nn_arp_init(gw_ip);
	
	pthread_create(&ntid, NULL, vport_test_thread, NULL);
}
