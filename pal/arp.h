#ifndef _PALI_ARP_H_
#define _PALI_ARP_H_

#include "utils.h"
#include "skb.h"

/*
 * @brief main function of arp thread
 */
extern int arp_loop(__unused void *data);

/*
 * @brief test whether arp function is fully enabled. When enabled, 
 *        applications can send packets to l2 neighbors, or they can only
 *        send packets to gateways.
 * @return 1 if enabled, 0 otherwise
 */
extern int l2_enabled(void);

/*
 * @brief enable fully arp function on thread tid;
 */
extern void pal_enable_l2(int tid);

/*
 * @brief initialize arp configuration;
 */
extern int pal_arp_init(void);

/*
 * @called by receiver to handle arp requests and responses
 */
extern int arp_handler(struct sk_buff *skb);

extern void nn_arp_init(uint32_t gw_ip);

extern int rcv_pkt_ext_arp_process(struct sk_buff *skb);

#endif
