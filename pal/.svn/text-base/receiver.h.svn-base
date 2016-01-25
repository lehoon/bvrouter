#ifndef _PALI_RECEIVER_H_
#define _PALI_RECEIVER_H_

#include "utils.h"
#include "fifo.h"
#include "skb.h"

/*
 * @brief main function of receiver thread. It
 */
extern int receiver_loop(__unused void *arg);
extern void pal_disq_init(void);


/*
 * @brief init dispatch queues, including receiver->worker queues
          and receiver->arp queues.
 */
extern void pal_disq_init(void);

/*
 * @brief Get the packet queue configuration of the current numa
 * @return Pointer to the packet queue configuration struct
 */
static inline struct pal_fifo *pal_dispatch_fifo(int tid)
{
	/* TODO: optimize this */
	return g_pal_config.thread[pal_thread_id()]->pkt_q[tid];
}

extern void l2_init(uint32_t vtep_ip, uint32_t local_ip, uint8_t *vtep_mac,uint32_t gw_ip);
extern void l2_slab_init(int numa_id);
extern 	int l2_handler(struct sk_buff *skb);

#endif
