#ifndef _PAL_IP_FR_RE_H_
#define _PAL_IP_FR_RE_H_
#include <stdint.h>
#include <rte_kni.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include <rte_ip_frag.h>

struct fragment_rx_queue {
	struct rte_mempool *direct_pool;
	struct rte_mempool *indirect_pool;
};

#define MBUF_TABLE_SIZE 4
struct fragment_mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MBUF_TABLE_SIZE];
};

struct ip_fragment_conf {
	struct fragment_rx_queue rxqueue;
	struct fragment_mbuf_table tx_mbuf;
};

#define	MAX_FLOW_NUM	UINT16_MAX
#define	MIN_FLOW_NUM	1
#define	DEF_FLOW_NUM	0x1000

/* TTL numbers are in ms. */
#define	MAX_FLOW_TTL	(3600 * MS_PER_S)
#define	MIN_FLOW_TTL	1
#define	DEF_FLOW_TTL	MS_PER_S

/* Should be power of two. */
#define	IP_FRAG_TBL_BUCKET_ENTRIES	16

struct ip_reassemble_conf {
	struct 	rte_ip_frag_death_row death_row;
};

#endif
