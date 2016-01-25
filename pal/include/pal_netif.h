#ifndef _PAL_NETIF_H_
#define _PAL_NETIF_H_
#include "pal_skb.h"
#include "pal_conf.h"
#include <rte_ethdev.h>

struct pal_port_hw_stats {
	uint64_t ipackets;  /**< Total number of successfully received packets. */
	uint64_t opackets;  /**< Total number of successfully transmitted packets.*/
	uint64_t ibytes;    /**< Total number of successfully received bytes. */
	uint64_t obytes;    /**< Total number of successfully transmitted bytes. */
	uint64_t ierrors;   /**< Total number of erroneous received packets. */
	uint64_t oerrors;   /**< Total number of failed transmitted packets. */
	uint64_t imcasts;   /**< Total number of multicast received packets. */
	uint64_t rx_nombuf; /**< Total number of RX mbuf allocation failures. */
	uint64_t fdirmatch; /**< Total number of RX packets matching a filter. */
	uint64_t fdirmiss;  /**< Total number of RX packets not matching any filter. */
	uint64_t q_ipackets[PAL_MAX_THREAD];
	/**< Total number of queue RX packets. */
	uint64_t q_opackets[PAL_MAX_THREAD];
	/**< Total number of queue TX packets. */
	uint64_t q_ibytes[PAL_MAX_THREAD];
	/**< Total number of successfully received queue bytes. */
	uint64_t q_obytes[PAL_MAX_THREAD];
	/**< Total number of successfully transmitted queue bytes. */
	uint64_t q_errors[PAL_MAX_THREAD];
};

/* transmit a packet. this pointer may point to pal_send_raw_pkt or
 * pal_send_pkt_arp
 * note: Data pointer must point to ip header before calling this function */
extern int (* pal_send_pkt)(struct sk_buff *skb, unsigned port_id);

/*
 * @brief Transmit a packet from a specified port
 * @param port_id Port used to transmit the packet
 * @param skb The packet to be sent
 * @param txq_id The id of tx queue to be used for transmit
 * @return 0 on success, -1 on failure
 * @note For logical ports, caller must use the same queue id as the cresponding
 *       physical port.
 */
extern int pal_send_raw_pkt(struct sk_buff *skb,
                            unsigned port_id);


extern int pal_send_batch_pkt(struct sk_buff *skb, unsigned port_id);
extern void pal_flush_port(void);

/*
 * @brief Test whether a port is enabled
 * @return 0 if this port is not enabled, 1 otherwise
 * @note Caller must make sure that port_id falls between [0, PAL_MAX_PORT],
 *       or there may be a segmentation fault.
 */
static inline int pal_port_enabled(int port_id)
{
	return g_pal_config.port[port_id] != NULL;
}

/*
 * @brief Get the total number of physical ports in the entire system
 * @return Number of pysical ports
 */
static inline int pal_phys_port_count(void)
{
	return g_pal_config.sys.n_physport;
}

/*
 * @brief Get the total number of ports in the entire system
 * @return Number of ports, including physical ones and logical ones
 */
static inline int pal_port_count(void)
{
	return g_pal_config.sys.n_port;
}

/*
 * @brief Return the configuration structure of a port
 * @return A pointer to the configuration structure, or NULL if port not enabled.
 * @note Caller must make sure that port_id falls between [0, PAL_MAX_PORT],
 *       or there may be a segmentation fault.
 */
static inline struct port_conf *pal_port_conf(int port_id)
{
	return g_pal_config.port[port_id];
}

/*
 * @brief Return the numa id of a port
 * @return Numa id of this port
 * @note Caller must make sure that port_id falls between [0, PAL_MAX_PORT],
 *       or there may be a segmentation fault.
 */
static inline int pal_port_numa(int port_id)
{
	return g_pal_config.port[port_id]->numa;
}

/*
 * @brief Get hardware nic statistics
 */
extern void pal_port_get_stats(int port_id, struct pal_port_hw_stats *stats);

#endif
