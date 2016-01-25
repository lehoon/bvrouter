#ifndef _PAL_SKB_H_
#define _PAL_SKB_H_
#include <rte_mbuf.h>

#include "pal_cpu.h"
#include "pal_list.h"
#include "pal_byteorder.h"
#include "pal_pktdef.h"

/* max packet size. This does not include PAL_PKT_HEADROOM.*/
/* Note: in ixgbe_dev_rx_init, the default max packet size is 2048, because
 * RX buffer size in the BSIZEPACKET field of the SRRCTL register of the queue
 * is in 1 KB resolution, and valid values can be from 1 KB to 16 KB.
 * I guess if we receive a packet between 1600 and 2048, there may be a
 * segmentation fault.
 * So we MUST make sure that the MTU of switch is no more than 1500.
 * Note2: in an allocated skb, max pkt size is actually 1598, because we moved
 * the data pointer to make sure it's 4-byte aligned.
 */
#define PAL_MAX_PKT_SIZE	1600

struct sk_buff {
	/* mbuf MUST be the first member */
	struct rte_mbuf		mbuf;
	struct pal_list_head	list;

	/* Pointer to start of data.
	 * Note this is different from mbuf.buf_addr.
	 * head = (void *)skb + sizeof(*skb)
	 * mbuf.buf_addr = (void *)skb + sizeof(mbuf)
	 */
	void			*head;

	struct eth_hdr		*eth; /* ether header, or NULL if not set */

	union {
		struct ip_hdr	*iph;
		struct arp_hdr	*arph;
		void		*l3_hdr;
	}; /* ip/arp header, or NULL if not set */

	union {
		struct tcp_hdr	*tcph;
		struct udp_hdr	*udph;
		struct icmp_hdr	*icmph;
		void		*l4_hdr;
	}; /* tcp/udp/icmp header, or NULL if not set */

	void *private_data;

	unsigned	recv_if;
	unsigned	send_if;

	/* indicates whether this skb should be dumped before transmit */
	uint8_t		dump;
	uint8_t		snat_flag;
	uint8_t		dnat_flag;
	struct fib_result *res;
};


/* Every allocated skb has at least PAL_PKT_HEADROOM before data pointer */
#define PAL_PKT_HEADROOM	(int)(RTE_PKTMBUF_HEADROOM - \
                        (sizeof(struct sk_buff) - sizeof(struct rte_mbuf)))

/* size of an mbuf object. this is equal to
 * sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM + PAL_MAX_PKT_SIZE*/
#define MBUF_SIZE	\
	(PAL_MAX_PKT_SIZE + PAL_PKT_HEADROOM + sizeof(struct sk_buff))

/*
 * @brief Get the data pointer of the skb
 * @param skb Pointer to the skb
 * @return A pointer to the buffer of the skb
 */
static inline void *skb_data(const struct sk_buff *skb)
{
	return skb->mbuf.pkt.data;
}

/*
 * @brief Get the length of a specified packet. Starts from data pointer.
 */
static inline unsigned skb_len(const struct sk_buff *skb)
{
	return skb->mbuf.pkt.data_len;
}

/*
 * @brief Get the length of a specified packet. Starts from data pointer.
 */
static inline unsigned skb_pkt_len(const struct sk_buff *skb)
{
	return skb->mbuf.pkt.pkt_len;
}

static inline void *skb_l2_header(const struct sk_buff *skb);
static inline unsigned skb_l2_len(const struct sk_buff *skb)
{
	return skb->mbuf.pkt.data_len + 
		((unsigned long)skb_data(skb) - (unsigned long)skb_l2_header(skb));
}

/*
 * @brief Add space to the head of a buffer
 * @param skb Buffer to use
 * @param len Amount of space to add
 * @return A pointer to the first byte of new space
 * @note This function does not do sanity check
 */
static inline void *skb_push(struct sk_buff *skb, unsigned len)
{
	skb->mbuf.pkt.data = (void *)(((uint8_t *)skb->mbuf.pkt.data) - len);
	skb->mbuf.pkt.data_len += len;
	skb->mbuf.pkt.pkt_len += len;

	return skb->mbuf.pkt.data;
}

/*
 * @brief Remove space from the head of a buffer
 * @param skb Buffer to use
 * @param len Amount of space to remove
 * @return A pointer to the first byte of new space
 * @note This function does not do sanity check
 */
static inline void *skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->mbuf.pkt.data = (void *)(((uint8_t *)skb->mbuf.pkt.data) + len);
	skb->mbuf.pkt.data_len -= len;
	skb->mbuf.pkt.pkt_len -= len;

	return skb->mbuf.pkt.data;
}

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	if(likely(len <=  skb_len(skb))){
		return 1;
	}else{
		return 0;
	}
}

static inline int skb_cow_head(void)
{
	return 0;
}

/*
 * @brief Add space to the tail of a buffer
 * @param skb Buffer to use
 * @param len Amount of space to add
 * @return A pointer to the first byte of new space
 * @note This function does not do sanity check
 */
static inline void *skb_append(struct sk_buff *skb, unsigned int len)
{
	void *tail = (void *)((uint8_t *)skb->mbuf.pkt.data + skb->mbuf.pkt.data_len);

	skb->mbuf.pkt.data_len += len;
	skb->mbuf.pkt.pkt_len += len;

	return tail;
}

/*
 * @brief Remove space from the tail of a buffer
 * @param skb Buffer to use
 * @param len Amount of space to remove
 * @return A pointer to the first byte of the whole buffer
 * @note This function does not do sanity check
 */
static inline void *skb_adjust(struct sk_buff *skb, unsigned int len)
{
	skb->mbuf.pkt.data_len -= len;
	skb->mbuf.pkt.pkt_len -= len;

	return skb->mbuf.pkt.data;
}

static inline void skb_reset_network_header(struct sk_buff *skb)
{
	skb->l3_hdr = skb_data(skb);
}

static inline void skb_reset_eth_header(struct sk_buff *skb)
{
	skb->eth = (struct eth_hdr *)skb_data(skb);
}

static inline void skb_reset_l4_header(struct sk_buff *skb)
{
	skb->l4_hdr = (void *)skb_data(skb);
}


/*
 * @brief Get the ip header pointer of this packet.
 */
static inline struct ip_hdr *skb_ip_header(const struct sk_buff *skb)
{
	return skb->iph;
}

/*
 * @brief Free a skb structure.
 * @note Sent skbs are automatically freed by the driver.
 */
static inline void pal_skb_free(struct sk_buff *skb)
{
	rte_pktmbuf_free(&skb->mbuf);
}

/*
 * @brief Set the length of the packet. note that this does not change
 *        the data pointer
 */
static inline void skb_set_pkt_len(struct sk_buff *skb, unsigned len)
{
	skb->mbuf.pkt.data_len = len;
	skb->mbuf.pkt.pkt_len = len;
}

/*
 * @brief Get the ethernet header of this packet
 */
static inline struct eth_hdr *skb_eth_header(const struct sk_buff *skb)
{
	return skb->eth;
}

static inline void *skb_l2_header(const struct sk_buff *skb)
{
	return (void *)skb->eth;
}

/*
 * @brief Get the arp header of this packet.
 */
static inline struct arp_hdr *skb_arp_header(const struct sk_buff *skb)
{
	return skb->arph;
}


/*
 * @brief Get the layer 4 header pointer of this packet.
 */
static inline void *skb_l4_header(const struct sk_buff *skb)
{
	return skb->l4_hdr;
}

/*
 * @brief Get the tcp header pointer of this packet.
 */
static inline struct tcp_hdr *skb_tcp_header(const struct sk_buff *skb)
{
	return skb->tcph;
}

/*
 * @brief Get the udp header pointer of this packet.
 */
static inline struct udp_hdr *skb_udp_header(const struct sk_buff *skb)
{
	return skb->udph;
}

/*
 * @brief Get the icmp header pointer of this packet.
 */
static inline struct icmp_hdr *skb_icmp_header(const struct sk_buff *skb)
{
	return skb->icmph;
}

/*
 * @brief Check whether the ip and l4 checksum of skb is correct.
 *        This function only applies to skbs received from NIC,
 *        because it checks the checksum flag set by NIC
 * @param skb Skb to be checked
 * @return > 0 if ip and l4 checksum are both correct, 0 otherwise
 */
static inline unsigned skb_csum_ok(const struct sk_buff *skb)
{
	return !(skb->mbuf.ol_flags & (PKT_RX_IP_CKSUM_BAD |
	                               PKT_RX_L4_CKSUM_BAD));
}

/*
 * @brief Check whether the ip checksum of skb is correct.
 *        This function only applies to skbs received from NIC,
 *        because it checks the checksum flag set by NIC
 * @param skb Skb to be checked
 * @return > 0 if ip checksum is correct, 0 otherwise
 */
static inline unsigned skb_ip_csum_ok(const struct sk_buff *skb)
{
	return !(skb->mbuf.ol_flags & PKT_RX_IP_CKSUM_BAD);
}

/*
 * @brief Check whether the tcp/udp checksum of skb is correct.
 *        This function only applies to skbs received from NIC,
 *        because it checks the checksum flag set by NIC
 * @param skb Skb to be checked
 * @return > 0 if tcp/udp checksum is correct, 0 otherwise
 */
static inline unsigned skb_l4_csum_ok(const struct sk_buff *skb)
{
	return !(skb->mbuf.ol_flags & PKT_RX_L4_CKSUM_BAD);
}

/*
 * @brief Create a slab on the current numa to allocate skb
 * @param name Name of the slab, must unique across the system
 * @param n_skb Number of skbs this slab contain
 * @return Pointer to the slab, or NULL on failure
 * @note If multiple threads alloc skbs from the same skb slab, caller must
 *        use locks to avoid race condition. However, freeing skbs in multiple
 *        threads at the same time is OK.
 */
static inline struct pal_slab *pal_skb_slab_create_numa(const char *name,
				unsigned n_skb, int numa)
{
	struct rte_mempool *pool;

	/* no MEMPOOL_F_SP_PUT flag because it is very likely that multiple
	 * threads would free skbs from the same skb slab at the same time.
	 * For example, different workers may free skbs alloced by the same
	 * receiver at the same time. */
	pool = rte_mempool_create(name, n_skb, MBUF_SIZE, 0,
	                          sizeof(struct rte_pktmbuf_pool_private),
	                          rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,
	                          numa, MEMPOOL_F_SC_GET);

	return (struct pal_slab *)pool;
}

/*
 * @brief Create a slab on the current numa to allocate skb
 * @param name Name of the slab, must unique across the system
 * @param n_skb Number of skbs this slab contain
 * @return Pointer to the slab, or NULL on failure
 */
static inline struct pal_slab *pal_skb_slab_create(const char *name, unsigned n_skb)
{
	return pal_skb_slab_create_numa(name, n_skb, pal_numa_id());
}

/*
 * @brief Reset data pointer to its orignial place.
 *
 */
static inline void skb_init(struct sk_buff *skb)
{
	struct rte_mbuf *m;
	m = &skb->mbuf;

	m->pkt.next = NULL;
	m->pkt.pkt_len = 0;
	m->pkt.vlan_macip.data = 0;
	m->pkt.nb_segs = 1;
	m->pkt.in_port = 0xff;
    rte_mbuf_refcnt_set(m, 1);
	m->ol_flags = 0;
	/* buf_ofs = (RTE_PKTMBUF_HEADROOM <= m->buf_len) ?
			RTE_PKTMBUF_HEADROOM + 2 : m->buf_len; */
	skb->head = (char *)skb + sizeof(*skb);
	/* Add 2 bytes to make allocated skb 4-byte aligned, because by default,
	 * the RTE_PKTMBUF_HEADROOM is 2-byte aligned but not 4-byte aligned.
	 * This is to make ip headers of received packets 4-byte aligend.*/
	m->pkt.data = (char*) m->buf_addr + RTE_PKTMBUF_HEADROOM + 2;

	skb->eth = NULL;
	skb->l3_hdr = NULL;
	skb->l4_hdr = NULL;
	skb->private_data = NULL;

	m->pkt.data_len = 0;
}

static inline struct sk_buff *pal_skb_alloc(struct pal_slab *skb_slab)
{
	void *skb;

	if(rte_mempool_get((struct rte_mempool *)skb_slab, &skb) != 0)
		return NULL;

	skb_init((struct sk_buff *)skb);

	return (struct sk_buff *)skb;
}

static inline int print_pkt(const struct sk_buff *skb)
{
	unsigned i;
	const unsigned char *p;

	p = (const unsigned char *)skb->mbuf.pkt.data;
	for(i = 0; i < skb->mbuf.pkt.data_len; i++) {
		printf("%02x ", p[i]);
		if(((i + 1) & 15) == 0)
			printf("\n");
	}
	if((i & 15) != 0)
		printf("\n");

	printf("\n");

	return 0;
}

/*
 * note: pointer to eth/network/transport header are invalid after clone
 */
static inline struct sk_buff *skb_clone(const struct sk_buff *skb,
                                        struct pal_slab *slab, uint16_t size)
{
	struct rte_mbuf *m2;
	const struct rte_mbuf *m;
	struct sk_buff *skb2;

	skb2 = pal_skb_alloc(slab);
	if (skb2 == NULL)
		return NULL;

	m = &skb->mbuf;
	m2 = &skb2->mbuf;
	size = min(m->pkt.data_len, size);
	m2->pkt.next = NULL;
	m2->pkt.vlan_macip.data = m->pkt.vlan_macip.data;
	m2->pkt.nb_segs = 1;
	m2->pkt.in_port = m->pkt.in_port;
	m2->ol_flags = m->ol_flags;
	m2->pkt.data = (char *)m2->buf_addr + ((const char *)m->pkt.data - (const char *)m->buf_addr);
	/* we don't use SG IO, so pkt_len is equal to data_len */
	m2->pkt.pkt_len = size;
	m2->pkt.data_len = size;

	memcpy(m2->pkt.data, m->pkt.data, size);

	return skb2;
}


/* calculate pseudo header csum for l4 protocols.
 * note: sip, dip must be in network byteorder, len should be in host byteorder */
static inline uint16_t pal_cal_pseudo_csum(uint8_t proto,
			uint32_t sip, uint32_t dip, uint16_t len)
{
	uint32_t csum;

	csum = (sip & 0x0000ffffUL) + (sip >> 16);
	csum += (dip & 0x0000ffffUL) + (dip >> 16);

	csum += (uint16_t)proto << 8;
	csum += pal_htons(len);

	csum = (csum & 0x0000ffffUL) + (csum >> 16);
	csum = (csum & 0x0000ffffUL) + (csum >> 16);

	return (uint16_t)csum;
}

/* @brief Set ip checksum offload.
 *    For more information about checksum offload of Niantic, refer to
 *    datasheet 7.2.5 "Transmit Checksum Offloading in Nonsegmentation Mode"
 * @param skb Packet whose ip checksum is to be offloaded
 * @param iphdr_len Ip header length, including ip options, in host byteorder
 */
static inline void skb_ip_csum_offload(struct sk_buff *skb, uint16_t iphdr_len)
{
	skb->iph->check = 0;
	skb->mbuf.ol_flags |= PKT_TX_IP_CKSUM;

	skb->mbuf.pkt.vlan_macip.f.l2_len = sizeof(struct eth_hdr);
	skb->mbuf.pkt.vlan_macip.f.l3_len = iphdr_len;
}

/*
 * @breif Set tcp hardware checksum offload.
 * @param skb Packet whose checksum is to be offloaded
 * @param sip Source ip address of the packet, in network byteorder
 * @param dip Destination ip address, in network byteorder
 * @param tcp_len Tcp total lenth, including tcp header and body, in host byteorder
 * @param iphdr_len Ip header length, including ip options, in host byteorder
 * @note skb->tcph pointer must be set correctly before calling this function.
 */
static inline void skb_tcp_csum_offload(struct sk_buff *skb,
			uint32_t sip, uint32_t dip, uint16_t tcp_len, uint16_t iphdr_len)
{
	skb->tcph->check = pal_cal_pseudo_csum(PAL_IPPROTO_TCP, sip, dip, tcp_len);
	skb->mbuf.ol_flags &= ~(uint16_t)PKT_TX_L4_MASK;
	skb->mbuf.ol_flags |= PKT_TX_TCP_CKSUM;

	skb->mbuf.pkt.vlan_macip.f.l2_len = sizeof(struct eth_hdr);
	skb->mbuf.pkt.vlan_macip.f.l3_len = iphdr_len;
}

/*
 * @breif Set udp hardware checksum offload.
 * @param skb Packet whose checksum is to be offloaded
 * @param sip Source ip address of the packet, in network byteorder
 * @param dip Destination ip address, in network byteorder
 * @param udp_len Udp total lenth, including udp header and body, in host byteorder
 * @param iphdr_len Ip header length, including ip options, in host byteorder
 * @note skb->udph pointer must be set correctly before calling this function.
 */
static inline void skb_udp_csum_offload(struct sk_buff *skb,
			uint32_t sip, uint32_t dip, uint16_t udp_len, uint16_t iphdr_len)
{
	skb->udph->check = pal_cal_pseudo_csum(PAL_IPPROTO_UDP, sip, dip, udp_len);
	skb->mbuf.ol_flags &= ~(uint16_t)PKT_TX_L4_MASK;
	skb->mbuf.ol_flags |= PKT_TX_UDP_CKSUM;

	skb->mbuf.pkt.vlan_macip.f.l2_len = sizeof(struct eth_hdr);
	skb->mbuf.pkt.vlan_macip.f.l3_len = iphdr_len;
}

/*
 * @breif Set ip and tcp hardware checksum offload.
 * @param skb Packet whose checksum is to be offloaded
 * @param sip Source ip address of the packet, in network byteorder
 * @param dip Destination ip address, in network byteorder
 * @param tcp_len Tcp total lenth, including tcp header and body, in host byteorder
 * @param iphdr_len Ip header length, including ip options, in host byteorder
 * @note skb->tcph pointer must be set correctly before calling this function.
 */
static inline void skb_iptcp_csum_offload(struct sk_buff *skb,
			uint32_t sip, uint32_t dip, uint16_t tcp_len, uint16_t iphdr_len)
{
	skb->tcph->check = pal_cal_pseudo_csum(PAL_IPPROTO_TCP, sip, dip, tcp_len);
	skb->iph->check = 0;
	skb->mbuf.ol_flags &= ~(uint16_t)PKT_TX_L4_MASK;
	skb->mbuf.ol_flags |= (PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM);

	skb->mbuf.pkt.vlan_macip.f.l2_len = sizeof(struct eth_hdr);
	skb->mbuf.pkt.vlan_macip.f.l3_len = iphdr_len;
}

/*
 * @breif Set ip and udp hardware checksum offload.
 * @param skb Packet whose checksum is to be offloaded
 * @param sip Source ip address of the packet, in network byteorder
 * @param dip Destination ip address, in network byteorder
 * @param udp_len Udp total lenth, including udp header and body, in host byteorder
 * @param iphdr_len Ip header length, including ip options, in host byteorder
 * @note skb->udph pointer must be set correctly before calling this function.
 */
static inline void skb_ipudp_csum_offload(struct sk_buff *skb,
			uint32_t sip, uint32_t dip, uint16_t udp_len, uint16_t iphdr_len)
{
	skb->udph->check = pal_cal_pseudo_csum(PAL_IPPROTO_UDP, sip, dip, udp_len);
	skb->iph->check = 0;
	skb->mbuf.ol_flags &= ~(uint16_t)PKT_TX_L4_MASK;
	skb->mbuf.ol_flags |= (PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM);

	skb->mbuf.pkt.vlan_macip.f.l2_len = sizeof(struct eth_hdr);
	skb->mbuf.pkt.vlan_macip.f.l3_len = iphdr_len;
}

static inline void skb_set_dump(struct sk_buff *skb)
{
	skb->dump = 1;
}

#endif
