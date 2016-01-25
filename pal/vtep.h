#ifndef _PAL_VTEP_H
#define _PAL_VTEP_H

#include <stdint.h>

#include "pal_vxlan.h"

#define	IPV4_MTU_DEFAULT	ETHER_MTU

extern struct vtep_dev nn_vtep;

struct vtep_dev {
	__be32 		nn_vtep_ip;
    __be32 		nn_local_ip;
	uint8_t  	nn_vtep_mac[6];

	__be16 	vtep_vxlan_dst_port;

	const struct vtep_device_ops *vtep_ops;
}__rte_cache_aligned ;

struct vtep_device_ops {
	int			(*send)(struct sk_buff *skb, struct vxlan_dev *vdev,
				  struct vxlan_rdst *rdst,__be16 src_port);
	int			(*recv)(struct sk_buff *skb);
};

static inline int is_vtep_ip(__be32 dst_ip)
{
	return (dst_ip == nn_vtep.nn_vtep_ip);
}

static inline int is_vtep_port(uint16_t port)
{
	return (port == nn_vtep.vtep_vxlan_dst_port);
}

static inline __be32 get_vtep_ip(void)
{
	return nn_vtep.nn_vtep_ip;
}

static inline uint8_t *get_vtep_mac(void)
{
	return nn_vtep.nn_vtep_mac;
}

static inline int is_local_ip(__be32 dst_ip)
{
	return (dst_ip == nn_vtep.nn_local_ip);
}

static inline __be32 get_local_ip(void)
{
	return nn_vtep.nn_local_ip;
}



static inline int is_vxlan_packet(struct ip_hdr  * iphdr,struct udp_hdr * udphdr)
{
	if(is_vtep_ip(iphdr->daddr) && is_vtep_port(udphdr->dest))
			return IS_VXLAN;

	return NO_VXLAN;
}

struct nn_gateway_dev {
	__be32 		nn_gw_ipv4_addr;
	uint8_t 	nn_gw_mac[6];
}__rte_cache_aligned ;

extern struct nn_gateway_dev nn_gateway;

static inline __be32 get_nn_gw_ip(void)
{
	return nn_gateway.nn_gw_ipv4_addr;
}

static inline void set_nn_gw_ip(__be32 gw_ip)
{
	nn_gateway.nn_gw_ipv4_addr = gw_ip;
}

static inline uint8_t *get_nn_gw_mac(void)
{
	return nn_gateway.nn_gw_mac;
}

#define  ETH_ALEN  6 /* Octets in one ethernet addr */
#define  VTEP_SRC_PORT_MIN  1024
#define  VTEP_SRC_PORT_MAX  6000
#define  VTEP_SRC_PORT_RANGE ((VTEP_SRC_PORT_MAX - VTEP_SRC_PORT_MIN) + 1)

static inline __be16 vtep_src_port(__be32 dip)
{
    return pal_htons((pal_hash32(dip) % VTEP_SRC_PORT_RANGE) + VTEP_SRC_PORT_MIN);
}

extern int vtep_init(uint32_t vtep_ip,uint8_t *vtep_mac, uint32_t local_ip);
extern int rcv_int_network_pkt_process(struct sk_buff  *skb_p);
extern int vtep_xmit_one(struct sk_buff *skb, struct vxlan_dev *vdev,
				  struct vxlan_rdst *rdst,__be16 src_port);
#endif

