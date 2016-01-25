#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
//#include <arpa/inet.h>
#include <rte_kni.h>
#include <rte_ethdev.h>
#include <rte_eth_bond.h>
#include <rte_ether.h>

#include "pal_vxlan.h"
#include "pal_error.h"
#include "vtep.h"
#include "pal_ip_cell.h"
#include "pal_netif.h"

struct vtep_dev nn_vtep;

struct nn_gateway_dev nn_gateway;

extern int ip_fragment_send(struct sk_buff *skb);
/*
* when we transmit  a vxlan packet, we append vxlan head, udp head,
* ip head, eth head  to the position of 'skb->data' in proper sequence.
* and then  set hardware offload and transmit  it using dpdk api..
*/
static int __bvrouter vtep_send(struct sk_buff *skb, struct vxlan_dev *vdev,
				  struct vxlan_rdst *rdst,__be16 src_port)
{
	struct ip_hdr *iph;
	struct ip_hdr *oip;
	struct vxlanhdr *vxh;
	struct udp_hdr *uh;
	struct eth_hdr *eth;
	__be32 dst;
	__be16 dst_port;
    uint32_t vni;
	uint16_t	id;
	uint8_t tos, ttl;
    int ret = 0;

	dst_port = rdst->remote_port ? rdst->remote_port : vdev->dst_port;
	vni = rdst->remote_vni;
	dst = rdst->remote_ip;
	ttl = vdev->ttl;
	tos = vdev->tos;

	oip = skb_ip_header(skb);
	id = oip->id;

	/*set vxlan header*/
	vxh = (struct vxlanhdr *) skb_push(skb, sizeof(*vxh));
	vxh->vx_flags = pal_htonl(VXLAN_FLAGS);
	vxh->vx_vni = pal_htonl(vni << 8);

	/*set udp header, and no udp checksum*/
	skb_push(skb, sizeof(*uh));
	skb_reset_l4_header(skb);
	uh = skb_udp_header(skb);
	uh->dest = dst_port;
	uh->source = src_port;
	uh->len= pal_htons(skb_pkt_len(skb));
	uh->check= 0;

	/*set ip header, and soft ip checksum*/
	skb_push(skb, sizeof(*iph));
	skb_reset_network_header(skb);
	iph	= skb_ip_header(skb);
	iph->version	= 4;
	iph->ihl	= sizeof(struct ip_hdr) >> 2;
	iph->protocol	= PAL_IPPROTO_UDP;
	iph->tos	= tos;
	iph->daddr	= dst;
	iph->saddr	= get_vtep_ip();
	iph->ttl	= ttl;
	iph->tot_len  = pal_htons(skb_pkt_len(skb));
	iph->frag_off = pal_htons(0x0000);	//set DF=0 and MF=0
	iph->id = id;

	/* if we don't need to do any fragmentation */
	if (likely (IPV4_MTU_DEFAULT >= skb_pkt_len(skb))) {
		/*set hardware checksum*/
		skb_ip_csum_offload(skb,20);

		/*set eth header*/
		skb_push(skb, sizeof(*eth));
		skb_reset_eth_header(skb);
		eth	= skb_eth_header(skb);
		eth->type = pal_htons(PAL_ETH_IP);
		mac_copy(eth->dst, get_nn_gw_mac());
		mac_copy(eth->src, get_vtep_mac());

		if((ret = pal_send_batch_pkt(skb, skb->recv_if)) == 0){
			return 0;
		}else
			goto tx_error;
	} else {
		/*need fragmentation*/
		return ip_fragment_send(skb);
	}

tx_error:
	return -EFAULT;
}

/*
 * @brief:reply the arp request from vm
 * @param: skb:arp request pkt dev: input device
 */
static int vxlan_arp_rcv(struct sk_buff *skb, struct vxlan_dev *dev)
{
    uint32_t i,dip,tmp;
	struct eth_hdr *ethh;
	struct arp_hdr *arph;
	struct int_vport *int_vport = NULL;
    struct pal_hlist_node *pos = NULL;
    struct vport *vport = NULL;

    /*vport must be a internal gateway,only reply the req for gw ip*/
   	ethh = skb_eth_header(skb);
    skb_pull(skb, sizeof(struct eth_hdr));
    if (!pskb_may_pull(skb, sizeof(struct arp_hdr))) {
        return -1;
    }

    skb_reset_network_header(skb);
   	arph = skb_arp_header(skb);
    if (arph->ar_op != pal_htons(PAL_ARPOP_REQUEST)) {
        PAL_LOG("not a arp request\n");
        return -1;
    }

    dip = arph->dst_ip;
    for (i = 0; i < INT_VPORT_HASH_SIZE; i++) {
        pal_hlist_for_each_entry(int_vport, pos, &dev->int_vport_head[i], hlist)
        {
            if (dip == int_vport->vp.vport_ip) {
                vport = &int_vport->vp;
                break;
            }
        }
    }

    if (!vport) {
        PAL_DEBUG("not request for a gw ip\n");
        return -1;
    }

    /*swap ip address*/
    tmp = arph->src_ip;
    arph->src_ip = arph->dst_ip;
    arph->dst_ip = tmp;

    /*copy the src mac into dst mac*/
    mac_copy(arph->dst_mac, arph->src_mac);
    mac_copy(ethh->dst, ethh->src);

    //change the arp op into ARPOP_REPLY
    arph->ar_op = pal_ntohs(PAL_ARPOP_REPLY);

    //copy the src mac with port's mac
    mac_copy(arph->src_mac, vport->vport_eth_addr);
    mac_copy(ethh->src, vport->vport_eth_addr);
    skb_push(skb, sizeof(struct eth_hdr));

    vport->vport_ops->send(skb, vport);

    return 0;
}

/*
* when we receive a vxlan pakcket, we strip it's udp and vxlan header,
* look up vni hash to find it belongs to which vxlan_vport.
*/
static int __bvrouter vtep_rcv(struct sk_buff  *skb_p){
	struct vxlanhdr *vxh;
	struct vxlan_dev *vdev;
	struct int_vport *vport;
	struct eth_hdr *eth;
	uint32_t vni;
	uint32_t index;

	/* pop off outer UDP header */
	skb_pull(skb_p, sizeof(struct udp_hdr));

	/* Need Vxlan and inner Ethernet header to be present */
	if (unlikely(!pskb_may_pull(skb_p, sizeof(struct vxlanhdr))))
		goto drop;

	/* Drop packets with reserved bits set */
	vxh = (struct vxlanhdr *) skb_data(skb_p);
	if (unlikely(vxh->vx_flags != pal_htonl(VXLAN_FLAGS) ||
	    (vxh->vx_vni & pal_htonl(0xff)))) {
		PAL_DEBUG("invalid vxlan flags=%#x vni=%#x\n",
			   pal_ntohl(vxh->vx_flags), pal_ntohl(vxh->vx_vni));
		goto drop;
	}

	skb_pull(skb_p, sizeof(struct vxlanhdr));
	vni = pal_ntohl(vxh->vx_vni) >> 8;

	/*1. find vxlan_dev*/
	index = get_hash_index_vni(vni);
	vdev = find_lock_vxlan_dev(vni,index);
	if (unlikely(!vdev)) {
		pal_cur_thread_conf()->stats.ip.unknown_dst++;
		PAL_DEBUG("unknown vni %d\n", vni);
		goto drop;
	}

	/*2. check eth header*/
	if (unlikely(!pskb_may_pull(skb_p, ETH_HLEN))) {
		read_unlock_vxlan_dev(index);
		goto drop;
	}
	skb_reset_eth_header(skb_p);
	eth = skb_eth_header(skb_p);

    /*3. for arp request, vxlan_dev used as arpproxy*/
    if (unlikely(eth->type == pal_htons(PAL_ETH_ARP))) {
        if (vxlan_arp_rcv(skb_p, vdev)){
			read_unlock_vxlan_dev(index);
            goto drop;
        }else{
			read_unlock_vxlan_dev(index);
            return 0;
        }
    }

    /*TODO what if a broadcast or multicast pkts?*/
	/*4. find int_vport*/
	vport = __find_int_vport_nolock(vdev,eth->dst);
	if (unlikely(!vport)) {
		read_unlock_vxlan_dev(index);
		goto drop;
	}

	vport->vp.vport_ops->recv(skb_p,(struct vport *)vport);

	return 0;

drop:
	pal_skb_free(skb_p);
	return -EFAULT;
}

static const struct vtep_device_ops vtep_ops = {
	.send	= vtep_send,
	.recv	= vtep_rcv,
};

int vtep_init(uint32_t vtep_ip,uint8_t *vtep_mac,uint32_t local_ip){

	if(!pal_is_valid_ether_addr(vtep_mac))
		PAL_PANIC("invalid vtep mac!\n");

	mac_copy(nn_vtep.nn_vtep_mac,vtep_mac);
	nn_vtep.nn_vtep_ip = vtep_ip;
    nn_vtep.nn_local_ip = local_ip;
	nn_vtep.vtep_vxlan_dst_port= pal_htons(VTEP_VXLAN_UDP_DST_PORT);
	nn_vtep.vtep_ops = &vtep_ops;

	return 0;
}

int __bvrouter rcv_int_network_pkt_process(struct sk_buff  *skb_p)
{
	return nn_vtep.vtep_ops->recv(skb_p);
}

int __bvrouter vtep_xmit_one(struct sk_buff *skb, struct vxlan_dev *vdev,
				  struct vxlan_rdst *rdst,__be16 src_port)
{
	return nn_vtep.vtep_ops->send(skb,vdev,rdst,src_port);
}
