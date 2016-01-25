/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file         $HeadURL: $
* @brief        ipv4 pkt process
* @author       zhangyu(zhangyu09@baidu.com)
* @date         $Date:$
* @version      $Id: $
***********************************************************************
*/

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bvr_namespace.h"
#include "pal_vport.h"
#include "pal_skb.h"
#include "pal_pktdef.h"
#include "pal_route.h"
#include "pal_byteorder.h"
#include "pal_utils.h"
#include "bvr_arp.h"
#include "bvr_ipv4.h"
#include "bvr_netfilter.h"
#include "logger.h"
//#include "logger.h"

/** @brief Swap some bytes and avoid unaligned r/w
 *  @param pa  A pointer of address to be swapped
 *  @param pb  Another pointer of address to be swapped
 *  @param num  Bytes number to be swapped
 */
static inline void swap_n_bytes(u8 *pa, u8 *pb, int num)
{
	u8 tmp;
	int i;

	for (i = 0; i < num; i++){
		tmp = pa[i];
		pa[i] = pb[i];
		pb[i] = tmp;
	}

	return;
}

/*
 * @brief Swap dest mac and src mac and take care of unaligned r/w
 * @param l2_header Pointer of l2 header
 */
static inline void swap_mac(u8 *l2_header)
{
	if (((u64)l2_header & 0x01UL) == 0) {

		u16 *p = (u16 *)l2_header;
		u16 tmp;

		tmp = *p;
		*p = *(p + 3);
		*(p + 3) = tmp;

		p++;

		tmp = *p;
		*p = *(p + 3);
		*(p + 3) = tmp;

		p++;

		tmp = *p;
		*p = *(p + 3);
		*(p + 3) = tmp;

		return;
	} else {
		swap_n_bytes(l2_header, l2_header + 6, 6);
		return;
	}
}


static inline int is_phy_port(struct vport *vp) {
    return (vp->vport_type == PHY_VPORT);
}

static int icmp_reply(struct sk_buff *skb)
{
	struct ip_hdr *iph = (struct ip_hdr *)skb_ip_header(skb);
	struct icmp_hdr *icmph = skb_icmp_header(skb);
	unsigned icmp_len = htons(iph->tot_len) - (iph->ihl * 4);
	u8 *l2_dest_mac_p = skb_eth_header(skb)->dst;
	u32 tmp_addr;

	BVR_DEBUG("in icmp handler\n");
	/* icmp content must be more then 8 bytes */
	if (icmp_len >= 8 && icmp_len <= skb_len(skb)) {
		/* we only handle icmp echo request */
		if (icmph->type == ICMP_ECHO) {
			if (icmp_check_sum_correct((u16 *)icmph, icmp_len)) {
				icmph->type = ICMP_ECHOREPLY;

				/* update icmp check sum*/
				icmph->checksum = icmph->checksum + htons(0x0800);

				/* Exchange ip addresses */
				tmp_addr = iph->saddr;
				iph->saddr = iph->daddr;
				iph->daddr = tmp_addr;

				/*update ip ttl*/
				iph->ttl = 64;
                iph->check = ip_fast_csum((u16 *)iph, iph->ihl * 4);
				swap_mac(l2_dest_mac_p);

				BVR_DEBUG("send icmp reply \n");
                return 0;

			} else {

				BVR_DEBUG("Bad icmp checksum\n");
			}
		} else {
			BVR_DEBUG("icmp not echo request!\n");
		}
	} else {
		BVR_DEBUG("icmp len < 8 len %d, invalid\n", icmp_len);
	}

	return -1;
}


static int ip_output_finish(struct sk_buff *skb, __unused struct vport *in, struct vport *out)
{
    if (out == NULL) {
        BVR_WARNING("fatal error ip_output out NULL\n");
        return NF_DROP;
    }
    struct net *net = dev_net(out);
    struct ip_hdr *iph = skb_ip_header(skb);
    int lcore_id = rte_lcore_id();

    net->stats[lcore_id].output_pkts++;
    net->stats[lcore_id].output_bytes += skb_len(skb);

    skb_push(skb, (iph->ihl << 2) + sizeof(struct eth_hdr));
    out->vport_ops->send(skb, out);
    return NF_ACCEPT;
}

/*
 * @brief ip output lookup route table and arp table,
 * process icmp pkt for local ip
 */
static int ip_output(struct sk_buff *skb, struct vport *in, __unused struct vport *out)
{
    struct eth_hdr *ethh = skb_eth_header(skb);
    struct ip_hdr *iph = skb_ip_header(skb);
    if (in == NULL) {
        BVR_WARNING("fata error ip_output in NULL\n");
        return NF_DROP;
    }
    struct net *net = dev_net(in);
    struct fib_result res;
    // struct arp_entry *entry;
    int lcore_id = rte_lcore_id();
    if (net->route_table == NULL) {
    /*route table NULL? some one may deleting this bvr*/
        return NF_DROP;
    }
    int err = pal_route_lookup(net->route_table, iph->daddr, &res);
    if(err) {
        /*why error?*/
        net->stats[lcore_id].rterror_pkts++;
        net->stats[lcore_id].rterror_bytes += skb_len(skb);
        goto drop;
    }
    /*if route type local, should process pkt on your own*/
    if (res.route_type == PAL_ROUTE_LOCAL) {
        if (iph->protocol == PAL_IPPROTO_ICMP) {
            /*only process icmp ping for local ip*/
            if (icmp_reply(skb)) {
                goto drop;
            } else {
                /*skip the postrouting for snat*/
                return ip_output_finish(skb, in, res.port_dev);
            }

        }else {
            /*except icmp, drop all*/
            goto drop;
        }
    }
    /* If route to qr has nexthop, change dst_mac to nexthop */
    if (!is_phy_port((struct vport *)res.port_dev)
            && res.next_hop != 0
            && res.next_hop != res.sip) {
        if (unlikely(locate_eth_dst(res.port_dev, res.next_hop, ethh->dst) < 0)) {
            net->stats[lcore_id].rterror_pkts++;
            net->stats[lcore_id].rterror_bytes += skb_len(skb);
            goto drop;
        }
    }
    /*offload the arp procesee to vport*/
    #if 0
    else {
        /*pkts to forward, lookup arp table first*/
        if (0 == res.next_hop) {
            /*connected route, use daddr mac*/
            entry = find_arp_entry(net, iph->daddr);

            if (entry == NULL) {
                net->stats[lcore_id].arperror_pkts++;
                net->stats[lcore_id].arperror_bytes += skb_len(skb);
                goto drop;
            }
            /*change mac*/
            struct eth_hdr *ehdr = skb_eth_header(skb);
            mac_copy(ehdr->dst, entry->mac_addr);
            /*change source mac to output vport mac*/
            mac_copy(ehdr->src, ((struct vport *)res.port_dev)->vport_eth_addr);
        }
        /*if route type is not connected, next_hop not zero but gw ip,
          we do not lookup gw mac in arp table and change smac and dmac ,
          phy vport will change smac and dmac for us*/

    }
    #endif
    return nf_hook_iterate(NFPROTO_IPV4, NF_POSTROUTING, skb, in,
        res.port_dev, ip_output_finish);

drop:
    return NF_DROP;
}



static int ip_forward(struct sk_buff *skb, struct vport *in, struct vport *out)
{
    /*only get through the filter rules,  after that lookup route and arp table.
     *the order is ip_rcv-->PREROUTING-->ip_forwaord-->FORWARDING-->ip_output
     *-->lookup_routetable-->lookup_arptable-->POSTROUTING-->ip_output_finish
     *so pkts which should be filtered won't lookup route table and arp table.
     */
    return nf_hook_iterate(NFPROTO_IPV4, NF_FORWARDING, skb, in,
        out, ip_output);
   // return ip_forward(skb, dev);
}



static int ip_rcv(struct sk_buff *skb, struct vport *dev)
{
    struct ip_hdr *iph;
    struct net *net;
    u32 len = 0;
    int lcore_id = rte_lcore_id();

    net = dev_net(dev);

    if (unlikely(net == NULL)) {
        return NF_DROP;
    }

    /*make sure we can access field in ip header*/
    if (!pskb_may_pull(skb, sizeof(struct ip_hdr)))
    {
        goto hdr_error;
    }

    iph = skb_ip_header(skb);

    /*
     *  RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
     *
     *  Is the datagram acceptable?
     *
     *  1.  Length at least the size of an ip header
     *  2.  Version of 4
     *  3.  Checksums correctly. [Speed optimisation for later, skip loopback checksums]
     *  4.  Doesn't have a bogus length
     */
    if (iph->ihl < 5 || iph->version != 4) {
        goto hdr_error;
    }

    if (!pskb_may_pull(skb, iph->ihl * 4)) {
        goto hdr_error;
    }
    len = ntohs(iph->tot_len);

    /*don't test ip len,cause if ip fragment in vxlan level, the inner ip
     lengh maybe longer than skb len.*/

    if (len < (u32)(iph->ihl << 2)) {
        goto hdr_error;
    }

    /*pull the ip header and set eth l4 header (useful for filter)*/
    skb_pull(skb, ((iph->ihl) << 2));
    skb_reset_l4_header(skb);

    /*maybe we don't care the inner csum results*/
    /*maybe, just maybe but we still need to check, because we do NAT and
      update csum, what if we change the wrong csum to right? so if ip csum
      error we drop it as soon as possible. If csum test make perf bad, consider
      to remove it.*/
     /*test by testcenter this ipcsum check did not effect perf a lot
        (210wpps - 211wpps)*/

    if ((iph->check != 0) && (iph->check != ip_fast_csum((u16 *)iph, (iph->ihl << 2)))) {
        BVR_WARNING("ip csum check error\n");
        goto hdr_error;
    }
    net->stats[lcore_id].input_pkts++;
    net->stats[lcore_id].input_bytes += skb_len(skb);
    return nf_hook_iterate(NFPROTO_IPV4, NF_PREROUTING, skb, dev,
        NULL, ip_forward);

hdr_error:
    net->stats[lcore_id].hdrerror_pkts++;
    net->stats[lcore_id].hdrerror_bytes += skb_len(skb);
    return NF_DROP;

}

/*
 * @brief entry for bvrouter pkt process,
 * return NF_DROP or NF_ACCEPT, if NF_DROP return, caller should release skb
 */
int bvr_pkt_handler(struct sk_buff *skb, struct vport *dev)
{
    /*mbuf.data should point to ether header*/
    skb_reset_eth_header(skb);
    struct eth_hdr *eth = skb_eth_header(skb);

    if(unlikely(skb_len(skb) < sizeof(struct eth_hdr))) {
        return NF_DROP;
    }
    /*move mbuf.data to l3 header */
    skb_pull(skb, sizeof(struct eth_hdr));
    skb_reset_network_header(skb);

    switch(eth->type) {
        case pal_htons_constant(PAL_ETH_ARP):
            /*arp proxy implement in vxlan_dev, never a arp req come here*/
            return arp_rcv(skb, dev);
        case pal_htons_constant(PAL_ETH_IP):

            if ((eth->dst[0] & 0x1) == 0) {
                return ip_rcv(skb, dev);
            }else {
                /*drop multicast/broadcast pkts*/
                return NF_DROP;
            }

        default:
            return NF_DROP;
    }
    return NF_DROP;
}


#if 0
struct packet_type ip_type = {
    .type = rte_cpu_to_be16(ETH_P_IP),
    .func = ip_rcv,
};
#endif

