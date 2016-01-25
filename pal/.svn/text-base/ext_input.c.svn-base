#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "pal_phy_vport.h"
#include "pal_ip_cell.h"
#include "pal_error.h"
#include "vtep.h"
#include "pal_netif.h"

/*
*  vtep icmp process.
*/
static int rcv_vtep_icmp_process(struct sk_buff *skb)
{
	struct ip_hdr *iph = (struct ip_hdr *)skb_ip_header(skb);
	struct icmp_hdr *icmph = skb_icmp_header(skb);
	unsigned icmp_len = pal_htons(iph->tot_len) - (iph->ihl * 4);
	uint8_t *l2_dest_mac_p = skb_eth_header(skb)->dst;
	uint32_t tmp_addr;
	
	/* icmp content must be more then 8 bytes */
	if((icmp_len < 8 )|| (icmp_len > skb_len(skb)))
		goto drop;

	/* we only handle icmp echo request */
	if (icmph->type != ICMP_ECHO)
		goto drop;

	if (!icmp_check_sum_correct((uint16_t *)icmph, icmp_len))
		goto drop;

	icmph->type = ICMP_ECHOREPLY;
	/* update icmp check sum*/
	icmph->checksum = icmph->checksum + pal_htons_constant(0x0800);
	/* Exchange ip addresses */
	tmp_addr = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = tmp_addr;
	/**update ip ttl*/
	iph->ttl = 64;
	
	skb_ip_csum_offload(skb, iph->ihl * 4);
	
	pal_swap_mac(l2_dest_mac_p);
	
	skb_push(skb, (unsigned long)skb_l4_header(skb) - 
				  (unsigned long)skb_l2_header(skb));
	
	pal_cur_thread_conf()->stats.ip.icmp.reply_pkts++;
	
	if(pal_send_raw_pkt(skb,skb->recv_if)==0) 
		return 0;
	
	pal_cur_thread_conf()->stats.ip.icmp.reply_failure++;
	
drop:
	/* drop skbuff and rte_mbuf*/
	pal_skb_free(skb);
	return -EFAULT;
}

/*
* packet to vtep dev.
*/
static int rcv_vtep_pkt_process(struct sk_buff *skb,struct ip_hdr *iph)
{
	/*only process icmp protocl*/
	if(iph->protocol == PAL_IPPROTO_ICMP){
		pal_cur_thread_conf()->stats.ip.icmp.rx_pkts++;
		pal_cur_thread_conf()->stats.ip.icmp.rx_bytes += skb_l2_len(skb);
		rcv_vtep_icmp_process(skb);
	}else
		goto drop;

	return 0;

drop:	
	pal_cur_thread_conf()->stats.ip.unknown_dst++;
	pal_skb_free(skb);
	return -EFAULT;
}

/*
*  First serarch ip_cell by dst_ip. then acquire phy_vport pointer 
*  and  deleiver packet to this port.
*/
 static int __bvrouter rcv_ext_pkt_process(struct sk_buff  *skb,struct ip_hdr *iph)
{
	struct phy_vport *vport;	
	__be32 dst_ip;

	dst_ip = iph->daddr;	
	
	vport = find_get_phy_vport(dst_ip);
	if (unlikely(!vport)) {
		/*if it's a vtep_ip packet*/
		if(is_vtep_ip(dst_ip)){
			return rcv_vtep_pkt_process(skb,iph);
		}else
			goto drop;
	}
	
	vport->vp.vport_ops->recv(skb,(struct vport *)vport);
	
	return 0;
	
drop:	
	pal_cur_thread_conf()->stats.ip.unknown_dst++;
	/* drop skbuff and rte_mbuf*/
	pal_skb_free(skb);
	return -EFAULT;
}

/*
* receive from extern network, so this may be a vtep packet
* or floting ip packet , even illegal packet.
*/
int __bvrouter rcv_ext_network_pkt_process(struct sk_buff  *skb)
{
	return rcv_ext_pkt_process(skb,skb_ip_header(skb));
}

