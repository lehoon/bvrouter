#include "ip.h"
#include "skb.h"
#include "ipgroup.h"
#include "utils.h"
#include "pktdef.h"
#include "netif.h"
#include "vnic.h"

/** @brief Swap some bytes and avoid unaligned r/w
 *  @param pa  A pointer of address to be swapped
 *  @param pb  Another pointer of address to be swapped
 *  @param num  Bytes number to be swapped
 */
static inline void swap_n_bytes(uint8_t *pa, uint8_t *pb, int num)
{
	uint8_t tmp;
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
static inline void swap_mac(uint8_t *l2_header)
{
	if (((uint64_t)l2_header & 0x01UL) == 0) {

		uint16_t *p = (uint16_t *)l2_header;
		uint16_t tmp;

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

static int icmp_handler(struct sk_buff *skb)
{
	struct ip_hdr *iph = (struct ip_hdr *)skb_ip_header(skb);
	struct icmp_hdr *icmph = skb_icmp_header(skb);
	unsigned icmp_len = pal_htons(iph->tot_len) - (iph->ihl * 4);
	uint8_t *l2_dest_mac_p = skb_eth_header(skb)->dst;
	uint32_t tmp_addr;

	pal_cur_thread_conf()->stats.ip.icmp.rx_pkts++;
	pal_cur_thread_conf()->stats.ip.icmp.rx_bytes += skb_l2_len(skb);

	PAL_DEBUG("in icmp handler\n");
	/* icmp content must be more then 8 bytes */
	if (icmp_len >= 8 && icmp_len <= skb_len(skb)) {
		/* we only handle icmp echo request */
		if (icmph->type == ICMP_ECHO) {
			if (icmp_check_sum_correct((uint16_t *)icmph, icmp_len)) {
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

				swap_mac(l2_dest_mac_p);

				skb_push(skb, (unsigned long)skb_l4_header(skb) -
				              (unsigned long)skb_l2_header(skb));
				pal_cur_thread_conf()->stats.ip.icmp.reply_pkts++;
				if (pal_send_raw_pkt(skb, skb->recv_if) == 0) {
					PAL_DEBUG("sent icmp reply\n");
					return 0;
				}

				pal_cur_thread_conf()->stats.ip.icmp.reply_failure++;
				PAL_DEBUG("send icmp reply failed\n");

			} else {
				pal_cur_thread_conf()->stats.ip.icmp.csum_err++;
				PAL_DEBUG("Bad icmp checksum\n");
			}
		} else {
			pal_cur_thread_conf()->stats.ip.icmp.not_echo_pkts++;
			pal_cur_thread_conf()->stats.ip.icmp.not_echo_bytes += skb_l2_len(skb);
			PAL_DEBUG("icmp not echo request!\n");
		}
	} else {
		pal_cur_thread_conf()->stats.ip.icmp.trunc_pkts++;
		PAL_DEBUG("icmp len < 8, invalid\n");
	}

	return -1;
}

static int tcp_dispatch(struct sk_buff *skb, const struct pal_dip *dip)
{
	struct tcp_hdr *tcph = skb_tcp_header(skb);

	pal_cur_thread_conf()->stats.ip.tcp.rx_pkts++;
	pal_cur_thread_conf()->stats.ip.tcp.rx_bytes += skb_l2_len(skb);

	if (!skb_l4_csum_ok(skb)) {
		pal_cur_thread_conf()->stats.ip.tcp.csum_err++;
		PAL_DEBUG("TCP check sum error\n");
		return -1;
	}

	if (skb_len(skb) < (unsigned)tcph->doff * 4) {
		pal_cur_thread_conf()->stats.ip.tcp.trunc_pkts++;
		PAL_DEBUG("error: skb len < doff * 4\n");
		return -1;
	}

	if (dispatch_pkt(skb, dip) == 0)
		/* DO NOT free. Already sent to worker */
		return 0;

	return -1;
}

static int udp_dispatch(struct sk_buff *skb, const struct pal_dip *dip)
{
	pal_cur_thread_conf()->stats.ip.udp.rx_pkts++;
	pal_cur_thread_conf()->stats.ip.udp.rx_bytes += skb_l2_len(skb);

	if (!skb_l4_csum_ok(skb)) {
		pal_cur_thread_conf()->stats.ip.udp.csum_err++;
		PAL_DEBUG("UDP check sum error\n");
		return -1;
	}

	if (skb_len(skb) < 8) {
		pal_cur_thread_conf()->stats.ip.udp.trunc_pkts++;
		PAL_DEBUG("error: skb len < udp header length\n");
		return -1;
	}

	if (dispatch_pkt(skb, dip) == 0) {
		/* DO NOT free. Already sent to worker */
		return 0;
	}

	return -1;
}

static int icmp_dispatch(struct sk_buff *skb, const struct pal_dip *dip)
{
	struct ip_hdr *iph = (struct ip_hdr *)skb_ip_header(skb);
	struct icmp_hdr *icmph = skb_icmp_header(skb);
	unsigned icmp_len = pal_ntohs(iph->tot_len) - (iph->ihl * 4);

	pal_cur_thread_conf()->stats.ip.icmp.rx_pkts++;
	pal_cur_thread_conf()->stats.ip.icmp.rx_bytes += skb_l2_len(skb);

	/* icmp content must be more then 8 bytes */
	if (icmp_len >= 8 && icmp_len <= skb_len(skb)) {
		if (icmp_check_sum_correct((uint16_t *)icmph, icmp_len)) {
			return dispatch_pkt(skb, dip);
		} else {
			pal_cur_thread_conf()->stats.ip.icmp.csum_err++;
			PAL_DEBUG("Bad icmp checksum\n");
		}
	} else {
		pal_cur_thread_conf()->stats.ip.icmp.trunc_pkts++;
		PAL_DEBUG("icmp len < 8, invalid\n");
	}

	return -1;
}

/*
 * @brief Handles ip packets
 * @param skb Pointer to the skb, whose data pointer must be set to ip header.
 * @return 0 on success. -1 on failure. The packet is freed in both cases
 */
int ip_handler(struct sk_buff *skb)
{
	int ret = -1;
	struct ip_hdr *iph;
	struct pal_dip *dip;

	if (!skb_ip_csum_ok(skb)) {
		PAL_DEBUG("skb ip csum error\n");
		pal_cur_thread_conf()->stats.ip.csum_err++;
		goto free_out;
	}

	iph = skb_ip_header(skb);

	if ((unsigned)iph->ihl < 5 || skb_len(skb) < (unsigned)iph->ihl * 4) {
		pal_cur_thread_conf()->stats.ip.trunc_pkts++;
		goto free_out;
	}

	dip = pal_ipg_find_ip(iph->daddr);
	if (dip == NULL) {
		pal_cur_thread_conf()->stats.ip.unknown_dst++;
		/* TODO: use default ip group. */
		PAL_DEBUG("dip "NIPQUAD_FMT" not found\n", NIPQUAD(iph->daddr));
		goto free_out;
	}

	switch (dip->type) {
	case PAL_DIP_USER:
		skb_pull(skb, iph->ihl * 4);
		skb_reset_l4_header(skb);
		switch (iph->protocol) {
		case PAL_IPPROTO_TCP:
			ret = tcp_dispatch(skb, dip);
			break;
		case PAL_IPPROTO_UDP:
			ret = udp_dispatch(skb, dip);
			break;
		case PAL_IPPROTO_ICMP:
			if (dip->ipg->flags & PAL_IPG_F_HANDLEICMP) {
				ret = icmp_dispatch(skb, dip);
			} else {
				ret = icmp_handler(skb);
			}
			break;
		default:
			pal_cur_thread_conf()->stats.ip.unknown_proto_pkts++;
			pal_cur_thread_conf()->stats.ip.unknown_proto_bytes += skb_l2_len(skb);
			PAL_DEBUG("UNKNOWN IP PKTS\n");
			if (dip->ipg->flags & PAL_IPG_F_HANDLEUNKNOWIPPROTO) {
				ret = dispatch_pkt(skb, dip);
			} else {
				ret = -1;
			}
			break;
		}

		if (ret >= 0) {
			pal_ipg_put_ip(dip->ip);
			return 0;
		}

		goto putdip_out;

	case PAL_DIP_VNIC:
		if (dip->port != skb->recv_if) {
			pal_cur_thread_conf()->stats.tap.port_err++;
			PAL_DEBUG("got a packet for wrong vnic\n");
			goto putdip_out;
		}

		/* push the data pointer to include the ethernet header */
		skb_push(skb, sizeof(struct eth_hdr));
		if (pal_send_to_vnic(dip->port, skb) == 0) {
            pal_skb_free(skb);
		    pal_ipg_put_ip(dip->ip);
			return 0;
		}
		goto putdip_out;

	default:
		pal_cur_thread_conf()->stats.ip.unknown_dst++;
		PAL_DEBUG("unknown\n");
		goto putdip_out;
	}

putdip_out:
	pal_ipg_put_ip(dip->ip);

free_out:
	pal_skb_free(skb);

	return ret;
}

