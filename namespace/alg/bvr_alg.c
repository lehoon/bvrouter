
#include <libev/ev.h>
#include "pal_cpu.h"
#include "pal_conf.h"
#include "pal_thread.h"
#include "pal_skb.h"
#include "pal_pktdef.h"
#include "pal_utils.h"
#include "pal_ipgroup.h"
#include "pal_netif.h"
#include "pal_malloc.h"
#include "pal_vnic.h"
#include "pal_vport.h"


#include "bvr_netfilter.h"
#include "bvr_alg.h"
#include "bvr_ftp.h"
#include "bvr_hash.h"
#include "logger.h"
#define FTP_PORT 21


static u32 bvr_alg_decode(struct sk_buff *skb, u32 *direction, __unused void *private_data)
{
    struct ip_hdr *iph = skb_ip_header(skb);
    struct tcp_hdr *tcph = NULL;
    /*private data*/
    u32 ftpport = FTP_PORT;

    switch (iph->protocol) {
    case PAL_IPPROTO_TCP:
        tcph = skb_tcp_header(skb);
        /* decode for ftp */
        {
            if (pal_ntohs(tcph->source) == ftpport) {
                *direction = FTP_PASSIVE;
                return BVR_ALG_FTP;
            }
        }
        break;
    case PAL_IPPROTO_UDP:
    case PAL_IPPROTO_ICMP:
    default:
        break;
    }
    return BVR_ALG_ANY;
}


static u32 bvr_alg_out(__unused u8 hooknum, struct sk_buff *skb, struct vport *in, struct vport *out, __unused void *private_data)
{
    if (!in || !out) {
        return NF_ACCEPT;
    }

    if (in->vport_type == VXLAN_VPORT && out->vport_type == PHY_VPORT)
    {
        u32 direction = 0;
        u32 appid = bvr_alg_decode(skb, &direction, private_data);

        switch (appid) {
        case BVR_ALG_FTP:
            bvr_alg_ftp_out(skb, direction);
            break;
        default:
            break;
        }
        return NF_ACCEPT;
    }
    return NF_ACCEPT;

}

struct nf_hook_ops alg_ops = {
    .hook = bvr_alg_out,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_POSTROUTING,
    .priority = NF_IP_PRI_ALG,
 //   .private_data = 21,
};

