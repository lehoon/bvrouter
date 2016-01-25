#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "pal_phy_vport.h"
#include "pal_ip_cell.h"
#include "pal_error.h"
#include "vtep.h"
#include "pal_netif.h"

void show_floating_ip(struct phy_vport *vport)
{
	struct ip_cell *ipcell;

	pal_list_for_each_entry(ipcell, &vport->floating_list, list) {
		dump_ip_cell(ipcell);
	}
}

static int phy_vport_init(struct vport *dev)
{
	int err;
	struct phy_vport *vport = (struct phy_vport *)dev;

	atomic_set(&(vport->count),0);
	vport->port_state = PHY_VPORT_INIT;

	/*create ext_gw_ip cell*/
	if((err = ip_cell_add(vport->vp.vport_ip,
		EXT_GW_IP,vport)) < 0){
		return err;
	}

    memset(vport->stats, 0, sizeof(vport->stats));
    memset(vport->use_count, 0, sizeof(vport->use_count));

	/*init floating ip list*/
	PAL_INIT_LIST_HEAD(&vport->floating_list);
	vport->fl_ip_count = 0;

	phy_vport_get(vport);
	return 0;
}

static int phy_vport_close(struct vport *dev)
{
	struct phy_vport *vport = (struct phy_vport *)dev;
	phy_vport_release(vport);
	return 0;
}

static int __bvrouter phy_vport_send(struct sk_buff *skb, struct vport *dev)
{
	struct eth_hdr *eth;
	int ret;
	struct phy_vport *vport = (struct phy_vport *)dev;
   	int lcore_id = rte_lcore_id();
    struct ip_hdr *iph;
	vport->stats[lcore_id].tx_packets++;
	vport->stats[lcore_id].tx_bytes += skb_len(skb);
	eth	= skb_eth_header(skb);
	mac_copy(eth->dst, get_nn_gw_mac());
	mac_copy(eth->src, get_vtep_mac());

    iph = skb_ip_header(skb);
    /*for reassemble pkt, rte_reassemble set PKT_TX_IP_CKSUM*/
    #if 0
    if (skb->mbuf.ol_flags & PKT_TX_IP_CKSUM) {
        iph->check = 0;
        skb->mbuf.pkt.vlan_macip.f.l2_len = sizeof(struct eth_hdr);
        skb->mbuf.pkt.vlan_macip.f.l3_len = iph->ihl << 2;
    }
    #endif
	if((ret = pal_send_batch_pkt(skb, skb->recv_if)) == 0){
			return 0;
	}else
			goto tx_error;

tx_error:
		vport->stats[lcore_id].tx_errors += ret;
		//pal_skb_free(skb);
		return -EFAULT;
}

static int __bvrouter phy_vport_recv(struct sk_buff *skb,struct vport *dev)
{
	struct ip_hdr  *iph;
	int ret;
	struct phy_vport *vport = (struct phy_vport *)dev;
    int lcore_id = rte_lcore_id();

	vport->stats[lcore_id].rx_packets++;
	vport->stats[lcore_id].rx_bytes += skb_len(skb);

	iph = skb_ip_header(skb);
	skb_push(skb, ((iph->ihl) << 2));
	skb_push(skb, sizeof(struct eth_hdr));

	read_lock_namespace(dev->private);
	ret = bvr_pkt_handler(skb,dev);
	read_unlock_namespace(dev->private);

	vport->use_count[lcore_id]--;

	if(unlikely(ret == BVROUTER_DROP)){
		pal_skb_free(skb);
		return -EFAULT;
	}

	return 0;
}

const struct vport_device_ops phy_vport_ops = {
	.init	= phy_vport_init,
	.send	= phy_vport_send,
	.recv	= phy_vport_recv,
	.close  = phy_vport_close,
};

