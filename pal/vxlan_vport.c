#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "pal_vxlan.h"
#include "pal_error.h"
#include "vtep.h"
#include "pal_malloc.h"
#include "pal_slab.h"

static struct pal_slab *vxlan_fdb_slab = NULL;
static struct pal_slab *vxlan_arp_slab = NULL;
static struct pal_slab *vxlan_skb_slab = NULL;

static __be16 vxlan_src_port(struct sk_buff *);


/* Look up Ethernet address in forwarding table, no lock*/
static struct vxlan_fdb *__vxlan_find_mac(struct vxlan_dev *vdev,
					uint8_t *mac)

{
	struct pal_hlist_head *head = vxlan_fdb_head(vdev, mac);
	struct vxlan_fdb *f;
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(f,hnode, head, hlist) {
		if (pal_compare_ether_addr(mac, f->eth_addr) == 0)
			return f;
	}

	return NULL;
}

static struct vxlan_fdb *__bvrouter __vxlan_find_mac_index(struct vxlan_dev *vdev,
					uint8_t *mac,uint32_t index)

{
	struct pal_hlist_head *head = vxlan_fdb_head_index(vdev, index);
	struct vxlan_fdb *f;
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(f,hnode, head, hlist) {
		if (pal_compare_ether_addr(mac, f->eth_addr) == 0)
			return f;
	}

	return NULL;
}

static struct vxlan_fdb *__bvrouter vxlan_find_lock_mac(struct vxlan_dev *vdev,
					 uint8_t *mac,uint32_t index)
{
	struct vxlan_fdb *f;

	read_lock_vxlan_fdb(vdev,index);
	f = __vxlan_find_mac_index(vdev, mac,index);

	return f;
}

static int vxlan_fdb_append(struct vxlan_fdb *f,
			    __be32 ip, __be16 port, uint32_t vni, uint32_t ifindex,struct vxlan_dev *vdev,uint32_t index)
{
	struct vxlan_rdst *rd_prev, *rd;

	rd_prev = NULL;
	for (rd = &f->remote; rd; rd = rd->remote_next) {
		if (rd->remote_ip == ip &&
		    rd->remote_port == port &&
		    rd->remote_vni == vni &&
		    rd->remote_ifindex == ifindex)
			return 0;
		rd_prev = rd;
	}
	rd = pal_malloc(sizeof(*rd));
	if (rd == NULL)
		return -ENOMEM;
	rd->remote_ip = ip;
	rd->remote_port = port;
	rd->remote_vni = vni;
	rd->remote_ifindex = ifindex;
	rd->remote_next = NULL;

	write_lock_vxlan_fdb(vdev,index);
	rd_prev->remote_next = rd;
	write_unlock_vxlan_fdb(vdev,index);

	return 1;
}

static int __vxlan_fdb_create(struct vxlan_dev *vdev,
					uint8_t *mac, __be32 ip,
					__be16 port, uint32_t vni, uint32_t ifindex,uint32_t index)

{
	struct vxlan_fdb *f;

	f = __vxlan_find_mac(vdev, mac);
	if (f) {
		if (pal_is_multicast_ether_addr(f->eth_addr)||
				pal_is_broadcast_ether_addr(f->eth_addr)) {
			int rc = vxlan_fdb_append(f, ip, port, vni, ifindex,vdev,index);
			if (rc < 0)
				return rc;
		}else {
            /*if fdb exists and nothing to update ignore it*/
            if (f->remote.remote_ip == ip && f->remote.remote_port == port &&
		        f->remote.remote_vni == vni && f->remote.remote_ifindex == ifindex) {
			    return -EEXIST;
            }
            /*update the fdb entry*/
            write_lock_vxlan_fdb(vdev,index);
            f->remote.remote_ip = ip;
            f->remote.remote_port = port;
            f->remote.remote_vni = vni;
            f->remote.remote_ifindex = ifindex;
            f->remote.remote_next = NULL;
            write_unlock_vxlan_fdb(vdev,index);
            return 0;
        }
	} else {
		f = pal_slab_alloc(vxlan_fdb_slab);
		if (!f)
			return -ENOMEM;

		f->remote.remote_ip = ip;
		f->remote.remote_port = port;
		f->remote.remote_vni = vni;
		f->remote.remote_ifindex = ifindex;
		f->remote.remote_next = NULL;
		rte_memcpy(f->eth_addr, mac, 6);

		write_lock_vxlan_fdb(vdev,index);
		++vdev->fdb_cnt;
		pal_hlist_add_head(&f->hlist,
				   vxlan_fdb_head(vdev, mac));
		write_unlock_vxlan_fdb(vdev,index);
	}

	return 0;
}

/* Add static entry */
int vxlan_fdb_add( struct vxlan_dev *vdev,
			  unsigned char *mac,
			 __be32 ip, __be16 port, uint32_t vni,uint32_t ifindex)
{
	int err;
	uint32_t index;

	index = get_hash_index_mac(mac);
	err = __vxlan_fdb_create(vdev, mac, ip,
			       port, vni, ifindex, index);
	return err;
}

static void vxlan_fdb_free(struct vxlan_fdb *f)
{
	while (f->remote.remote_next) {
		struct vxlan_rdst *rd = f->remote.remote_next;

		f->remote.remote_next = rd->remote_next;
		pal_free(rd);
	}
	pal_slab_free(f);
}

static void __vxlan_fdb_destroy(struct vxlan_dev *vdev, struct vxlan_fdb *f, uint32_t index)
{
	write_lock_vxlan_fdb(vdev,index);
	--vdev->fdb_cnt;
	pal_hlist_del(&f->hlist);
	write_unlock_vxlan_fdb(vdev,index);

	vxlan_fdb_free(f);
}

/* Delete fdb entry  */
int vxlan_fdb_delete(struct vxlan_dev *vdev,
			     unsigned char *mac)
{
	uint32_t index;
	struct vxlan_fdb *f;
	int err = -ENOENT;

	index = get_hash_index_mac(mac);
	f = __vxlan_find_mac(vdev, mac);
	if (f) {
		__vxlan_fdb_destroy(vdev, f,index);
		err = 0;
	}

	return err;
}

/*flush fdb table*/
int vxlan_fdb_flush(struct vxlan_dev *vdev)
{
	unsigned int h;

	for (h = 0; h < FDB_HASH_SIZE; ++h) {
		struct vxlan_fdb *f;

		while (!pal_hlist_empty(&vdev->fdb_array[h].head)) {
			f = pal_hlist_entry(vdev->fdb_array[h].head.first, struct vxlan_fdb, hlist);
			__vxlan_fdb_destroy(vdev,f,h);
		}
	}

	return 0;
}

static void vxlan_fdb_dump(struct vxlan_fdb *f)
{

	printf("-------fdb-------- :\n");
	printf("----MAC:%x---\n",f->eth_addr[0]);
	printf("remote_ip: %x\n",f->remote.remote_ip);
	printf("remote_port: %x\n",f->remote.remote_port);
	printf("vni: %x",f->remote.remote_vni);

	while (f->remote.remote_next) {
		struct vxlan_rdst *rd = f->remote.remote_next;
		printf("remote_ip: %x\n",rd->remote_ip);
		printf("remote_port: %x\n",rd->remote_port);
		printf("vni: %x",rd->remote_vni);

		f->remote.remote_next = rd->remote_next;
	}
}

int vxlan_fdb_show(struct vxlan_dev *vdev)
{
	unsigned int h;

	for (h = 0; h < FDB_HASH_SIZE; ++h) {
		struct vxlan_fdb *f;
		struct pal_hlist_node *hnode;

		read_lock_vxlan_fdb(vdev,h);
		pal_hlist_for_each_entry(f,hnode,vxlan_fdb_head_index(vdev,h), hlist) {
			vxlan_fdb_dump(f);
		}
		read_unlock_vxlan_fdb(vdev,h);
	}

	return 0;
}

void vxlan_fdb_slab_init(int numa_id)
{
    vxlan_fdb_slab = pal_slab_create("vxlan_fdb", VXLAN_FDB_SLAB_SIZE,
		sizeof(struct vxlan_fdb), numa_id, 0);

	if (!vxlan_fdb_slab) {
		PAL_PANIC("create vxlan_fdb slab failed\n");
	}
}

/*find arp entry, no lock*/
static inline struct vxlan_arp_entry *__find_arp_entry(struct vxlan_dev *vdev,
	__be32 ip,uint32_t index)
{
    struct vxlan_arp_entry *tmp;
    struct pal_hlist_node *pos;

    pal_hlist_for_each_entry(tmp, pos, vxlan_arp_head_index(vdev,index), hlist){
        if (tmp->ip == ip)
            return tmp;
    }

    return NULL;
}

struct vxlan_arp_entry *find_vxlan_arp_entry(struct vxlan_dev *vdev,
	__be32 ip)
{
    uint32_t index;
    struct vxlan_arp_entry *tmp;

	index = get_hash_index_arp(ip);
	read_lock_vxlan_arp(vdev,index);
	tmp = __find_arp_entry(vdev,ip,index);
	read_unlock_vxlan_arp(vdev,index);

    return tmp;
}

static int find_vxlan_arp_entry_info(struct vxlan_dev *vdev,
	__be32 ip,uint8_t *dst_mac)
{
    uint32_t index;
    struct vxlan_arp_entry *tmp;

	index = get_hash_index_arp(ip);
	read_lock_vxlan_arp(vdev,index);
	tmp = __find_arp_entry(vdev,ip,index);
	if(unlikely(!tmp)){
		read_unlock_vxlan_arp(vdev,index);
		return -1;
	}else{
		mac_copy(dst_mac,tmp->mac_addr);
	}
	read_unlock_vxlan_arp(vdev,index);

    return 0;
}

/* Fill in dst_mac with specified vxlan_vport and dst_ip. */
int locate_eth_dst(struct vport *vp, __be32 ip, uint8_t *dst_mac) {
    if (vp->vport_type == PHY_VPORT) {
        return -1;
    }
    return find_vxlan_arp_entry_info(((struct int_vport *)vp)->vdev, ip, dst_mac);
}

static int __add_arp_entry(struct vxlan_dev *vdev,
	struct vxlan_arp_entry *entry,uint32_t index)
{
    struct vxlan_arp_entry *add_entry;

    add_entry = __find_arp_entry(vdev,entry->ip,index);
	if(add_entry){
		write_lock_vxlan_arp(vdev,index);
		/*update arp entry mac, also should be protected by lock*/
		rte_memcpy(add_entry->mac_addr, entry->mac_addr, 6);
		write_unlock_vxlan_arp(vdev,index);
	}else{
		add_entry = pal_slab_alloc(vxlan_arp_slab);
		if (!add_entry) {
        	return -ENOMEM;
    	}

		add_entry->ip = entry->ip;
		rte_memcpy(add_entry->mac_addr, entry->mac_addr, 6);

		write_lock_vxlan_arp(vdev,index);
		++vdev->arp_cnt;
		pal_hlist_add_head(&add_entry->hlist,vxlan_arp_head_index(vdev,index));
		write_unlock_vxlan_arp(vdev,index);
	}

    return 0;
}

int add_vxlan_arp_entry(struct vxlan_dev *vdev, struct vxlan_arp_entry *entry)
{
	int err;
	uint32_t index;

	index = get_hash_index_arp(entry->ip);
	err = __add_arp_entry(vdev,entry,index);

	return err;
}

static void arp_entry_free(struct vxlan_arp_entry *entry)
{
	if(entry){
		pal_slab_free(entry);
	}
}

static void __vxlan_arp_destroy(struct vxlan_dev *vdev, struct vxlan_arp_entry *entry,uint32_t index)
{
	write_lock_vxlan_arp(vdev,index);
	--vdev->arp_cnt;
	pal_hlist_del(&entry->hlist);
	write_unlock_vxlan_arp(vdev,index);

	arp_entry_free(entry);
}

int del_vxlan_arp_entry(struct vxlan_dev *vdev, __be32 ip)
{
  	uint32_t index;
	struct vxlan_arp_entry *entry;
	int err = -ENOENT;

	index = get_hash_index_arp(ip);

	entry = __find_arp_entry(vdev,ip,index);
	if (entry) {
		__vxlan_arp_destroy(vdev, entry,index);
		err = 0;
	}

	return err;
}

/*flush arp table*/
int vxlan_arp_flush(struct vxlan_dev *vdev)
{
	unsigned int h;

	for (h = 0; h < ARP_HASH_SIZE; ++h) {
		struct vxlan_arp_entry *entry;
		while (!pal_hlist_empty(&vdev->arp_array[h].head)) {
			entry = pal_hlist_entry(vdev->arp_array[h].head.first, struct vxlan_arp_entry, hlist);
			__vxlan_arp_destroy(vdev,entry,h);
		}
	}

	return 0;
}

void vxlan_arp_slab_init(int numa_id)
{
    vxlan_arp_slab = pal_slab_create("vxlan_arp_entry", VXLAN_ARP_SLAB_SIZE,
		sizeof(struct vxlan_arp_entry), numa_id, 0);

	if (!vxlan_arp_slab) {
		PAL_PANIC("create vxlan_arp_entry slab failed\n");
	}
}

static int int_vport_init(struct vport *dev){
	struct int_vport *vport = (struct int_vport *)dev;

	vport->vni_hash_index = get_hash_index_vni(vport->vdev->vni);
	vport->src_port = vtep_src_port(vport->vp.vport_ip);
    memset(vport->stats, 0, sizeof(vport->stats));

	return 0;
}

static int int_vport_close(__unused struct vport *dev){
	return 0;
}

static int __bvrouter int_vport_send(struct sk_buff *skb, struct vport *dev)
{
	struct int_vport *vport = (struct int_vport *)dev;
	struct eth_hdr *eth;
	struct ip_hdr *iph;
	struct vxlan_rdst *rdst0 = NULL, *rdst = NULL;
	struct vxlan_fdb *f;
	uint32_t index;
    uint16_t src_port;
	int rc1 = 0, rc = 0;
    int lcore_id = rte_lcore_id();

    eth = skb_eth_header(skb);
    src_port = vxlan_src_port(skb);

    switch (eth->type) {
        case pal_htons_constant(PAL_ETH_ARP):
            /*fdb find*/
			index = get_hash_index_mac(eth->dst);
            /*this may cause arp request may not reply*/
	        f = vxlan_find_lock_mac(vport->vdev, eth->dst,index);
	        if (unlikely(!f)) {
				read_unlock_vxlan_fdb(vport->vdev,index);
		        vport->stats[lcore_id].tx_dropped++;
		        goto drop;
	        } else
		        rdst0 = &f->remote;

	        rc = 0;

	        /* if there are multiple destinations, send copies */
	        for (rdst = rdst0->remote_next; rdst; rdst = rdst->remote_next) {
		        struct sk_buff *skb1;
		        skb1 = skb_clone(skb,vxlan_skb_slab, 2000);
		        if (skb1) {
			        vport->stats[lcore_id].tx_packets++;
			        rc1 = vtep_xmit_one(skb1, vport->vdev, rdst, src_port);
			        if (rc == 0)
				        rc = rc1;
		        }
	        }
            break;
        case pal_htons_constant(PAL_ETH_IP):
            iph = skb_ip_header(skb);
	        /*arp find*/
            /* Attemp to fill in dst_mac with dst_ip. Failing here doesn't matter cause dst_mac 
             * may already be the nexthop's mac. */
			find_vxlan_arp_entry_info(vport->vdev,iph->daddr,eth->dst);
	        mac_copy(eth->src, vport->vp.vport_eth_addr);

	        /*fdb find*/
			index = get_hash_index_mac(eth->dst);
	        f = vxlan_find_lock_mac(vport->vdev, eth->dst,index);
	        if (unlikely(!f)) {
				read_unlock_vxlan_fdb(vport->vdev,index);
		        vport->stats[lcore_id].tx_dropped++;
		        goto drop;
	        } else
		        rdst0 = &f->remote;

	        rc = 0;

	        /* if there are multiple destinations, send copies */
	        for (rdst = rdst0->remote_next; rdst; rdst = rdst->remote_next) {
		        struct sk_buff *skb1;
		        skb1 = skb_clone(skb,vxlan_skb_slab, 2000);
		        if (skb1) {
			        vport->stats[lcore_id].tx_packets++;
			        rc1 = vtep_xmit_one(skb1, vport->vdev, rdst, src_port);
			        if (rc == 0)
				        rc = rc1;
		        }
	        }
            break;
        default:
            goto drop;
    }

	vport->stats[lcore_id].tx_packets++;
	rc1 = vtep_xmit_one(skb, vport->vdev, rdst0, src_port);
	read_unlock_vxlan_fdb(vport->vdev,index);

	if (rc == 0)
		rc = rc1;

	return rc;

drop:
	pal_skb_free(skb);
	return -EFAULT;
}

/*protected by namespace lock*/
static int __bvrouter int_vport_recv(struct sk_buff *skb,struct vport *dev)
{
	struct int_vport *vport = (struct int_vport *)dev;
	int ret;

	read_lock_namespace(dev->private);
	ret = bvr_pkt_handler(skb,dev);
	read_unlock_namespace(dev->private);

	read_unlock_vxlan_dev(vport->vni_hash_index);
	if(unlikely(ret == BVROUTER_DROP))
		goto drop;

	return 0;
drop:
	pal_skb_free(skb);
	return -EFAULT;
}

const struct vport_device_ops int_vport_ops = {
	.init	= int_vport_init,
	.send	= int_vport_send,
	.recv	= int_vport_recv,
	.close  = int_vport_close,
};

void vxlan_skb_slab_init(int numa_id)
{
    vxlan_skb_slab = pal_slab_create_multipc("vxlan skb", VXLAN_SKB_SLAB_SIZE,
		2048, numa_id, 0);

	if (!vxlan_skb_slab) {
		PAL_PANIC("create vxlan skb slab failed\n");
	}
}

/* Make sure that the packet is complete, which means @skb points to eth header */
static uint32_t _skb_get_hash(struct sk_buff *skb) {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t protocol;
    uint32_t keys[4];
    struct ip_hdr *iph = NULL;
    struct arp_hdr *arph = NULL;
    struct udp_hdr *udph = NULL;
    struct tcp_hdr *tcph = NULL;
    struct eth_hdr *ethh = NULL;

    if (unlikely(!pskb_may_pull(skb, sizeof(ethh)))) {
        return 0;
    }
    skb_reset_eth_header(skb);
    ethh = skb_eth_header(skb);
    protocol = ethh->type >> 16;

    /*Find ips&ports from L3/L4 header*/
    switch(ethh->type) {
    case pal_htons_constant(PAL_ETH_ARP):
        arph = skb_arp_header(skb);
        src_ip = arph->src_ip;
        dst_ip = arph->dst_ip;
        src_port = 0;
        dst_port = 0;
        break;
    case pal_htons_constant(PAL_ETH_IP):
        iph = skb_ip_header(skb);
        src_ip = iph->saddr;
        dst_ip = iph->daddr;
        protocol += iph->protocol;

        /*Find ports from TCP/UDP header*/
        if (unlikely(!pskb_may_pull(skb, sizeof(iph)))) {
            return 0;
        }
        switch(iph->protocol) {
        case PAL_IPPROTO_TCP:
            tcph = skb_tcp_header(skb);
            src_port = tcph->source;
            dst_port = tcph->dest;
            break;
        case PAL_IPPROTO_UDP:
            udph = skb_udp_header(skb);
            src_port = udph->source;
            dst_port = udph->dest;
            break;
        case PAL_IPPROTO_ICMP:
            src_port = 0;
            dst_port = 0;
            break;
        default:
            return 0;
        }
        break;
    default:
        return 0;
    }

    /* get a consistent hash (same value on both flow directions) */
    if ((src_ip > dst_ip) || ((src_ip == dst_ip) && (src_port > dst_port))) {
        keys[0] = dst_ip;
        keys[1] = src_ip;
        keys[2] = (dst_port << 16) + src_port;
        keys[3] = protocol;
    } else {
        keys[0] = src_ip;
        keys[1] = dst_ip;
        keys[2] = (src_port << 16) + dst_port;
        keys[3] = protocol;
    }

    return pal_hash_crc((void *)keys, 16);
}


/* Compute source port for outgoing packet
 *   first choice is to use L4 flow hash since it will spread better
 *   secondary choice is to use crc_hash on the Ethernet header
 */
static __be16 vxlan_src_port(struct sk_buff *skb)
{
    uint32_t hash;

    hash = _skb_get_hash(skb);
    if (!hash)
        hash = pal_hash_crc(skb_data(skb), 2 * ETH_ALEN);

	return pal_htons((((uint64_t) hash * VTEP_SRC_PORT_RANGE) >> 32) + VTEP_SRC_PORT_MIN);
}
