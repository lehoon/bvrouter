/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file         $HeadURL: $
* @brief        arp module in namespace
* @author       zhangyu(zhangyu09@baidu.com)
* @date         $Date:$
* @version      $Id: $
***********************************************************************
*/

#include <stdio.h>
#include "bvrouter_list.h"
#include "bvr_hash.h"
#include "bvr_namespace.h"
#include "bvr_errno.h"
#include "bvr_arp.h"
#include "bvr_netfilter.h"

#include "pal_malloc.h"
#include "pal_utils.h"
#include "pal_slab.h"
#include "pal_pktdef.h"
#include "pal_byteorder.h"
#include "pal_vxlan.h"
#include "logger.h"

struct pal_slab *g_bvr_arp_slab = NULL;
struct pal_slab *g_bvr_arp_table_slab = NULL;


/*
 * @brief:reply the arp request from vm
 * @param: skb:arp request pkt dev: input device
 */
int arp_rcv(struct sk_buff *skb, struct vport *dev)
{
    /*vport must be a internal gateway,only reply the req for gw ip*/
    u32 tmp = 0;
    if (dev->vport_type != VXLAN_VPORT) {
        return NF_DROP;
    }

    if (!pskb_may_pull(skb, sizeof(struct arp_hdr))) {
        return NF_DROP;
    }

//    struct vxlan_vport *vxlan_port = (struct vxlan_vport *)dev;
    struct eth_hdr *ethh = skb_eth_header(skb);
    struct arp_hdr *arph = skb_arp_header(skb);

    u32 dip = arph->dst_ip;
    if (dip != dev->vport_ip) {
        BVR_DEBUG("not request for gw ip\n");
        return NF_DROP;
    }

    if (arph->ar_op != pal_htons(PAL_ARPOP_REQUEST)) {
        BVR_DEBUG("not a arp request\n");
        return NF_DROP;
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
    mac_copy(arph->src_mac, dev->vport_eth_addr);
    mac_copy(ethh->src, dev->vport_eth_addr);
    skb_push(skb, sizeof(struct eth_hdr));
    dev->vport_ops->send(skb, dev);

    return NF_ACCEPT;
}


#if 0
struct packet_type arp_type = {
    .type = cpu_to_be16(ETH_P_ARP),
    .func = arp_rcv,
};
#endif

/*
 * @brief:init arp hash table when create net
 * @param: net struct
 */
static int arp_net_init(struct net *net)
{
    u32 i = 0;
    net->arp_table = pal_slab_alloc(g_bvr_arp_table_slab);
    if (!net->arp_table) {
        BVR_ERROR("run off memory\n");
        return -1;
    }
    for (i = 0; i < ARP_TABLE_SIZE; i++)
    {
        PAL_INIT_HLIST_HEAD(&net->arp_table[i]);
    }
    //memcpy(net->gw_mac, , 6);
    return 0;
}


/*
 * @brief:clear arp hash table when delete a net
 * @param: net struct
 */
static void arp_net_exit(struct net *net)
{

    struct arp_entry *entry = NULL;
    struct pal_hlist_node *pos = NULL, *n = NULL;
    struct pal_hlist_head *head = NULL;
    u32 i = 0;
    rte_rwlock_write_lock(&net->net_lock);
    head = net->arp_table;
    net->arp_table = NULL;
    rte_rwlock_write_unlock(&net->net_lock);
    for (i = 0; i < ARP_TABLE_SIZE; i++) {
        pal_hlist_for_each_entry_safe(entry, pos, n, &head[i], hlist)
        {
            pal_hlist_del(&entry->hlist);
            pal_slab_free(entry);
        }
    }
    pal_slab_free(head);
}


/*pernet list ,should be registered when init namespace*/
struct pernet_operation arp_net_ops = {
    .init = arp_net_init,
    .exit = arp_net_exit,
};


/** @brief  find a arp_entry,only used in control plane no read lock get.
 *  @param  net: entry:arp_enty to find,only use entry->ip
 *  @return arp_entry or NULL
 */
struct arp_entry *find_arp_entry(struct net *net, u32 ip)
{
    /*arp_table can be NULL ,when destroy a arp table,
     but haven't free the net.pkt may get in the net,and
     lookup arp table. when this happened return NULL,dataplane
     will drop the pkt.*/
    if (net->arp_table == NULL) {
        return NULL;
    }
    u32 key = 0;
    struct arp_entry *tmp = NULL;
    struct pal_hlist_node *pos = NULL;
    key = nn_hash_4byte(ip) & ARP_TABLE_MASK;
 //   rte_rwlock_write_lock(&net->net_lock);
    pal_hlist_for_each_entry(tmp, pos, &net->arp_table[key], hlist)
    {
        if (tmp->ip == ip) {
        /*the same ip means same entry,ip and mac is one to one mapping*/
            return tmp;
        }
    }
    return NULL;
}

/** @brief  add a arp_entry,only used in control plane get write lock first.
 *  @param  net:add entry to net, entry:arp_enty to add
 *  @return -1 error(already exist), 0 ok
 */
int add_arp_entry(struct net *net, struct arp_entry entry)
{
    /*arp table won't be NULL but still can found net on
     control plane*/
    ASSERT(net->arp_table != NULL);

    u32 key = 0;
    struct arp_entry *add_entry = NULL;
    if ((add_entry = find_arp_entry(net, entry.ip)) != NULL) {
        BVR_WARNING("arp entry add conflict, over write it\n");
        memcpy(&add_entry->mac_addr, &entry.mac_addr, sizeof(add_entry->mac_addr));
        return 0;
    }

    add_entry = pal_slab_alloc(g_bvr_arp_slab);
    if (!add_entry) {
        BVR_WARNING("arp entry:running out if memory\n");
        return -NN_ENOMEM;
    }
    *add_entry = entry;
    BVR_DEBUG("add mac address %02x:%02x:%02x:%02x:%02x:%02x\n",
    ((unsigned char *)&add_entry->mac_addr)[0], \
    ((unsigned char *)&add_entry->mac_addr)[1], \
    ((unsigned char *)&add_entry->mac_addr)[2], \
    ((unsigned char *)&add_entry->mac_addr)[3],
    ((unsigned char *)&add_entry->mac_addr)[4],
    ((unsigned char *)&add_entry->mac_addr)[5]);

    key = nn_hash_4byte(add_entry->ip) & ARP_TABLE_MASK;
    rte_rwlock_write_lock(&net->net_lock);
    pal_hlist_add_head(&add_entry->hlist, &net->arp_table[key]);
    rte_rwlock_write_unlock(&net->net_lock);

    return 0;
}

/** @brief  del a arp_entry,only used in control plane get write lock first.
 *  @param  net:del entry from net, entry:arp_enty to del, only use entry->ip
 *  @return -1 error(entry not exist), 0 ok
 */
int del_arp_entry(struct net *net, struct arp_entry entry)
{
    /*arp table won't be NULL but still can found net on
     control plane*/
    ASSERT(net->arp_table != NULL);
    struct arp_entry *del_entry = NULL;

    if ((del_entry = find_arp_entry(net, entry.ip)) == NULL) {
        BVR_WARNING("arp entry del error, del a entry not exist\n");
        return -NN_EARPNOTEXIST;
    }
    rte_rwlock_write_lock(&net->net_lock);
    pal_hlist_del(&del_entry->hlist);
    pal_slab_free(del_entry);
    rte_rwlock_write_unlock(&net->net_lock);

    return 0;
}


/*
 * @brief  init arp subsystem
 */
int bvr_arp_init(int numa_id)
{
    g_bvr_arp_slab = pal_slab_create("bvr_arp", BVRARP_SLAB_SIZE,
        sizeof(struct arp_entry), numa_id, 0);
    if (g_bvr_arp_slab == NULL) {
        PAL_ERROR("bvr arp init error\n");
        return -1;
    }

    g_bvr_arp_table_slab = pal_slab_create("bvr_arp_table", BVRARP_TABLE_SLAB_SIZE,
        sizeof(struct pal_hlist_head) * ARP_TABLE_SIZE, numa_id, 0);
    if (g_bvr_arp_table_slab == NULL) {
        PAL_ERROR("bvr arp init error\n");
        return -1;
    }
    return 0;

}

