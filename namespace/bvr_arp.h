/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file         $HeadURL: $
* @brief        arp module header file in namespace
* @author       zhangyu(zhangyu09@baidu.com)
* @date         $Date:$
* @version      $Id: $
***********************************************************************
*/

#ifndef ARP_H
#define ARP_H

#include "pal_list.h"
#include "pal_vport.h"
#include "pal_utils.h"
#include "pal_slab.h"
#include "pal_pktdef.h"
#include "pal_byteorder.h"
#include "bvr_namespace.h"

/*arp hash table size*/
#define ARP_TABLE_TABLE_OFFSET 8
#define ARP_TABLE_SIZE (1ULL << ARP_TABLE_TABLE_OFFSET)
#define ARP_TABLE_MASK (ARP_TABLE_SIZE - 1)


#define BVRARP_SLAB_SIZE (NAMESPACE_SLAB_SIZE * 128)
#define BVRARP_TABLE_SLAB_SIZE (NAMESPACE_SLAB_SIZE)

struct arp_entry {
    struct pal_hlist_node hlist;
    u32 ip;
    unsigned char mac_addr[6];
} ;

int arp_rcv(struct sk_buff *skb, struct vport *dev);

int bvr_arp_init(int numa);

struct arp_entry *find_arp_entry(struct net *net, u32 ip);

int add_arp_entry(struct net *net, struct arp_entry entry);
int del_arp_entry(struct net *net, struct arp_entry entry);
#endif

