
/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file         $HeadURL: $
* @brief        net namespace module
* @author       zhangyu(zhangyu09@baidu.com)
* @date         $Date:$
* @version      $Id: $
***********************************************************************
*/


#ifndef NAMESPACE_H
#define NAMESPACE_H

#include "pal_atomic.h"
#include "bvr_hash.h"
#include "bvr_errno.h"
#include "bvrouter_list.h"
#include "pal_list.h"
#include "pal_conf.h"


#define NAMESPACE_TABLE_OFFSET 12
#define NAMESPACE_TABLE_SIZE (1ULL << NAMESPACE_TABLE_OFFSET)
#define NAMESPACE_TABLE_MASK (NAMESPACE_TABLE_SIZE - 1)
#define NAMESPACE_SLAB_SIZE 1024*10


#define NAMESPACE_NAME_SIZE 104
//#define MAX_CORE_NUM 32


/*statistics information per cpu for each namespace*/
struct statistics {
    u64 hdrerror_pkts;
    u64 hdrerror_bytes;
    u64 rterror_bytes;
    u64 rterror_pkts;
    u64 arperror_pkts;
    u64 arperror_bytes;
    u64 input_pkts;
    u64 input_bytes;
    u64 output_pkts;
    u64 output_bytes;
    u64 pad[6];
};

#define dev_net(dev) (struct net *)dev->private
//struct counter {
//

//};

struct net {
    struct route_table *route_table;    /*route table*/
    struct pal_hlist_head *arp_table;   //arp table
    struct xt_table *filter;            //netfilter filter table
    struct xt_table *nat;               //netfilter nat table

    struct pal_list_head dev_base_head;     //dev list

    struct pal_hlist_node hlist;    //link to namespace hash table

    /*cache line 2*/
    char name[NAMESPACE_NAME_SIZE];
    u8 counter[PAL_MAX_CPU];
    atomic_t if_count;          //count how many interfaces referenced the net
  //atomic_t user_count;        //count how many pkt run through the net

    rte_rwlock_t net_lock;      //rwlock to protect resource in net(router table etc)

    /*cache line 3*/

    struct statistics stats[PAL_MAX_CPU];  //per cpu statistics
};


struct pernet_operation {
    struct pal_list_head list;
    int (*init) (struct net *net);  //initialize the subsystem
    void (*exit) (struct net *net); //free the subsystem resource
};

static inline
int net_eq(const struct net *net1, const struct net *net2)
{
    return net1 == net2;
}


/*when a interface reference a net,increase the if_count*/
static inline void net_if_hold(struct net *net)
{
    atomic_inc(&net->if_count);
}

/*when a interface reference a net,decrease the if_count*/
static inline void net_if_put(struct net *net)
{
    atomic_dec(&net->if_count);
}

/*when a skb go through a net,increase count and hold read lock*/
static inline void net_user_hold(struct net *net)
{
    rte_rwlock_read_lock(&net->net_lock);
    //atomic_inc(&net->user_count);
    net->counter[rte_lcore_id()]++;
}

/*when a skb leave a net,decrease count and release read lock*/
static inline void net_user_put(struct net *net)
{
    rte_rwlock_read_unlock(&net->net_lock);
    //atomic_dec(&net->user_count);
    net->counter[rte_lcore_id()]--;

}

int register_pernet_operations(struct pernet_operation *ops);

void unregister_pernet_operations(struct pernet_operation *ops);


/*the operation below only can be used by control process*/
struct net *net_get(char *name);
int namespace_init(int numa);

int net_create(char *name);
int del_net(char *name);

#endif
