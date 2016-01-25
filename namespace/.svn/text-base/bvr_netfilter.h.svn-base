/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file         $HeadURL: $
* @brief        netfilter module provide ACL and NAT function
* @author       zhangyu(zhangyu09@baidu.com)
* @date         $Date:$
* @version      $Id: $
***********************************************************************
*/




#ifndef NETFILTER_H
#define NETFILTER_H
#include <stdio.h>
#include <string.h>
#include "pal_skb.h"
#include "pal_vport.h"
#include "pal_list.h"
#include "pal_pktdef.h"
#include "bvr_hash.h"
#include "bvr_namespace.h"

#include "bvrouter_list.h"

enum {
    NFPROTO_UNSPEC =  0,
    NFPROTO_IPV4   =  2,
    NFPROTO_ARP    =  3,
    NFPROTO_BRIDGE =  7,
    NFPROTO_IPV6   = 10,
    NFPROTO_DECNET = 12,
    NFPROTO_NUMPROTO,
};

enum {
    NF_PREROUTING =  0,
    NF_FORWARDING   =  1,
    NF_POSTROUTING =  2,
    NF_MAX_HOOKS,
};

enum {

    NF_DROP = 0,
    NF_ACCEPT,
    NF_SNAT,
    NF_DNAT,
    NF_DUMP,
    NF_STOLEN,
    NF_TARGET_MAX,
};

enum {
    NF_IP_PRI_NAT_DST   = 0,
    NF_IP_PRI_PRE_DUMP  = 1,
    NF_IP_PRI_FILTER    = 2,
    NF_IP_PRI_NAT_SRC   = 3,
    NF_IP_PRI_POST_DUMP = 4,
    NF_IP_PRI_ALG = 5,
    NF_IP_PRI_LAST = 100,

};


#define NAT_TABLE "nat"
#define FILTER_TABLE "filter"


/*each net has 2 xt_table*/
#define XT_TABLE_SLAB_SIZE (NAMESPACE_SLAB_SIZE * 2)
/*each net has 1 xt_nat_table and 1 xt_filter_table*/
#define XT_NAT_TABLE_SLAB_SIZE NAMESPACE_SLAB_SIZE
#define XT_FILTER_TABLE_SLAB_SIZE NAMESPACE_SLAB_SIZE
#define IPT_NAT_ENTRY_SLAB_SIZE ((XT_NAT_TABLE_SLAB_SIZE) * (NAT_TABLE_SIZE)/8)
#define IPT_FILTER_ENTRY_SLAB_SIZE ((XT_NAT_TABLE_SLAB_SIZE) * (FILTER_TABLE_SIZE)/8)



/*
 * @brief: transfer ip and mask to format xx.xx.xx.xx/xx
 *         if you don't need mask, set mask 0.
 */
static inline char *trans_ip(u32 ip, u32 mask)
{
    static int i = 0;
    static char g_print_ip_buf[5][20];

    i = (i + 1) % 5;
    memset(g_print_ip_buf[i], 0, 20);
    sprintf(g_print_ip_buf[i], "%d.%d.%d.%d",
    ((unsigned char *)&ip)[0], \
    ((unsigned char *)&ip)[1], \
    ((unsigned char *)&ip)[2], \
    ((unsigned char *)&ip)[3]);
    int len = strlen(g_print_ip_buf[i]);
    if ((mask > 0) && (mask <= 32)) {
        sprintf(g_print_ip_buf[i] + len, "/%d", mask);
    }
    return g_print_ip_buf[i];
}

/*
 * @brief: transfer mac to format xx:xx:xx:xx:xx:xx
 */
static inline char *trans_mac(unsigned char *mac)
{
    if (!mac) {
        return NULL;
    }
    static int i = 0;
    static char g_print_mac_buf[5][20];

    i = (i + 1) % 5;
    memset(g_print_mac_buf[i], 0, 20);
    sprintf(g_print_mac_buf[i], "%02x:%02x:%02x:%02x:%02x:%02x",
    (unsigned char )mac[0], \
    (unsigned char )mac[1], \
    (unsigned char )mac[2], \
    (unsigned char )mac[3],
    (unsigned char )mac[4],
    (unsigned char )mac[5]);

    return g_print_mac_buf[i];
}

typedef unsigned int nf_hookfn(u8 hooknum,
                    struct sk_buff* skb,
                    struct vport *in,
                    struct vport *out,
                    __unused void *private_data);

struct nf_hook_ops {
    struct pal_list_head list;  /*list to nf_hook*/
    nf_hookfn *hook;            /*hook function*/
    u8 pf;                      /*protocol*/
    u8 hooknum;                 /*hook number*/
    int priority;               /*priority*/
    void *private_data;
};


extern struct pal_list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];


int nf_hook_iterate(u8 pf, u8 hook, struct sk_buff *skb,
         struct vport *in, struct vport *out,
         int (*okfn)(struct sk_buff *, struct vport *, struct vport *));

#define set_bit(a, b) ((a) = ((a) | (1ULL << (b))))
#define clear_bit(a, b) ((a) = ((a) & ~(1ULL << (b))))
#define get_bit(a,b) (((a) & (1ULL) << b) >> b)

static inline int get_mask_count(u32 a)
{
    int count = 0;
    while (a > 0){
        a = a & (a - 1);
        count++;
    }
    return count;
}
#define XT_NAME_SIZE 32
struct xt_table {
    u8 af;
    u32 valid_hooks;
    void *private;
    char name[XT_NAME_SIZE];
};

/*each namespace has 1024 nat rules*/
#define NAT_HASH_OFFSET         10
#define NAT_TABLE_SIZE          (1UL << NAT_HASH_OFFSET)
#define NAT_TABLE_MASK          (NAT_TABLE_SIZE - 1)


struct counter {
    u64 pcnt, bcnt;
    u64 pad[6];

};

struct ipt_counter {
    struct counter cnt[PAL_MAX_CPU];
};

#define ADD_COUNTER(c, b, p, lcoreid) do { (c).cnt[lcoreid].bcnt += (b);\
    (c).cnt[lcoreid].pcnt += (p); } while(0)


struct nat_rule_table {
    u32 rule_num;
    u32 rule_mask;
    struct pal_hlist_head nat_hmap[NAT_TABLE_SIZE];
};

struct xt_nat_table {
    struct nat_rule_table table[NF_MAX_HOOKS];
};


struct ipt_nat_entry {
    struct pal_hlist_node hlist;
    u32 orig_ip;
    u32 nat_ip;
    u32 nat_target;
    u32 pad[9];
    struct ipt_counter counter;
//    volatile u64 hit_pkts;
//    volatile u64 hit_bytes;
};

#define FILTER_HASH_OFFSET          7
#define FILTER_TABLE_SIZE           (1UL << FILTER_HASH_OFFSET)
#define FILTER_TABLE_MASK           (FILTER_TABLE_SIZE - 1)

struct filter_rule_table {
    struct pal_list_head mask_list;     //rule table for filter
    u32 rule_num;           //mask list
    u32 rule_mask;          //rule number count
    struct pal_hlist_head filter_hmap[FILTER_TABLE_SIZE];  //rule hash table
};

struct xt_filter_table {
    struct filter_rule_table table[NF_MAX_HOOKS];
};

struct flow_key {
    /*for memcpy to cmp two obj,make this alignment*/
    u32 sip;
    u32 dip;
    u16 sport[2];   /*sport[0]:start, sport[1]:end*/
    u16 dport[2];   /*dport[0]:start, dport[1]:end*/
    u32 proto;
}__attribute__((packed));


struct flow_mask {
    /*for memcpy to cmp two obj,make this alignment*/
    u32 sip;        /*255.255.255.0*/
    u32 dip;
    u16 proto;

    u8 sport;
    u8 dport;
}__attribute__((packed));


struct ipt_flow_mask {
    struct pal_list_head list;
    int ref_cnt;
    struct flow_mask mask;
};

struct ipt_filter_entry {
    struct pal_hlist_node hlist;

    struct flow_mask mask_value;
    u32 priority;
    struct flow_key key;
    u16 dir;            /*switch on the dir filter, only filter the tcp syn and icmp req*/
    u16 filter_target;
    struct ipt_flow_mask *mask; //point to mask listed in mask_list
    /*cache line 2*/
    struct ipt_counter counter;
//    volatile u64 hit_pkts;
//    volatile u64 hit_bytes;
};


int nf_init(int numa);

int ipt_nat_insert_rule(struct net *net, u8 hook_num, struct ipt_nat_entry entry);
int ipt_nat_del_rule(struct net *net, u8 hook_num, struct ipt_nat_entry entry);
int ipt_filter_add_rule(struct net *net, u8 hook_num, struct ipt_filter_entry entry);
int ipt_filter_del_rule(struct net *net, u8 hook_num, struct ipt_filter_entry entry);
void ipt_nf_nat_rules_flush(struct net *net);
void ipt_nf_filter_rules_flush(struct net *net);


#endif
