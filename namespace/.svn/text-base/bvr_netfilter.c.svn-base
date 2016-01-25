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

#include <string.h>
#include <stdlib.h>


#include "bvr_namespace.h"
#include "bvr_errno.h"
#include "pal_malloc.h"
#include "pal_skb.h"
#include "pal_slab.h"
#include "pal_spinlock.h"
#include "pal_vnic.h"

#include "bvr_netfilter.h"
#include "pal_utils.h"
#include "logger.h"
//#include "hash.h"
/*nf hooks global variable, should read mostly*/
struct pal_list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];
/*pal slab*/
struct pal_slab *g_xt_table_slab = NULL;
struct pal_slab *g_xt_filter_table_slab = NULL;
struct pal_slab *g_xt_nat_table_slab = NULL;
struct pal_slab *g_ipt_nat_entry_slab = NULL;
struct pal_slab *g_ipt_filter_entry_slab = NULL;
struct pal_slab *g_ipt_filter_mask_slab = NULL;


/*
 * @brief: register a xt_table, used when init xt_table
 * @return xt_table if success ,return NULL  for error
 */
static struct xt_table *ipt_register_table(const struct xt_table *table)
{
    u32 i, j;
    struct xt_table *new_table = pal_slab_alloc(g_xt_table_slab);

    if (new_table == NULL) {
        return NULL;
    }

    strcpy(new_table->name, table->name);
    new_table->valid_hooks = table->valid_hooks;
    new_table->af = table->af;
    new_table->private = NULL;

    if (!strcmp(new_table->name, "nat")) {
        new_table->private = pal_slab_alloc(g_xt_nat_table_slab);
        if (new_table->private == NULL) {
            goto free_xt;
        }
        struct xt_nat_table *nat_table = (struct xt_nat_table *)new_table->private;

        for (i = 0; i < NF_MAX_HOOKS; i++) {
            nat_table->table[i].rule_num = 0;
            nat_table->table[i].rule_mask = NAT_TABLE_MASK;
            for (j = 0; j < NAT_TABLE_SIZE; j++) {
                PAL_INIT_HLIST_HEAD(&nat_table->table[i].nat_hmap[j]);
            }
        }
    }else if (!strcmp(new_table->name, "filter")) {
        new_table->private = pal_slab_alloc(g_xt_filter_table_slab);
        if (new_table->private == NULL) {
            goto free_xt;
        }

        struct xt_filter_table *filter_table = (struct xt_filter_table *)new_table->private;
        for (i = 0; i < NF_MAX_HOOKS; i++) {
            PAL_INIT_LIST_HEAD(&filter_table->table[i].mask_list);
            BVR_DEBUG("we have initialize the mask list add %p\n",&filter_table->table[i].mask_list);
            filter_table->table[i].rule_num = 0;
            filter_table->table[i].rule_mask = FILTER_TABLE_MASK;
            for (j = 0; j < FILTER_TABLE_SIZE; j++) {
                PAL_INIT_HLIST_HEAD(&filter_table->table[i].filter_hmap[j]);
            }
        }
    }else {
        /*only nat and filter table support*/
        goto free_xt;
    }
    return new_table;
free_xt:
    pal_slab_free(new_table);
    return NULL;
}


#define NAT_VALID_HOOKS ((1 << (NF_PREROUTING)) | (1 << (NF_POSTROUTING)))
#define FILTER_VALID_HOOKS ((1 << (NF_FORWARDING)) | (1 << (NF_PREROUTING)) | (1 << (NF_POSTROUTING)))

/*static table for register*/
static const struct xt_table nat = {
    .name = NAT_TABLE,
    .valid_hooks = NAT_VALID_HOOKS,
    .af = NFPROTO_IPV4,
};

static const struct xt_table filter = {
    .name = FILTER_TABLE,
    .valid_hooks = FILTER_VALID_HOOKS,
    .af = NFPROTO_IPV4,
};


/*
 * @brief: netfilter init function pernet
 * @return 0 for success ,return -1 for error
 */
static int nf_net_init(struct net *net)
{
    BVR_DEBUG("initialize the netfilter module for net %s\n",net->name);
    net->filter = ipt_register_table(&filter);
    BVR_DEBUG("filter table %p\n",net->filter->private);
    if (!net->filter)
        goto err;
    net->nat = ipt_register_table(&nat);
    if (!net->nat)
        goto free_filter;
    BVR_DEBUG("nat table %p\n",net->nat->private);
    return 0;
free_filter:
    pal_slab_free(net->filter->private);
    pal_slab_free(net->filter);
err:
    return -1;
}

/*
 * @brief: netfilter exit function pernet
 * @return void
 */
static void nf_net_exit(struct net *net)
{
    BVR_DEBUG("destroy the netfilter module for net %s\n",net->name);
    u32 i = 0, j = 0;
    /*release rwlock as soon as possible*/
    rte_rwlock_write_lock(&net->net_lock);
    struct xt_table *filter = net->filter;
    struct xt_table *nat = net->nat;
    net->filter = NULL;
    net->nat = NULL;
    rte_rwlock_write_unlock(&net->net_lock);

    /*filter and nat table can't be NULL before destroy them*/
    ASSERT((filter != NULL) && (nat != NULL));

    struct xt_filter_table *filter_table = (struct xt_filter_table *)filter->private;
    struct xt_nat_table *nat_table = (struct xt_nat_table *)nat->private;
    BVR_DEBUG("filter table %p, nat table %p\n",filter_table,nat_table);

    /*filter and nat rule table can't be NULL before destroy them*/
    ASSERT((filter_table != NULL) && (nat_table != NULL))
    struct ipt_flow_mask *pos = NULL, *next = NULL;
    struct ipt_filter_entry *fpos = NULL;
    struct ipt_nat_entry *npos = NULL;
    struct pal_hlist_node *node = NULL, *node1 = NULL;
    /*delete all rules in filter rule table*/
    for(i = 0; i < NF_MAX_HOOKS; i++)
    {

        pal_list_for_each_entry_safe(pos, next, &filter_table->table[i].mask_list, list)
        {
            pal_list_del(&pos->list);
            pal_slab_free(pos);
        }

        for (j = 0; j < FILTER_TABLE_SIZE; j++)
        {
            pal_hlist_for_each_entry_safe(fpos, node, node1, &filter_table->table[i].filter_hmap[j], hlist)
            {
                pal_hlist_del(&fpos->hlist);
                pal_slab_free(fpos);
            }
        }
    }
    pal_slab_free(filter->private);
    pal_slab_free(filter);

    /*delete all rules in nat rule table*/
    for(i = 0; i < NF_MAX_HOOKS; i++)
    {
        for (j = 0; j < NAT_TABLE_SIZE; j++)
        {
            pal_hlist_for_each_entry_safe(npos, node, node1, &nat_table->table[i].nat_hmap[j], hlist)
            {
                pal_hlist_del(&npos->hlist);
                pal_slab_free(npos);
            }
        }
    }
    pal_slab_free(nat->private); //xt_nat_info need mempool
    pal_slab_free(nat);
}

/*provide for bvrouter as netfilter subsystem init and exit*/
struct pernet_operation nf_net_ops = {
    .init = nf_net_init,
    .exit = nf_net_exit,
};




static struct ipt_nat_entry *__ipt_nat_hit_rule(struct xt_nat_table *nat_table, u8 hook_num, u32 ip)
{
    u32 key = nn_hash_4byte(ip) & nat_table->table[hook_num].rule_mask;
    struct ipt_nat_entry *t = NULL;
    struct pal_hlist_node *pos = NULL;
    struct pal_hlist_head *head = &nat_table->table[hook_num].nat_hmap[key];

    pal_hlist_for_each_entry(t, pos, head, hlist)
    {
        if (t->orig_ip == ip)
            return t;
    }
    return NULL;
}

/*
 * @brief: if hit the rule.return nat rule
 * @return nat rule or NULL
 */
static struct ipt_nat_entry *ipt_nat_hit_rule(struct xt_table *table, u8 hook_num, u32 ip)
{
    struct xt_nat_table *nat_table = (struct xt_nat_table *)table->private;

     /*nat_table can be NULL ,when destroy nat table,
     but haven't free the net.pkt may get in the net,and
     lookup nat table. when this happened return NULL,dataplane
     will drop the pkt.*/
    if (nat_table == NULL) {
        return NULL;
    }

    return __ipt_nat_hit_rule(nat_table, hook_num, ip);
}


/*
 * @brief: it's different from hit rule. for hit rule, we just compare the
 *         original ip. find rule we should compare nat ip and target also.
 * @return nat rule or NULL
 */
static struct ipt_nat_entry *__ipt_nat_find_rule(struct xt_nat_table *nat_table, u8 hook_num, struct ipt_nat_entry *entry)
{
    struct ipt_nat_entry *t;
    struct pal_hlist_node *pos;
    u32 key = nn_hash_4byte(entry->orig_ip) & nat_table->table[hook_num].rule_mask;
    struct pal_hlist_head *head = &nat_table->table[hook_num].nat_hmap[key];

    pal_hlist_for_each_entry(t, pos, head, hlist)
    {
        BVR_DEBUG("get in hlist t->oip %x,t->nat ip %x\n",t->orig_ip,t->nat_ip);
        if ((t->orig_ip == entry->orig_ip)) {
            //&& (t->nat_ip == entry->nat_ip)
            //&& (t->nat_target == entry->nat_target))
            /*delete nat rule by orignal ip*/
            return t;
        }
    }
    return NULL;
}


__unused static struct ipt_nat_entry * ipt_nat_find_rule(struct xt_table *table, u8 hook_num, struct ipt_nat_entry *entry)
{
    struct xt_nat_table *nat_table = (struct xt_nat_table *)table->private;

    ASSERT(nat_table != NULL);

    return __ipt_nat_find_rule(nat_table, hook_num, entry);
}


static void __ipt_nat_insert_rule(struct xt_nat_table *nat_table, u8 hook_num, struct ipt_nat_entry * entry)
{
    u32 key = nn_hash_4byte(entry->orig_ip) & nat_table->table[hook_num].rule_mask;
    nat_table->table[hook_num].rule_num++;

    pal_hlist_add_head(&entry->hlist, &nat_table->table[hook_num].nat_hmap[key]);

}


static void __ipt_nat_del_rule(struct ipt_nat_entry *entry)
{
    pal_hlist_del(&entry->hlist);
    pal_slab_free(entry);
}


/**
 * @brief __ipt_nat_get_conflicting_rule - Return the nat rule which conflict with @new_entry.
 *                                         Conflict means same floating IP,
 *                                         in other words, orig_ip of dnat or nat_ip of snat.
 * @param nat_table - Table of all nat rules.
 * @param hook_num - Hook num which locates the specified nat hash map.
 * @param new_entry - The new nat rule.
 * @return - NULL if there is no conflict, otherwise the conflicting #ipt_nat_entry
 */
static struct ipt_nat_entry *__ipt_nat_get_conflicting_rule(
        struct xt_nat_table *nat_table,
        u8 hook_num,
        struct ipt_nat_entry new_entry) {
    u32 key;
    struct ipt_nat_entry *t = NULL;
    struct pal_hlist_node *pos = NULL;
    struct pal_hlist_head *head = NULL;

    for (key = 0; key < NAT_TABLE_SIZE; key++) {
        head = &nat_table->table[hook_num].nat_hmap[key];
        pal_hlist_for_each_entry(t, pos, head, hlist)
        {
            if (t->orig_ip == new_entry.orig_ip) {
                BVR_WARNING("ip snat rule already exist, original ip "NIPQUAD_FMT", overwrite it\n",
                    NIPQUAD(new_entry.orig_ip));
                return t;
            }
            if (t->nat_ip == new_entry.nat_ip) {
                BVR_WARNING("ip dnat rule already exist, nat ip "NIPQUAD_FMT", overwrite it\n",
                    NIPQUAD(new_entry.nat_ip));
                return t;
            }
        }
    }
    return NULL;
}


/*always insert into the list tail,we need to get lock*/
int ipt_nat_insert_rule(struct net *net, u8 hook_num, struct ipt_nat_entry entry)
{
    struct xt_nat_table *nat_table = (struct xt_nat_table *)net->nat->private;
    struct ipt_nat_entry *entry_add = NULL;
    /*never got a NULL nat table here*/
    ASSERT(nat_table != NULL)

    if (!get_bit(net->nat->valid_hooks, hook_num)) {
        BVR_WARNING("hook_num is not valid\n");
        return -NN_EINVAL;
    }
    if (((entry.nat_target == NF_SNAT) && (hook_num != NF_POSTROUTING))
        || ((entry.nat_target == NF_DNAT) && (hook_num != NF_PREROUTING))) {
        BVR_WARNING("rule target is not vaild\n");
        return -NN_EINVAL;
        //return error;
    }

    if ((entry_add = __ipt_nat_get_conflicting_rule(nat_table, hook_num, entry)))
    {
        /* If there is an conflicting nat rule, delete it first */
        nat_table->table[hook_num].rule_num--;
        pal_rwlock_write_lock(&net->net_lock);
        __ipt_nat_del_rule(entry_add);
        pal_rwlock_write_unlock(&net->net_lock);
    }
    /*maybe should use pal slab*/
    entry_add = pal_slab_alloc(g_ipt_nat_entry_slab);
    if (!entry_add)
    {
        BVR_WARNING("memory is runing out\n");
        return -NN_ENOMEM;
    }
    *entry_add = entry;
    memset(&entry_add->counter, 0, sizeof(entry_add->counter));
    pal_rwlock_write_lock(&net->net_lock);
    __ipt_nat_insert_rule(nat_table, hook_num, entry_add);
    pal_rwlock_write_unlock(&net->net_lock);

    return 0;
}


/*
 * @brief: delete a nat rule, entry is only a union for params
 * @return 0 for success, error number for error
 */
int ipt_nat_del_rule(struct net *net, u8 hook_num, struct ipt_nat_entry entry)
{

    struct xt_nat_table *nat_table = (struct xt_nat_table *)net->nat->private;
    struct ipt_nat_entry *entry_del = NULL;
    ASSERT(nat_table != NULL);

    if (!get_bit(net->nat->valid_hooks, hook_num)) {
        //return error
        return -NN_EINVAL;
    }
    #if 0
    if (((entry.nat_target == NF_SNAT) && (hook_num != NF_POSTROUTING))
        || ((entry.nat_target == NF_DNAT) && (hook_num != NF_PREROUTING)))
    {
        return -NN_EINVAL;
        //return error
    }
    #endif
    if ((entry_del = __ipt_nat_find_rule(nat_table, hook_num, &entry)) == NULL)
    {
        BVR_WARNING("no available nat rule find\n");
        return -NN_ENFNOTEXIST;
    }
    nat_table->table[hook_num].rule_num--;
    pal_rwlock_write_lock(&net->net_lock);
    __ipt_nat_del_rule(entry_del);
    pal_rwlock_write_unlock(&net->net_lock);
    return 0;

}


/*
 * @brief: find filter rule, that is used when add or delete a filter entry
 * @return filter rule or NULL
 */
static struct ipt_filter_entry *ipt_filter_find_rule(struct xt_table *table, u8 hook_num, struct ipt_filter_entry *entry)
{

    struct ipt_filter_entry *tmp = NULL;
    struct pal_hlist_node *pos = NULL;
    u32 key = 0;
    struct xt_filter_table *filter_table = (struct xt_filter_table *)table->private;

    ASSERT(filter_table != NULL);

    key = nn_filter_rule_hash(entry->key.sip, entry->key.dip, entry->key.proto) &
        filter_table->table[hook_num].rule_mask;
    struct pal_hlist_head *head = &filter_table->table[hook_num].filter_hmap[key];
    BVR_DEBUG("sip %u,dip %u.proto %u, key %u",entry->key.sip,entry->key.dip,entry->key.proto,key);
    pal_hlist_for_each_entry(tmp, pos, head, hlist)
    {
#ifdef TEST
           BVR_DEBUG("step in\n");
        if ((memcmp(&tmp->mask_value, &entry->mask_value, sizeof(entry->mask_value)) != 0))
            BVR_DEBUG("mask val\n");
        if (memcmp(&tmp->key, &entry->key, sizeof(entry->key)) != 0)
            BVR_DEBUG("key val\n");
        if (tmp->filter_target != entry->filter_target)
            BVR_DEBUG("tar val\n");

        if (tmp->priority != entry->priority)
            BVR_DEBUG("prio\n");

#endif

        if ((memcmp(&tmp->mask_value, &entry->mask_value, sizeof(entry->mask_value)) == 0) &&
                (memcmp(&tmp->key, &entry->key, sizeof(entry->key)) == 0) &&
                (tmp->filter_target == entry->filter_target) && (tmp->priority == entry->priority))
                return tmp;
    }

    return NULL;

}

/*add filter rule to hlist by priority*/
static int __ipt_filter_add_rule(struct xt_filter_table *filter_table, u8 hook_num, struct ipt_filter_entry *entry)
{
    u32 sip = 0, dip = 0, key = 0;
    u8 proto = 0;
    struct ipt_filter_entry *pos = NULL, *last = NULL;
    struct pal_hlist_node *node = NULL;
    struct pal_hlist_head *head = NULL;
    sip = entry->key.sip;
    dip = entry->key.dip;
    proto = entry->key.proto;

    key = nn_filter_rule_hash(sip, dip, proto) & filter_table->table[hook_num].rule_mask;
    filter_table->table[hook_num].rule_num++;
    head = &filter_table->table[hook_num].filter_hmap[key];

    BVR_DEBUG("sip %u,dip %u.proto %u, key %u",entry->key.sip,entry->key.dip,entry->key.proto,key);
    if (pal_hlist_empty(head)) {
        /*empty hlist, we add at head*/
        pal_hlist_add_head(&entry->hlist, head);
    }else {

        pal_hlist_for_each_entry(pos, node, head, hlist)
        {
            if (pos->priority > entry->priority) {
                break;
            }
            last = pos;
        }
        if (last) {
            /*not the highest priority add after last*/
            pal_hlist_add_after(&last->hlist, &entry->hlist);
        }
        else {
            /*highest priority add before pos*/
            pal_hlist_add_before(&entry->hlist, &pos->hlist);
        }
    }

    return 0;
}


static int __ipt_filter_del_rule(struct ipt_filter_entry *entry)
{
    pal_hlist_del(&entry->hlist);
    pal_slab_free(entry);
    return 0;
}

/*
 * @brief: add a filter rule, entry is only a union for params
 * @return 0 for success, error number for error
 */
int ipt_filter_add_rule(struct net *net, u8 hook_num, struct ipt_filter_entry entry)
{
    struct xt_filter_table *filter_table = (struct xt_filter_table *)net->filter->private;

    ASSERT(filter_table != NULL);

    if (!get_bit(net->filter->valid_hooks, hook_num)) {
        BVR_WARNING("no valid hooks for filter\n");
        return -NN_EINVAL;
    }

    if ((entry.filter_target != NF_DROP) && (entry.filter_target != NF_ACCEPT) &&
        (entry.filter_target != NF_DUMP))
    {
        BVR_WARNING("filter target error %d\n",entry.filter_target);
        return -NN_EINVAL;
    }
    struct filter_rule_table *mask_table = &filter_table->table[hook_num];
    struct ipt_flow_mask *mask;
    struct ipt_filter_entry *entry_add = pal_slab_alloc(g_ipt_filter_entry_slab);

    if (!entry_add) {
        BVR_WARNING("alloc ip filter entry error\n");
        return -NN_ENOMEM;
    }
    *entry_add = entry;
    memset(&entry_add->counter, 0, sizeof(entry_add->counter));
    BVR_DEBUG("sport %d, sport %d\n",entry_add->key.sport[1], entry.key.sport[1]);
    pal_list_for_each_entry(mask, &mask_table->mask_list, list)
    {
        if(memcmp(&mask->mask, &entry_add->mask_value, sizeof(mask->mask)) == 0)
        {
            mask->ref_cnt++;
            entry_add->mask = mask;
            pal_rwlock_write_lock(&net->net_lock);
            __ipt_filter_add_rule(filter_table, hook_num, entry_add);
            pal_rwlock_write_unlock(&net->net_lock);
            return 0;
        }
    }
    mask = pal_slab_alloc(g_ipt_filter_mask_slab);
    if (!mask) {
        BVR_WARNING("alloc ip mask error\n");
        __ipt_filter_del_rule(entry_add);
        return -NN_ENOMEM;
    }

    mask->mask = entry_add->mask_value;
    entry_add->mask = mask;
    mask->ref_cnt = 1;

    pal_rwlock_write_lock(&net->net_lock);
    pal_list_add(&mask->list, &mask_table->mask_list);
    __ipt_filter_add_rule(filter_table, hook_num, entry_add);
    pal_rwlock_write_unlock(&net->net_lock);
    return 0;
}

/*
 * @brief: delete a filter rule, entry is only a union for params
 * @return 0 for success, error number for error
 */
int ipt_filter_del_rule(struct net *net, u8 hook_num, struct ipt_filter_entry entry)
{
    struct xt_filter_table *filter_table = (struct xt_filter_table *)net->filter->private;
    ASSERT(filter_table != NULL);
    struct ipt_filter_entry *entry_del = NULL;

    /*make some safe check*/
    if (!get_bit(net->filter->valid_hooks, hook_num)) {
        return -NN_EINVAL;
    }

    if ((entry.filter_target != NF_DROP) && (entry.filter_target != NF_ACCEPT)
        && (entry.filter_target != NF_DUMP))
    {
        return -NN_EINVAL;
    }

    if ((entry_del = ipt_filter_find_rule(net->filter, hook_num, &entry)) == NULL)
    {
        BVR_WARNING("no filter entry found\n");
        return -NN_ENFNOTEXIST;
    }

    entry_del->mask->ref_cnt--;

    if(entry_del->mask->ref_cnt == 0) {
        BVR_DEBUG("del mask");
        pal_rwlock_write_lock(&net->net_lock);
        pal_list_del(&entry_del->mask->list);
        pal_rwlock_write_unlock(&net->net_lock);
        pal_slab_free(entry_del->mask);
    }

    filter_table->table[hook_num].rule_num--;
    pal_rwlock_write_lock(&net->net_lock);
    __ipt_filter_del_rule(entry_del);
    pal_rwlock_write_unlock(&net->net_lock);
    return 0;

}

/*
 * @brief: flush all nat rules in nat table
 * @return void
 */
void ipt_nf_nat_rules_flush(struct net *net)
{
    u32 i = 0, j = 0;
    /*we really lock the net lock for a long time£¬
      we'd better not flush tables too offen*/
    rte_rwlock_write_lock(&net->net_lock);
    struct xt_table *nat = net->nat;

    /*filter and nat table can't be NULL before destroy them*/
    ASSERT((nat != NULL));
    struct xt_nat_table *nat_table = (struct xt_nat_table *)nat->private;

    /*filter and nat rule table can't be NULL before destroy them*/
    ASSERT((nat_table != NULL));

    struct pal_hlist_node *node = NULL, *node1 = NULL;
    struct ipt_nat_entry *npos = NULL;

    /*delete all rules in nat rule table*/
    for(i = 0; i < NF_MAX_HOOKS; i++)
    {
        for (j = 0; j < NAT_TABLE_SIZE; j++)
        {
            pal_hlist_for_each_entry_safe(npos, node, node1, &nat_table->table[i].nat_hmap[j], hlist)
            {
                pal_hlist_del(&npos->hlist);
                pal_slab_free(npos);
            }
        }
    }
    rte_rwlock_write_unlock(&net->net_lock);
}

/*
 * @brief: flush all filter rules in nat table
 * @return void
 */
void ipt_nf_filter_rules_flush(struct net *net)
{
    u32 i = 0, j = 0;
    /*we really lock the net lock for a long time£¬
      we'd better not flush tables too offen*/
    rte_rwlock_write_lock(&net->net_lock);
    struct xt_table *filter = net->filter;

    /*filter table can't be NULL before destroy them*/
    ASSERT((filter != NULL));
    struct xt_filter_table *filter_table = (struct xt_filter_table *)filter->private;

    /*filter rule table can't be NULL before destroy them*/
    ASSERT((filter_table != NULL));

    struct ipt_flow_mask *pos = NULL, *next = NULL;
    struct ipt_filter_entry *fpos = NULL;
    struct pal_hlist_node *node = NULL, *node1 = NULL;

    /*delete all rules in filter rule table*/
    for(i = 0; i < NF_MAX_HOOKS; i++)
    {

        pal_list_for_each_entry_safe(pos, next, &filter_table->table[i].mask_list, list)
        {
            pal_list_del(&pos->list);
            pal_slab_free(pos);
        }

        for (j = 0; j < FILTER_TABLE_SIZE; j++)
        {
            pal_hlist_for_each_entry_safe(fpos, node, node1, &filter_table->table[i].filter_hmap[j], hlist)
            {
                pal_hlist_del(&fpos->hlist);
                pal_slab_free(fpos);
            }
        }
    }
    rte_rwlock_write_unlock(&net->net_lock);
}





/*
 * @brief: test if hit a filter rule, used for datapath
 * @return ipt_filter_entry for success, NULL for error
 */
static struct ipt_filter_entry *ipt_filter_hit_rule(struct xt_table *table, u8 hook_num, struct sk_buff *skb)
{

    struct ip_hdr *iph = skb_ip_header(skb);
    struct tcp_hdr *tcph = NULL;
    struct udp_hdr *udph = NULL;
    struct icmp_hdr *icmph = NULL;
    u32 hdr_len;
    u16 sport;
    u16 dport;
    u32 key;

    u32 sip = iph->saddr;
    u32 dip = iph->daddr;
    u8 is_syn = 0;
    u8 is_req = 0;
    u8 is_udp = 0;

    switch (iph->protocol) {
        case PAL_IPPROTO_TCP:
            tcph = skb_l4_header(skb);
            hdr_len = tcph->doff << 2;
            if (likely(pskb_may_pull(skb, hdr_len))) {
                sport = tcph->source;
                dport = tcph->dest;
                is_syn = tcph->syn && (!tcph->ack);
            }else {
                return NULL;
            }
            break;
        case PAL_IPPROTO_UDP:
            udph = skb_l4_header(skb);
            hdr_len = sizeof(*udph);
            is_udp = 1;
            if (likely(pskb_may_pull(skb, hdr_len))) {
                sport = udph->source;
                dport = udph->dest;
            }else {
                return NULL;
            }
            break;
         case PAL_IPPROTO_ICMP:
            icmph = skb_l4_header(skb);
            hdr_len = sizeof(*icmph);
            /*icmp sport and dport set to 0*/
            sport = 0;
            dport = 0;
            if (likely(pskb_may_pull(skb, hdr_len))) {
                is_req = (icmph->type == ICMP_ECHO) ? 1 : 0;
            }else {
                return NULL;
            }
            /*no pull, no push*/
            break;
         default:
            /*only filter icmp,tcp,udp*/
            return NULL;
    }

    struct xt_filter_table *filter_table = (struct xt_filter_table *)table->private;

    if (filter_table == NULL)
        return NULL;

    struct ipt_flow_mask *mask = NULL;
    struct ipt_filter_entry *tmp = NULL, *result = NULL;
    struct pal_hlist_node *pos = NULL;

    pal_list_for_each_entry(mask, &filter_table->table[hook_num].mask_list, list)
    {
        u8 proto = mask->mask.proto ? iph->protocol : 0;
        key = nn_filter_rule_hash(sip & mask->mask.sip, dip & mask->mask.dip,
            proto) & filter_table->table[hook_num].rule_mask;

        struct pal_hlist_head *head = &filter_table->table[hook_num].filter_hmap[key];

        pal_hlist_for_each_entry(tmp, pos, head, hlist)
        {
            if((tmp->mask == mask) && ((sip & mask->mask.sip) == tmp->key.sip)
                && ((dip & mask->mask.dip) == tmp->key.dip) &&
                (proto  == tmp->key.proto)) {
                /*port range make sense only for udp and tcp pkts*/
                if (mask->mask.sport) {
                    if (ntohs(sport) < tmp->key.sport[0] || ntohs(sport) > tmp->key.sport[1])
                        continue;
                }
                if (mask->mask.dport) {
                    if (ntohs(dport) < tmp->key.dport[0] || ntohs(dport) > tmp->key.dport[1])
                        continue;
                }

                if(result == NULL) {
                    result = tmp;
                }
                else if(result->priority > tmp->priority)
                {
                    result = tmp;
                }
            }
        }
    }
    /*directionary filter only effect on DROP entry*/
    if (result != NULL) {
        if (result->dir && result->filter_target == NF_DROP) {
            if (is_syn || is_req || is_udp) {
                return result;
            }else {
                return NULL;
            }
        }
    }

    return result;

}


#define ASM
#ifdef ASM
static inline unsigned short from32to16(unsigned a)
{
    unsigned short b = a >> 16;
    asm("addw %w2,%w0\n\t"
        "adcw $0,%w0\n"
        : "=r" (b)
        : "0" (b), "r" (a));
    return b;
}

static inline unsigned add32_with_carry(unsigned a, unsigned b)
{
    asm("addl %2,%0\n\t"
        "adcl $0,%0"
        : "=r" (a)
        : "0" (a), "r" (b));
    return a;
}


/*
 * Do a 64-bit checksum on an arbitrary memory area.
 * Returns a 32bit checksum.
 *
 * This isn't as time critical as it used to be because many NICs
 * do hardware checksumming these days.
 *
 * Things tried and found to not make it faster:
 * Manual Prefetching
 * Unrolling to an 128 bytes inner loop.
 * Using interleaving with more registers to break the carry chains.
 */
static unsigned do_csum(unsigned char *buff, unsigned len)
{
    unsigned odd, count;
    unsigned long result = 0;

    if (unlikely(len == 0))
        return result;
    odd = 1 & (unsigned long) buff;
    if (unlikely(odd)) {
        result = *buff << 8;
        len--;
        buff++;
    }
    count = len >> 1;       /* nr of 16-bit words.. */
    if (count) {
        if (2 & (unsigned long) buff) {
            result += *(unsigned short *)buff;
            count--;
            len -= 2;
            buff += 2;
        }
        count >>= 1;        /* nr of 32-bit words.. */
        if (count) {
            unsigned long zero;
            unsigned count64;
            if (4 & (unsigned long) buff) {
                result += *(unsigned int *) buff;
                count--;
                len -= 4;
                buff += 4;
            }
            count >>= 1;    /* nr of 64-bit words.. */

            /* main loop using 64byte blocks */
            zero = 0;
            count64 = count >> 3;
            while (count64) {
                asm("addq 0*8(%[src]),%[res]\n\t"
                    "adcq 1*8(%[src]),%[res]\n\t"
                    "adcq 2*8(%[src]),%[res]\n\t"
                    "adcq 3*8(%[src]),%[res]\n\t"
                    "adcq 4*8(%[src]),%[res]\n\t"
                    "adcq 5*8(%[src]),%[res]\n\t"
                    "adcq 6*8(%[src]),%[res]\n\t"
                    "adcq 7*8(%[src]),%[res]\n\t"
                    "adcq %[zero],%[res]"
                    : [res] "=r" (result)
                    : [src] "r" (buff), [zero] "r" (zero),
                    "[res]" (result));
                buff += 64;
                count64--;
            }

            /* last upto 7 8byte blocks */
            count %= 8;
            while (count) {
                asm("addq %1,%0\n\t"
                    "adcq %2,%0\n"
                        : "=r" (result)
                    : "m" (*(unsigned long *)buff),
                    "r" (zero),  "0" (result));
                --count;
                    buff += 8;
            }
            result = add32_with_carry(result>>32,
                          result&0xffffffff);

            if (len & 4) {
                result += *(unsigned int *) buff;
                buff += 4;
            }
        }
        if (len & 2) {
            result += *(unsigned short *) buff;
            buff += 2;
        }
    }
    if (len & 1)
        result += *buff;
    result = add32_with_carry(result>>32, result & 0xffffffff);
    if (unlikely(odd)) {
        result = from32to16(result);
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
    }
    return result;
}

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 64-bit boundary
 */
static u32 csum_partial(void *buff, int len, u32 sum)
{
    return (u32)add32_with_carry(do_csum(buff, len),
                        (u32)sum);
}


static inline u32 csum_unfold(u16 n)
{
    return (u32)n;
}

/*
 *  Fold a partial checksum
 */

static inline u16 csum_fold(u32 sum)
{
    asm("addl %1, %0        ;\n"
        "adcl $0xffff, %0   ;\n"
        : "=r" (sum)
        : "r" ((u32)sum << 16),
          "0" ((u32)sum & 0xffff0000));
    return (u16)(~(u32)sum >> 16);
}


static inline void csum_replace4(u16 *sum, u32 from, u32 to)
{
    u32 diff[] = { ~from, to };

    *sum = csum_fold(csum_partial(diff, sizeof(diff), ~csum_unfold(*sum)));
}

static inline void csum_replace2(u16 *sum, u16 from, u16 to)
{
    csum_replace4(sum, (u32)from, (u32)to);
}


#else


/*
 * Fold a partial checksum
 */
static inline u16 csum_fold(u32 csum)
{
    u32 sum = csum;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (u16)~sum;
}



static unsigned do_csum(const unsigned short *buff, unsigned len)
{
    /*do csum for 8 bytes*/
    unsigned result = 0;
    result += buff[0];
    result += buff[1];
    result += buff[2];
    result += buff[3];
    return result;
}



static inline u32 csum_unfold(u16 n)
{
    return (u32)n;
}

u32 csum_partial(const void *buff, int len, u32 wsum)
{
    /*do csum partial for 8 bytes and add to the wsum*/
    unsigned int sum = (unsigned int)wsum;
    unsigned int result = do_csum(buff, len);

    /* add in old sum, and carry.. */
    result += sum;
    if (sum > result)
        result += 1;
    return result;
}


static inline void csum_replace4(u16 *sum, u32 from, u32 to)
{
    u32 diff[] = { ~from, to };

    *sum = csum_fold(csum_partial(diff, 8, ~csum_unfold(*sum)));
}


static inline void csum_replace2(u16 *sum, u16 from, u16 to)
{
    csum_replace4(sum, (u32)from, (u32)to);
}


#endif

#define	BVR_IP_HDR_MF_SHIFT	13
//#define	BVR_IP_HDR_MF_FLAG	(1 << BVR_IP_HDR_MF_SHIFT)
#define	BVR_IP_HDR_OFFSET_MASK	((1 << BVR_IP_HDR_MF_SHIFT) - 1)

/*for ip fragment, only first frag need udp csum update*/
static int udpcsum_need_update(struct ip_hdr *iph)
{
    u16 offset = 0;
    u16 frag_off = ntohs(iph->frag_off);
    offset = (frag_off & BVR_IP_HDR_OFFSET_MASK);
    /*offset == 0, means not a ip fragment or the first fragment*/
    return (!offset);
}


/*
 * @brief: nat functions, used for datapath, use fast update csum funcion
 *          to update csum after nat.
 * @return NF_DROP or NF_ACCEPT
 */
static unsigned int fn_nat_fn(struct sk_buff *skb, struct ipt_nat_entry *entry)
{
    struct ip_hdr *iph = skb_ip_header(skb);

    if(entry->nat_target == NF_SNAT) {
        /*update csum for ip checksum*/
        csum_replace4(&iph->check, iph->saddr, entry->nat_ip);
        if (iph->protocol == PAL_IPPROTO_TCP) {
            struct tcp_hdr *tcph = skb_tcp_header(skb);
            /*make sure we can access tcp header*/
            if (likely(pskb_may_pull(skb, sizeof(*tcph)))) {
                /*update csum for pseudo header */
                csum_replace4(&tcph->check, iph->saddr, entry->nat_ip);
            }else {
                return NF_DROP;
            }

        } else if (iph->protocol == PAL_IPPROTO_UDP && udpcsum_need_update(iph))
        {
            struct udp_hdr *udph = skb_udp_header(skb);
            /*make sure we can access udp header*/
            if (udph->check != 0) {
                if (likely(pskb_may_pull(skb, sizeof(*udph)))) {
                    /*update csum for pseudo header */
                    csum_replace4(&udph->check, iph->saddr, entry->nat_ip);
                }else {
                    return NF_DROP;
                }
            }
        }

        BVR_DEBUG("snat sip from %s to %s\n",trans_ip(iph->saddr, 0), trans_ip(entry->nat_ip, 0));
        iph->saddr = entry->nat_ip;
         /*that depends*/
        //skb->snat_flag = 1;

    }
    else if(entry->nat_target == NF_DNAT) {

        csum_replace4(&iph->check, iph->daddr, entry->nat_ip);
        if (iph->protocol == PAL_IPPROTO_TCP) {
            struct tcp_hdr *tcph = skb_tcp_header(skb);
            if (pskb_may_pull(skb, sizeof(*tcph))) {
                csum_replace4(&tcph->check, iph->daddr, entry->nat_ip);
            }else {
                return NF_DROP;
            }

        } else if (iph->protocol == PAL_IPPROTO_UDP && udpcsum_need_update(iph))
        {
            struct udp_hdr *udph = skb_udp_header(skb);
            if (udph->check != 0) {
                if (pskb_may_pull(skb, sizeof(*udph))) {
                    csum_replace4(&udph->check, iph->daddr, entry->nat_ip);
                }else {
                    return NF_DROP;
                }
            }
        }
        BVR_DEBUG("dnat dip from %s to %s\n",trans_ip(iph->daddr, 0), trans_ip(entry->nat_ip, 0));
        iph->daddr = entry->nat_ip;
        /*that depends*/
        skb->dnat_flag = 1;
    }
    ADD_COUNTER(entry->counter, skb_len(skb), 1, rte_lcore_id());
 //   entry->hit_pkts++;
 //   entry->hit_bytes += skb_len(skb);
    return NF_ACCEPT;
}



/*
 * @brief: dnat in prerouting, used for datapath, use fast update csum funcion
 *          to update csum after nat.
 * @return NF_DROP or NF_ACCEPT
 */
static unsigned int fn_nat_pre(u8 hooknum, struct sk_buff* skb, struct vport *in,
                               __unused struct vport *out, __unused void *private_data)
{
    struct ip_hdr *iph = skb_ip_header(skb);
    if (in == NULL) {
        return NF_DROP;
    }
    struct net *net = dev_net(in);

    struct xt_table *table = net->nat;
    struct ipt_nat_entry *entry;

    /* Only do DNAT to packets from qg, i.e. packets to-south */
    if(in->vport_type != PHY_VPORT) {
        return NF_ACCEPT;
    }

    if (table == NULL) {
        return NF_DROP;
    }
    entry = ipt_nat_hit_rule(table, hooknum, iph->daddr);

    if(NULL == entry)
        return NF_ACCEPT;

    return fn_nat_fn(skb, entry);
}

struct nf_hook_ops nf_nat_pre_ops = {
    .hook = fn_nat_pre,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_PREROUTING,
    .priority = NF_IP_PRI_NAT_DST,

};

/*
 * @brief: snat in postrouting, used for datapath, use fast update csum funcion
 *          to update csum after nat.
 * @return NF_DROP or NF_ACCEPT
 */
static unsigned int fn_nat_post(u8 hooknum, struct sk_buff* skb, __unused struct vport *in,
                                struct vport *out, __unused void *private_data)
{
    struct ip_hdr *iph = skb_ip_header(skb);

    if (out == NULL) {
        return NF_DROP;
    }
    struct net *net = dev_net(out);

    struct xt_table *table = net->nat;
    struct ipt_nat_entry *entry;

    if (table == NULL) {
        return NF_DROP;
    }

    /* Only do SNAT to packets to qg, i.e. packets to-north */
    if (out->vport_type != PHY_VPORT) {
        return NF_ACCEPT;
    }

    entry = ipt_nat_hit_rule(table, hooknum, iph->saddr);
    if(NULL == entry)
        return NF_ACCEPT;
    return fn_nat_fn(skb, entry);

}


struct nf_hook_ops nf_nat_post_ops = {
    .hook = fn_nat_post,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_POSTROUTING,
    .priority = NF_IP_PRI_NAT_SRC,

};

/*
 * @brief: filter function in forwarding. used for datapath
 * @return NF_DROP or NF_ACCEPT
 */
static unsigned int fn_filter(u8 hooknum, struct sk_buff* skb, struct vport *in,
                              __unused struct vport *out, __unused void *private_data)
{
    if (in == NULL) {
        return NF_DROP;
    }
    struct net *net = dev_net(in);

    struct xt_table *table = net->filter;
    /*filter rule table can be NULL ,when destroy a filter table,
     but haven't free the net.pkt may get in the net,and
     lookup filter table. when this happened dataplane
     will drop the pkt.*/
     if (table == NULL) {
        return NF_DROP;
     }


    struct ipt_filter_entry *entry = NULL;

    entry = ipt_filter_hit_rule(table, hooknum, skb);
    if(NULL == entry) {
        return NF_ACCEPT;
    }
    /*should be optimized. for SMP it may lead cache reponse*/
    ADD_COUNTER(entry->counter, skb_len(skb), 1, rte_lcore_id());

    /*dump pkt*/
    struct ip_hdr *iph = skb_ip_header(skb);
    if (entry->filter_target == NF_DUMP) {
        skb_push(skb, (iph->ihl << 2) + sizeof(struct eth_hdr));
        if (pal_dump_pkt(skb, 2000)) {
            BVR_WARNING("pkt dump error\n");
        }
        skb_pull(skb, (iph->ihl << 2) + sizeof(struct eth_hdr));
    }

    return entry->filter_target;

}

struct nf_hook_ops nf_filter_ops = {
    .hook = fn_filter,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_FORWARDING,
    .priority = NF_IP_PRI_FILTER,

};


struct nf_hook_ops nf_pre_dump_ops = {
    .hook = fn_filter,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_PREROUTING,
    .priority = NF_IP_PRI_PRE_DUMP,

};

struct nf_hook_ops nf_post_dump_ops = {
    .hook = fn_filter,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_POSTROUTING,
    .priority = NF_IP_PRI_POST_DUMP,

};





/*only allow to register/unregister a hook function in the init time on the init core
,no need to use a lock to protect the nk_hook list*/
static int nf_register_hook(struct nf_hook_ops *reg)
{
    struct nf_hook_ops *pos = NULL;

    pal_list_for_each_entry(pos, &nf_hooks[reg->pf][reg->hooknum], list) {
        if (reg->priority < pos->priority)
            break;
    }
    pal_list_add(&reg->list,pos->list.prev);
    return 0;

}


static void __unused nf_unregister_hook(struct nf_hook_ops *reg)
{
    pal_list_del(&reg->list);
}

int nf_hook_iterate(u8 pf, u8 hook, struct sk_buff *skb,
         struct vport *in, struct vport *out,
         int (*okfn)(struct sk_buff *, struct vport *, struct vport *))
{
    struct nf_hook_ops *pos = NULL;
    int ret;
    pal_list_for_each_entry(pos, &nf_hooks[pf][hook], list) {
        if (pos->hook) {
            ret = pos->hook(hook, skb, in, out, pos->private_data);
            /*for drop pkt no need to get through other hooks*/
            if (ret == NF_DROP) {
                return NF_DROP;
            }
            /********
            if (ret == NF_ACCEPT) {

                return okfn(skb, in, out);
            }
            *********/
        }
    }
    /*call the callback at last*/
    return okfn(skb, in, out);
}


extern struct nf_hook_ops alg_ops;


/*call when bvrouter init*/
int nf_init(int numa_id)
{

    u32 i, j;
    for (i = 0;i < NFPROTO_NUMPROTO; i++)
    {
        for (j = 0; j < NF_MAX_HOOKS; j++)
        {
            PAL_INIT_LIST_HEAD(&nf_hooks[i][j]);
        }
    }
    /*register hook functions*/
    nf_register_hook(&nf_nat_pre_ops);
    nf_register_hook(&nf_nat_post_ops);
    nf_register_hook(&nf_filter_ops);
    nf_register_hook(&nf_pre_dump_ops);
    nf_register_hook(&nf_post_dump_ops);
    nf_register_hook(&alg_ops);

    /*create slab*/
    /*param numa should be numa id where worker running on(the same as phy port plugged in)*/
    g_xt_table_slab = pal_slab_create("xt_table", XT_TABLE_SLAB_SIZE,
        sizeof(struct xt_table), numa_id, 0);
    g_xt_nat_table_slab = pal_slab_create("xt_nat_table", XT_NAT_TABLE_SLAB_SIZE,
        sizeof(struct xt_nat_table), numa_id, 0);
    g_xt_filter_table_slab = pal_slab_create("xt_filter_table", XT_FILTER_TABLE_SLAB_SIZE,
        sizeof(struct xt_filter_table), numa_id, 0);
    g_ipt_nat_entry_slab = pal_slab_create("ipt_nat_entry", IPT_NAT_ENTRY_SLAB_SIZE,
        sizeof(struct ipt_nat_entry), numa_id, 0);
    g_ipt_filter_entry_slab = pal_slab_create("ipt_filter_entry", IPT_FILTER_ENTRY_SLAB_SIZE,
        sizeof(struct ipt_filter_entry), numa_id, 0);
    g_ipt_filter_mask_slab = pal_slab_create("ipt_filter_mask", IPT_FILTER_ENTRY_SLAB_SIZE,
        sizeof(struct ipt_flow_mask), numa_id, 0);

    if (g_xt_table_slab == NULL || g_xt_nat_table_slab == NULL || g_xt_filter_table_slab == NULL
        || g_ipt_nat_entry_slab == NULL || g_ipt_filter_entry_slab == NULL) {
        PAL_ERROR("netfilter init error\n");
        return -1;
    }
    return 0;

}

