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

#include "bvr_namespace.h"
#include "bvr_errno.h"
#include "pal_malloc.h"
#include "pal_slab.h"
#include "pal_list.h"
#include "logger.h"
//#include "util.h"
/*only used in control plane, no lock to protect this hash table*/
struct pal_hlist_head namespace_hash_table[NAMESPACE_TABLE_SIZE]; //need to be initialized before used
//struct rte_rwlock_t namespace_hash_lock_array[NAMESPACE_TABLE_SIZE];//need to be initialized before used

/*only used in control plane, no lock to protect this list*/
static PAL_LIST_HEAD(pernet_list);

struct pal_slab *g_namespace_slab = NULL;


/*
 * @brief register a subsystem operation
 * @return 0 on success,
 */
int register_pernet_operations(struct pernet_operation *ops)
{
    pal_list_add_tail(&ops->list, &pernet_list);
    return 0;
}

/*
 * @brief unregister a subsystem operation
 */
void unregister_pernet_operations(struct pernet_operation *ops)
{
    pal_list_del(&ops->list);
}


/*
 * initialize each subsys registered
 */
static int net_install(struct net *net)
{
    struct pernet_operation *ops;
    int err = 0;
    pal_list_for_each_entry(ops, &pernet_list, list)
    {
        if (ops->init) {
            err = ops->init(net);
            if (err)
                goto undo;
        }
    }
    return 0;
undo:
    /*roll back for the subsys has already initialized*/
    pal_list_for_each_entry_continue_reverse(ops, &pernet_list, list)
    {
        if (ops->exit)
            ops->exit(net);
    }
    return -NN_ENETINSTALL;

}

/*
 * @brief: get a net by name,used by control thread,no lock protected
 * @return if found return net or NULL
 */

struct net *net_get(char *name)
{
    if (name == NULL) {
        return NULL;
    }
    u32 key;
    u32 len = strlen(name);
    struct net *net;
    struct pal_hlist_node *pos;
    if (len > NAMESPACE_NAME_SIZE) {
        return NULL;
    }

    key = nn_hash_str(name, len) & NAMESPACE_TABLE_MASK;

    pal_hlist_for_each_entry(net, pos, &namespace_hash_table[key], hlist)
    {
        /*find net by name*/
        if (!strcmp(net->name, name))
            return net;
    }

    return NULL;
}




/*
 * @brief: create a net named by param,used by control thread,no lock protected
 * @return 0 if success ,error number for error
 */

int net_create(char *name)
{
    if (name == NULL) {
        return -NN_EINVAL;
    }
    struct net *net;

    int error = 0;
    u32 key;

    net = net_get(name);
    /*make sure the net does not exist*/
    if(net) {
        /*net has exist*/
        BVR_WARNING("namespace %s has already exist\n", name);
        return -NN_ENSEXIST;
    }

    u32 len = strlen(name);
    if (len > NAMESPACE_NAME_SIZE)
    {
        BVR_WARNING("name length too long %d\n", len);
        return -NN_EOUTRANGE;
    }

    /*alloc memory for net*/
    net = pal_slab_alloc(g_namespace_slab);
    if(!net) {
        BVR_WARNING("namespace slab used up\n");
        return -NN_ENOMEM;
    }

    /*initialize net*/
    memset(net, 0, sizeof(*net));
    strncpy(net->name, name, NAMESPACE_NAME_SIZE);
    PAL_INIT_LIST_HEAD(&net->dev_base_head);

    atomic_set(&net->if_count, 0);
//    atomic_set(&net->user_count, 0);
    rte_rwlock_init(&net->net_lock);

    /*initialize subsys*/
    error = net_install(net);
    if (error)
    {
        pal_slab_free(net);
        return error;
    }

    key = nn_hash_str(name, len) & NAMESPACE_TABLE_MASK;

    /*add net to namespace hash table*/
    pal_hlist_add_head(&net->hlist, &namespace_hash_table[key]);

    return 0;
}


static inline int test_counter(u8 *counter)
{
    u32 i;
    for (i = 0; i < PAL_MAX_CPU; i++) {
        if(counter[i] != 0) {
            return 1;
        }

    }
    return 0;
}

/*
 * @brief: del a net by name,used by control thread,no lock protected
 * @return 0 if success ,error number for error
 */
int del_net(char *name)
{
    if (name == NULL) {
        return -NN_EINVAL;
    }
    struct net *net;
    struct pernet_operation *ops;
    u32 i;

    net = net_get(name);
    if (!net) {
        /*net has alreadly been deleted*/
        return -NN_ENSNOTEXIST;
    }

    pal_hlist_del(&net->hlist);

    /*before clean up subsys,hold the resource lock for write*/
    //rte_rwlock_write_lock(&net->net_lock);
    pal_list_for_each_entry(ops, &pernet_list, list) {
        if (ops->exit)
            ops->exit(net);
    }
    //rte_rwlock_write_unlock(&net->net_lock);

    /*dev has been deleted, if_count must be 0*/
    if (atomic_read(&net->if_count)) {
        BVR_ERROR("when delete a net, if count still not zero!!\n");
        return -NN_EREFCNT;
    }

    /*try five times to make sure the net can be free*/
    /*conisder user_count and net_lock up and down together,that means when we
     *hold write lock no pkt pass through this net.so maybe user_count no used
     *use the interface lock and net lock can make sure access security
     */
    for (i = 0; i < 5; i++) {
       // if (atomic_read(&net->user_count))
       if(test_counter(net->counter))
            usleep(10);
        else
            break;
    }

    if(i == 5) {
        BVR_ERROR("we try 5 times ,but still some pkt reference the net,may be something wrong\n");
        return -NN_EREFCNT;
    }
    pal_slab_free(net);
    return 0;

}


extern struct pernet_operation nf_net_ops;
extern struct pernet_operation arp_net_ops;
extern struct pernet_operation route_net_ops;
extern struct pernet_operation dev_net_ops;


/*called when bvrouter init*/
int namespace_init(int numa_id)
{
    u32 i;
    for (i = 0; i < NAMESPACE_TABLE_SIZE; i++) {
        PAL_INIT_HLIST_HEAD(&namespace_hash_table[i]);
    }
    /*register pernet operations*/
    register_pernet_operations(&nf_net_ops);
    register_pernet_operations(&arp_net_ops);
    register_pernet_operations(&dev_net_ops);
    /*route subsys must register after dev subsys*/
    register_pernet_operations(&route_net_ops);

    /*need more*/
    /*alloc slab*/
    /*param numa should be numa id where worker running on(the same as phy port plugged in)*/
    g_namespace_slab = pal_slab_create("namespace", NAMESPACE_SLAB_SIZE, sizeof(struct net), numa_id, 0);

    if (g_namespace_slab == NULL) {
        BVR_ERROR("init g_namespace_slab error\n");
        return -1;
    }
    return 0;
}

