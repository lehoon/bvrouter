#include "pal_route.h"
#include "bvr_namespace.h"
#include <stdio.h>
#include "logger.h"
static int route_net_init(struct net *net)
{
    /*call pal api to alloc route table*/
    net->route_table = pal_rtable_new();

    if (net->route_table == NULL) {
        BVR_ERROR("run out of memory when alloc route table\n");
        return -1;
    }

    return 0;
}


static void route_net_exit(struct net *net)
{
    struct route_table *rtable;
    /*get route table, we release the lock as faster as we can
      maybe some pkts would see route table NULL,that doesn't
      matter, just drop those pkts, because this bvrouter is
      deleting*/
    rte_rwlock_write_lock(&net->net_lock);
    rtable = net->route_table;
    net->route_table = NULL;
    rte_rwlock_write_unlock(&net->net_lock);

    /*call pal api to destroy */
    pal_rtable_destroy(rtable);

}

/*this will be registered duaring net init*/
struct pernet_operation route_net_ops = {
    .init = route_net_init,
    .exit = route_net_exit,
};
