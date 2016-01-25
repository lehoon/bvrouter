
#include "bvr_namespace.h"
#include <stdio.h>
#include "pal_list.h"
#include "pal_l2_ctl.h"

static int dev_net_init(struct net *net)
{
    /*so far,name space only keep interfaces in list*/
    PAL_INIT_LIST_HEAD(&net->dev_base_head);

    return 0;
}


static void dev_net_exit(struct net *net)
{
    /*net lock locked in this function*/
    nd_delete_vport(net);

}


/*dev_net_ops should be registered duaring net init*/
struct pernet_operation dev_net_ops = {
    .init = dev_net_init,
    .exit = dev_net_exit,
};
