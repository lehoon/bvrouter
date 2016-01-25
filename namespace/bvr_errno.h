#ifndef ERRNO_H
#define ERRNO_H

enum {
 //   NN_RESERVED     = 1
    NN_ENOMEM       = 1,    /*running out of memory*/
    NN_ENSEXIST     = 2,    /*namespace already not*/
    NN_ENSNOTEXIST  = 3,    /*namespace not exist*/
    NN_ENETINSTALL  = 4,    /*error when install net*/
    NN_EPARSECMD    = 5,    /*error when parse the json param*/
    NN_EREFCNT      = 6,    /*when free xx,but the reference count isn't zero*/
    NN_EINVAL       = 7,    /*invalid param*/
    NN_ENOSPACE     = 8,    /*no space*/
    NN_EOUTRANGE    = 9,    /*out of range*/
    NN_ENFEXIST     = 10,   /*netfilter rule exists*/
    NN_ENFNOTEXIST  = 11,   /*netfilter rule not exists*/
    NN_EIFNOTEXIST  = 12,   /*interface not exist*/
    NN_EIFEXIST     = 13,   /*interface exists*/
    NN_EIPEXIST     = 14,   /*floating ip exist*/
    NN_EIPNOTEXIST  = 15,   /*floating ip not exist*/
    NN_EARPEXIST    = 16,   /*arp exist*/
    NN_EARPNOTEXIST = 17,   /*arp not exist*/
    NN_EFDBEXIST    = 18,   /*fdb entry exist*/
    NN_EFDBNOTEXIST = 19,   /*fdb entry not exist*/
    NN_EEXCERR      = 20,   /*exec error*/
    NN_ERTIFNEXIST,         /*route to_port not exist*/
    NN_ERINVALPREFIX,       /*route invalid prefix*/
    NN_ERINVALMASK,         /*route invalid netmask*/
    NN_ERNODST,             /*route no neither nexthop nor to_port*/
    NN_ERCIDREXIST,         /*route conflicted*/
    NN_ERCIDRNEXIST,        /*route doesnt exist while deleting*/
    NN_ERGWUNREACHABLE,     /*route nexthop to no vport*/
    NN_ERGWONPHYPORT,       /*route nexthop on phy_vport(qg have no gateway)*/
    NN_ECMDID      ,        /**/
};
#endif
