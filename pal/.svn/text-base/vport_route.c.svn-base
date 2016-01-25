#include <string.h>
#include <stdint.h>
//#include <arpa/inet.h>

#include "pal_vport.h"
#include "pal_vxlan.h"
#include "pal_phy_vport.h"
#include "pal_list.h"
#include "pal_spinlock.h"
#include "route.h"
#include "vtep.h"

int add_route_to_nd(struct vport *dev,void *nd)
{
	uint32_t prefix,prefix_len,sip;
	int err;
	struct int_vport *vxlan_vp;
	struct phy_vport *phy_vp;
	struct route_table * t = get_nd_router_table(nd);

	if(!t){
		PAL_DEBUG("route_table is null\n");
		return -1;
	}

	if(dev->vport_type == VXLAN_VPORT){
		/*vxlan_vport*/
		vxlan_vp = (struct int_vport *)dev;
		sip = vxlan_vp->vp.vport_ip;
		prefix_len = vxlan_vp->vp.prefix_len;
        prefix = ip_to_prefix(sip, prefix_len);
	}else{
		/*phy_vport*/
		phy_vp = (struct phy_vport *)dev;
		sip = phy_vp->vp.vport_ip;
        /* phy_vport's connected route is default route */
        prefix_len = 0;
        prefix = inet_addr("0.0.0.0");
	}


	/*create local route and connect route*/
    err = route_add_local(t, sip, dev);
	if(err < 0)
		return -1;
    err = route_add_connected(t, prefix, prefix_len, sip, dev);
	if(err < 0){
        pal_route_del_local(t, sip);
		return -1;
	}

	return 0;
}

 int delete_route_from_nd(struct vport *dev,void *nd)
{
	uint32_t prefix,prefix_len,sip;
	struct route_table * t = get_nd_router_table(nd);

	if(!t){
		PAL_PANIC("null route_table!\n");
		return -1;
	}

	if(dev->vport_type == VXLAN_VPORT){
		struct int_vport *vxlan_vp = (struct int_vport *)dev;
		sip = vxlan_vp->vp.vport_ip;
		prefix_len = vxlan_vp->vp.prefix_len;
        prefix = ip_to_prefix(sip,prefix_len);
    }else {
        struct phy_vport *phy_vp = (struct phy_vport *)dev;
        sip = phy_vp->vp.vport_ip;
        prefix_len = 0;
        prefix = inet_addr("0.0.0.0");
    }

	pal_route_del_local(t,sip);
	pal_route_del_connect(t,prefix,prefix_len,sip);

	return 0;
}


