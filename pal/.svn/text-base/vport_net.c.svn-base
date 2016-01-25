#include <string.h>
#include <stdint.h>

#include "pal_vport.h"
#include "pal_vxlan.h"
#include "pal_phy_vport.h"
#include "pal_list.h"
#include "pal_spinlock.h"

struct vport_net vport_nets; 

/* Look up vport in vport_net, must lock held*/
struct vport *__find_vport_nolock(char *vport_name)
{
	struct vport *vp;	
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(vp,hnode,vport_head(&vport_nets,vport_name), hlist) {
		if (!strcmp(vp->vport_name,vport_name))
			return vp;
	}

	return NULL;
}

void delete_vport_from_list(struct pal_list_head *head)
{
	struct pal_list_head *element;
	struct vport_net *vpnet = &vport_nets;

	pal_spinlock_lock(&vpnet->hash_lock);
	/*delete all vport which belongs to one namespace*/
	while (!pal_list_empty(head)) {
		struct vport *vp;
		element = head->next;
		vp = pal_list_entry(element, struct vport, list_nd);
		if(vp->vport_type == VXLAN_VPORT){
			int_vport_delete(vpnet,(struct int_vport *)vp);
		}else{
			phy_vport_delete(vpnet,(struct phy_vport *)vp);
		}		
	}	
	pal_spinlock_unlock(&vpnet->hash_lock);
}

int find_vport_ip_from_list(struct pal_list_head *head,__be32 ip)
{	
	int find = 0;
	struct vport *vp;		

	if(!head)
		return 1;
	
	pal_list_for_each_entry(vp, head, list_nd){
		if(ip == vp->vport_ip){
			find = 1;
			break;
		}
	}	

	return find;
}

int vport_net_init(void)
{
	uint16_t h;
	struct vport_net *vpnet = &vport_nets;

	vpnet->addrcnt = 0;	
	pal_spinlock_init(&vpnet->hash_lock);	
	for (h = 0; h < VPORT_HASH_SIZE; ++h)
		PAL_INIT_HLIST_HEAD(&vpnet->vport_list[h]);
	
	return 0;
}

