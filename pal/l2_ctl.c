#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "pal_vxlan.h"
#include "pal_phy_vport.h"
#include "pal_ip_cell.h"
#include "pal_error.h"
#include "pal_l2_ctl.h"
#include "vtep.h"

static int _int_vport_add_ctl(char *vport_name,char *uuid,
	uint8_t *int_gw_mac,__be32 int_gw_ip, uint32_t prefix_len,uint32_t vni,void *private)
{
	int err;	
	/*create int vport and add to namespace*/	
	err = int_vport_add(vport_name,uuid,int_gw_mac,int_gw_ip,prefix_len,vni,private);
	return err;
}

/*1. create vxlan_vport*/
int int_vport_add_ctl(struct int_vport_entry *entry,void *private)
{
	int err;

	err = _int_vport_add_ctl(entry->vport_name,entry->uuid,entry->int_gw_mac,entry->int_gw_ip,
		entry->prefix_len,entry->vni,private);

	return err;
}

static int _phy_vport_add_ctl(char *vport_name, char *uuid,
			    const uint8_t *ext_gw_mac,__be32 ext_gw_ip,
			    uint32_t prefix_len,void *private)
{
	int err;
	/*create phy vport and add to namespace*/	
	err = phy_vport_add(vport_name,uuid,ext_gw_mac,ext_gw_ip,prefix_len,private);
	return err;
}

/*2. create phy_vport*/
int phy_vport_add_ctl(struct phy_vport_entry * entry,void *private)
{
	int err;

	mac_copy(entry->ext_gw_mac,get_vtep_mac());
	err = _phy_vport_add_ctl(entry->vport_name,entry->uuid,entry->ext_gw_mac,entry->ext_gw_ip,entry->prefix_len,private);

	return err;
}

/*3. delete vxlan_vport/phy_vport*/
int vport_delete_ctl(char *vport_name)
{
	int err;
	struct vport_net *vpnet = &vport_nets;
	struct vport *vp;
	
	if(strlen(vport_name) > VPORT_NAME_MAX)
		return -ENXIO;
	
	pal_spinlock_lock(&vpnet->hash_lock);
	vp= __find_vport_nolock(vport_name);
	if (vp) {
		if(vp->vport_type == VXLAN_VPORT){
			err = int_vport_delete(vpnet,(struct int_vport *)vp);
			if(err < 0)
				goto error;
		}else{
			err = phy_vport_delete(vpnet,(struct phy_vport *)vp);
			if(err < 0)
				goto error;
		}
		
	} else{ 
			err = -ENXIO;
			goto error;
	}
	pal_spinlock_unlock(&vpnet->hash_lock);	
	
	/*delete a default route entry*/
	return 0;

error:
	pal_spinlock_unlock(&vpnet->hash_lock);
	return err;
}

/*4. create floating ip*/
int floating_ip_add_ctl(__be32 floating_ip, 
				  char *vport_name)
{
	int err;
	struct vport_net *vpnet = &vport_nets;
	struct vport *vp;
	
	if(strlen(vport_name) > VPORT_NAME_MAX)
		return -ENXIO;
	
	pal_spinlock_lock(&vpnet->hash_lock);
	vp= __find_vport_nolock(vport_name);
	if(!vp||vp->vport_type!=PHY_VPORT){
		pal_spinlock_unlock(&vpnet->hash_lock);
		return -ESRCH;
	}else{
		err = ip_cell_add(floating_ip,FLOATING_IP,(struct phy_vport *)vp);
	}
	pal_spinlock_unlock(&vpnet->hash_lock);

	return err;
}

/*5. delete floating ip*/
int floating_ip_delete_ctl(__be32 floating_ip)
{
	return ip_cell_delete(floating_ip,FLOATING_IP);
}

/*6. show floating ip*/
int floating_ip_show_ctl(char *vport_name)
{
	struct vport_net *vpnet = &vport_nets;
	struct vport *vp;
	
	if(strlen(vport_name) > VPORT_NAME_MAX)
		return -ENXIO;
	
	pal_spinlock_lock(&vpnet->hash_lock);
	vp= __find_vport_nolock(vport_name);
	if(!vp||vp->vport_type!=PHY_VPORT){
		pal_spinlock_unlock(&vpnet->hash_lock);
		return -ESRCH;
	}else{
		show_floating_ip((struct phy_vport *)vp);
	}
	pal_spinlock_unlock(&vpnet->hash_lock);

	return 0;
}

static int _vxlan_fdb_add_ctl(uint32_t vni,
					 uint8_t *mac, __be32 remote_ip,
					__be16 remote_port)
{
	struct vxlan_dev *vdev;
	int err;	
	
	vdev = __find_vxlan_dev_nolock(vni);	
	if(!vdev){
		return -ESRCH;
	}else{
		err = vxlan_fdb_add(vdev,mac,remote_ip,remote_port,vni,0);	
	}
	
	return err;
}

/*7. create a fdb entry*/
int vxlan_fdb_add_ctl(uint32_t vni,struct fdb_entry *entry)
{
	int err;
	err = _vxlan_fdb_add_ctl(vni,entry->mac,entry->remote_ip,entry->remote_port);
	return err;
}

/*8. delete a fdb entry*/
int vxlan_fdb_delete_ctl(uint32_t vni,uint8_t *mac)
{
	struct vxlan_dev *vdev;
	int err;	
	
	vdev = __find_vxlan_dev_nolock(vni);	
	if(!vdev){
		return -ESRCH;
	}else{
		err = vxlan_fdb_delete(vdev,mac);	
	}
	
	return err;
}

/*9. Show forwarding table*/
int vxlan_fdb_show_ctl(uint32_t vni)
{
	struct vxlan_dev *vdev;
	
	vdev = __find_vxlan_dev_nolock(vni);	
	if(!vdev){
		return -ESRCH;
	}else{
		vxlan_fdb_show(vdev);
	}

	return 0;
}

/*10. get vxlan_dev*/
struct vxlan_dev * get_vxlan_dev(uint32_t vni)
{
	struct vxlan_dev *vdev;
	uint32_t index;
	
	index = get_hash_index_vni(vni);	
	read_lock_vxlan_dev(index);
	vdev = __find_vxlan_dev_nolock(vni);	
	read_unlock_vxlan_dev(index);

	return vdev;
}

/*11. delete all vport which belong to one namespace*/
void nd_delete_vport(void *nd)
{
	struct pal_list_head *head = get_nd_vport_head(nd); 
	delete_vport_from_list(head);
}

/*12. show route table entry*/
int route_entry_table_show_ctl(struct route_table *rt ,struct route_entry_table *reb)
{
	if(!rt || !reb)
		return -EFAULT;
	
	reb->len = 0;	
	pal_trie_traverse(rt,reb);
	return 0;
}

/*13. add arp entry*/
int vxlan_arp_add_ctl(uint32_t vni,struct vxlan_arp_entry *entry)
{
	struct vxlan_dev *vdev;
	int err;	
	
	vdev = __find_vxlan_dev_nolock(vni);	
	if(!vdev){
		return -ESRCH;
	}else{
		err = add_vxlan_arp_entry(vdev,entry);
	}
	
	return err;
}

/*14. delete arp entry*/
int vxlan_arp_delete_ctl(uint32_t vni,struct vxlan_arp_entry *entry)
{
	struct vxlan_dev *vdev;
	int err;	
	
	vdev = __find_vxlan_dev_nolock(vni);	
	if(!vdev){
		return -ESRCH;
	}else{
		err = del_vxlan_arp_entry(vdev,entry->ip);
	}
	
	return err;
}

