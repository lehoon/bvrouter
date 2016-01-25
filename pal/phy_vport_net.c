#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "pal_phy_vport.h"
#include "pal_ip_cell.h"
#include "pal_error.h"
#include "pal_malloc.h"
#include "pal_slab.h"

struct phy_net phy_vport_net;

static struct pal_slab *phy_vport_slab = NULL;

/*hold the read lock which protect the phy_vport*/
void get_phy_vport(struct phy_vport *vport)
{
	uint32_t index;
	struct phy_net *phynet = &phy_vport_net;
	
	index = get_hash_index_ext_ip(vport->vp.vport_ip);
	pal_rwlock_read_lock(&phynet->hash_lock_array[index]);
}

/*Release the read lock which protect the phy_vport*/
void put_phy_vport(struct phy_vport *vport)
{
	uint32_t index;
	struct phy_net *phynet = &phy_vport_net;
	
	index = get_hash_index_ext_ip(vport->vp.vport_ip);
	pal_rwlock_read_unlock(&phynet->hash_lock_array[index]);
}

/* Look up phy_vport in phy_vport_net */
static struct phy_vport *__find_phy_vport_nolock(__be32 ext_gw_ip)
{
	struct phy_vport *vport;	
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(vport,hnode,phy_vport_head(&phy_vport_net,ext_gw_ip), hlist_phy_vport) {
		if (vport->vp.vport_ip == ext_gw_ip)
			return vport;
	}

	return NULL;
}

/* Add a new phy_vport -- assumes lock held */
static int __phy_vport_create(struct vport_net *vpnet,
				struct phy_net *phynet,
				const char *vport_name,char *uuid,
			    const uint8_t *ext_gw_mac,__be32 ext_gw_ip,
			    uint32_t prefix_len,void *nd)
{
	struct phy_vport *vp;

	vp= __find_phy_vport_nolock(ext_gw_ip);
	if (vp) {
			return -EEXIST;
	} else {
		if (phynet->addrmax && phynet->addrcnt >= phynet->addrmax)
			return -ENOSPC;

		PAL_DEBUG("add vport %pM -> %pI4\n", ext_gw_mac, &ext_gw_ip);
		vp = pal_slab_alloc(phy_vport_slab);
		if (!vp)
			return -ENOMEM;
		
	    vp->vp.vport_name = pal_malloc(strlen(vport_name) + 1);
		if (!vp->vp.vport_name){
			pal_slab_free(vp);
			return -ENOMEM;
		}

	    vp->vp.uuid= pal_malloc(strlen(uuid) + 1);
		if (!vp->vp.uuid){			
			pal_free(vp->vp.vport_name);
			pal_slab_free(vp);			
			return -ENOMEM;
		}

		vp->vp.vport_ip = ext_gw_ip;		
		vp->vp.prefix_len = (prefix_len != 0 && prefix_len < 32) ? prefix_len : 24;
		strcpy(vp->vp.vport_name, vport_name);		
		strcpy(vp->vp.uuid, uuid);
		memcpy(vp->vp.vport_eth_addr, ext_gw_mac, 6);

		vp->vp.vport_type = PHY_VPORT;
		vp->vp.vport_ops = &phy_vport_ops;

		/*init ext_gw_ip and ..*/
		if(vp->vp.vport_ops->init((struct vport*)vp) < 0)
			goto error;

		write_lock_namespace(nd);
		/*add to namespace*/
		if(add_vport_to_namespace((struct vport *)vp,nd) < 0){			
			write_unlock_namespace(nd);
			/*delete external gateway ip*/
			ip_cell_delete(vp->vp.vport_ip,EXT_GW_IP);
			goto error;
		}		
		write_unlock_namespace(nd);

		add_phy_vport_to_phy_net(phynet,vp);
		add_phy_vport_to_vport_net(vpnet,vp);

		/*now, data plane can use this vport*/
		vp->port_state = PHY_VPORT_USEING;
	}
	
	return 0;
	
error:	
	pal_free(vp->vp.uuid);
	pal_free(vp->vp.vport_name);
	pal_slab_free(vp);
	return -EPERM;
}

/* Add static entry  */
int phy_vport_add(char *vport_name,char *uuid,
			    const uint8_t *ext_gw_mac,__be32 ext_gw_ip,
			    uint32_t prefix_len,void *nd)
{
	int err;
	uint8_t index;
	struct phy_net *phynet = &phy_vport_net;
	struct vport_net *vpnet = &vport_nets;
	struct vport *vp;	
	struct pal_list_head *head; 
	
	if(!vport_name || !uuid)
		return -ENXIO;
	
	if(strlen(vport_name) > VPORT_NAME_MAX)
		return -ENXIO;
	
	if(strlen(uuid) > VPORT_UUID_LENGTH)
		return -ENXIO;

	if (!pal_is_valid_ether_addr(ext_gw_mac))
		return -ENXIO;
	
	pal_spinlock_lock(&vpnet->hash_lock);
	vp= __find_vport_nolock(vport_name);
	if (vp) {	
			pal_spinlock_unlock(&vpnet->hash_lock);
			return -EEXIST;
	} else {
		head = get_nd_vport_head(nd); 
		if(find_vport_ip_from_list(head,ext_gw_ip) == 1){
			PAL_DEBUG("repeat ip in the namespace %x!\n",ext_gw_ip);
			pal_spinlock_unlock(&vpnet->hash_lock);
			return -EEXIST;
		}
		index = get_hash_index_ext_ip(ext_gw_ip);
		pal_rwlock_write_lock(&phynet->hash_lock_array[index]);		
		err = __phy_vport_create(vpnet,phynet,vport_name,uuid,ext_gw_mac,ext_gw_ip,prefix_len,nd);			
		pal_rwlock_write_unlock(&phynet->hash_lock_array[index]);
	}	
	pal_spinlock_unlock(&vpnet->hash_lock);

	return err;
}

static void phy_vport_free(struct phy_vport *vp)
{
	if(vp) {
		if(vp->vp.vport_name)
			pal_free(vp->vp.vport_name);
		if(vp->vp.uuid)
			pal_free(vp->vp.uuid);
		pal_slab_free(vp);
	}
}

static void __phy_vport_destroy(struct vport_net *vpnet,struct phy_net *phynet, struct phy_vport *vp)
{
	PAL_DEBUG("delete phy vport %pM\n", vp->vport_cfg.ext_gw_eth_addr);
	
	vp->vp.vport_ops->close((struct vport *)vp);

	/*delete from namespace*/
	remove_vport_from_namespace((struct vport *)vp,vp->vp.private);
		
	remove_phy_vport_from_phy_net(phynet,vp);
	remove_phy_vport_from_vport_net(vpnet,vp);

	phy_vport_free(vp);
}

static void shrink_ip_cell(struct phy_vport *vport)
{
	struct pal_list_head *element;

	/*delete external gateway ip*/
	ip_cell_delete(vport->vp.vport_ip,EXT_GW_IP);

	/*delete all floating ip*/
	while (!pal_list_empty(&vport->floating_list)) {
		struct ip_cell *ipcell;
		element = vport->floating_list.next;
		ipcell = pal_list_entry(element, struct ip_cell, list);
		ip_cell_delete(ipcell->ip,FLOATING_IP);	
	}
}

static int get_phy_vport_use_count(struct phy_vport *vp)
{
	int core_id,count = 0;
	
	for(core_id = 0; core_id < MAX_CORE_NUM; core_id++){
		count += vp->use_count[core_id];
	}
	
	return count;
}

/* 
 * Wait for a phy port .
 * When a phy_port->count equal to 1, get lock and return
 */
static void wait_on_phy_port(struct vport_net *vpnet,struct phy_net *phynet,
	struct phy_vport *vp)
{	
	uint8_t index;	
	do {
		if (get_phy_vport_use_count(vp) == 0)
			break;
		usleep(1);
	} while (1);
	index = get_hash_index_ext_ip(vp->vp.vport_ip);
	
	pal_spinlock_lock(&vpnet->hash_lock); 
	pal_rwlock_write_lock(&phynet->hash_lock_array[index]);		
}

/*
* delete a phy_vport, and vpnet->hash_lock must be held 
*/
int phy_vport_delete(struct vport_net *vpnet,struct phy_vport *vp)
{
	int err = -ENOENT;
	int count;	
	uint8_t index;	
	void *nd;
	struct phy_net *phynet = &phy_vport_net;

	index = get_hash_index_ext_ip(vp->vp.vport_ip);
	
	pal_rwlock_write_lock(&phynet->hash_lock_array[index]);
	if(vp->port_state == PHY_VPORT_DELETEING){
		err = -EIO;
		pal_rwlock_write_unlock(&phynet->hash_lock_array[index]);
		return err;
	}

	vp->port_state = PHY_VPORT_DELETEING;

	shrink_ip_cell(vp);
	
	nd = vp->vp.private;
	count = get_phy_vport_use_count(vp);
	if(!count){
		write_lock_namespace(nd);
		__phy_vport_destroy(vpnet,phynet,vp);		
		write_unlock_namespace(nd);
	}else if(count > 0){
		pal_rwlock_write_unlock(&phynet->hash_lock_array[index]);		
		pal_spinlock_unlock(&vpnet->hash_lock); 
		wait_on_phy_port(vpnet,phynet,vp);	

		write_lock_namespace(nd);
		__phy_vport_destroy(vpnet,phynet,vp);		
		write_unlock_namespace(nd);
	}else{
		PAL_PANIC("error phy_vport->count\n");
	}
	pal_rwlock_write_unlock(&phynet->hash_lock_array[index]);

	return 0;
}

int phy_net_init(void)
{
	uint16_t h;
	struct phy_net *phynet = &phy_vport_net;

	phynet->addrcnt = 0;
	phynet->addrmax = PHY_VPORT_NUM_MAX;
		
	for (h = 0; h < PHY_VPORT_HASH_SIZE; ++h){
		pal_rwlock_init(&phynet->hash_lock_array[h]);
		PAL_INIT_HLIST_HEAD(&phynet->phy_vport_list[h]);
	}
	
	return 0;
}

void phy_vport_slab_init(int numa_id)
{
    phy_vport_slab = pal_slab_create("phy_vport", PHY_VPORT_SLAB_SIZE, 
		sizeof(struct phy_vport), numa_id, 0);
	
	if (!phy_vport_slab) {
		PAL_PANIC("create phy_vport slab failed\n");
	}
}

