#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "pal_vxlan.h"
#include "pal_error.h"
#include "pal_malloc.h"
#include "pal_slab.h"


struct vxlan_dev_net vxlan_dev_nets;

static struct pal_slab *int_vport_slab = NULL;
static struct pal_slab *vxlan_dev_slab = NULL;

/*
* Look up vxlan_dev in vxlan_dev_nets, no lock  
*/
struct vxlan_dev *__find_vxlan_dev_nolock(uint32_t vni)
{
	struct vxlan_dev *vdev;		
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(vdev,hnode,vxlan_dev_head(&vxlan_dev_nets,vni), hlist) {
		if (vdev->vni == vni)
			return vdev;
	}

	return NULL;
}

static struct vxlan_dev *__bvrouter __find_vxlan_dev_nolock_index(uint32_t vni,uint32_t index)
{
	struct vxlan_dev *vdev;		
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(vdev,hnode,vxlan_dev_head_index(&vxlan_dev_nets,index), hlist) {
		if (vdev->vni == vni)
			return vdev;
	}

	return NULL;
}

/*
* Look up vxlan_dev in vxlan_dev_nets ,and then hold the read_lcok
*/
struct vxlan_dev *__bvrouter find_lock_vxlan_dev(uint32_t vni, uint32_t index)
{
	struct vxlan_dev *vdev;	

	read_lock_vxlan_dev(index);
	vdev = __find_vxlan_dev_nolock_index(vni,index);
	if(unlikely(!vdev)){
		read_unlock_vxlan_dev(index);
		return NULL;
	}
	
	return vdev;
}

/*create vxlan_dev, no lock*/
static struct vxlan_dev * __vxlan_dev_create(struct vxlan_dev_net *vxlan,uint32_t vni)
{
	struct vxlan_dev *vdev;
	uint16_t h;
	uint32_t index;

	if (vxlan->addrmax && vxlan->addrcnt >= vxlan->addrmax)
			return NULL;
		
	vdev = pal_slab_alloc(vxlan_dev_slab);
	if (!vdev)
		return NULL;

	vdev->vni = vni;
	vdev->dst_port = pal_htons(VTEP_VXLAN_UDP_DST_PORT);
	vdev->tos = 0;
	vdev->ttl = 64;
	vdev->flags = 0;
	vdev->fdb_cnt = 0;
	vdev->arp_cnt = 0;
	vdev->vport_cnt = 0;
	vdev->vport_cnt_max = VPORT_NUM_MAX_PER_VXLAN_DEV;

	atomic_set(&(vdev->count),0);
	
	for (h = 0; h < INT_VPORT_HASH_SIZE; ++h){			
		PAL_INIT_HLIST_HEAD(&vdev->int_vport_head[h]);
	}
	
	for (h = 0; h < FDB_HASH_SIZE; ++h){			
		pal_rwlock_init(&vdev->fdb_array[h].hash_lock);
		PAL_INIT_HLIST_HEAD(&vdev->fdb_array[h].head);
	}
	
	for (h = 0; h < ARP_HASH_SIZE; ++h){			
		pal_rwlock_init(&vdev->arp_array[h].hash_lock);
		PAL_INIT_HLIST_HEAD(&vdev->arp_array[h].head);
	}

	index = get_hash_index_vni(vni);
	write_lock_vxlan_dev(index);
	add_vxlan_dev_to_vxlan_net(vxlan,vdev);	
	write_unlock_vxlan_dev(index);
	
	vxlan_dev_get(vdev);

	return vdev;
}

static void vxlan_dev_free(struct vxlan_dev *vdev)
{
	if(vdev) {
		pal_slab_free(vdev);
	}
}

/*delete vxlan_dev, no lock*/
static void __vxlan_dev_delete(struct vxlan_dev_net *vxlan,struct vxlan_dev *vdev)
{
	uint32_t index;
	/*other int_vport is using*/
	if(atomic_read(&vdev->count) > 1)
		return;

	if(vdev->vport_cnt != 0)
		PAL_PANIC("vxlan_dev delete bug");

	vxlan_fdb_flush(vdev);
	if(vdev->fdb_cnt != 0)
		PAL_PANIC("vxlan_dev delete bug");

	vxlan_arp_flush(vdev);
	if(vdev->arp_cnt != 0)
		PAL_PANIC("vxlan_dev delete bug");

	index = get_hash_index_vni(vdev->vni);
	write_lock_vxlan_dev(index);
	remove_vxlan_dev_from_vxlan_net(vxlan,vdev);	
	write_unlock_vxlan_dev(index);
	
	vxlan_dev_free(vdev);
}

/*Look up int_vport in vxlan_dev, no lock*/
struct int_vport *__find_int_vport_nolock(struct vxlan_dev *vdev,uint8_t *mac)
{
	uint32_t index;
	struct int_vport *vport;		
	struct pal_hlist_node *hnode;

	index = get_hash_index_mac_int_vport(mac);
	pal_hlist_for_each_entry(vport,hnode,&vdev->int_vport_head[index], hlist) {
		if (pal_compare_ether_addr(mac, vport->vp.vport_eth_addr) == 0)
			return vport;
	}
	
	return NULL;
}

/* Add a new vxlan_vport -- assumes lock held */
static int __int_vport_create(struct vport_net *vpnet,
				struct vxlan_dev_net *vxlan,
				char *vport_name,char *uuid,
			    uint8_t *int_gw_mac,__be32 int_gw_ip,uint32_t prefix_len,uint32_t vni,
			    void *nd)
{
	uint32_t index; 
	struct vxlan_dev *vdev;
	struct int_vport *vp;

	vdev= __find_vxlan_dev_nolock(vni);
	if(vdev){
		if (vdev->vport_cnt_max && (vdev->vport_cnt >= vdev->vport_cnt_max))
			return -ENOSPC;
		
		vp = __find_int_vport_nolock(vdev,int_gw_mac);
		if(vp)
			return -EEXIST;
	}else{
		vdev = __vxlan_dev_create(vxlan,vni);
		if(!vdev)
			return -ENOMEM;
	}

	vp = pal_slab_alloc(int_vport_slab);
	if (!vp){
		__vxlan_dev_delete(vxlan,vdev);
		return -ENOMEM;
	}
	
	vp->vp.vport_name = pal_malloc(strlen(vport_name) + 1);
	if (!vp->vp.vport_name){		
		__vxlan_dev_delete(vxlan,vdev);
		pal_slab_free(vp);
		return -ENOMEM;
	}

	vp->vp.uuid = pal_malloc(strlen(uuid) + 1);
	if (!vp->vp.uuid){				
		__vxlan_dev_delete(vxlan,vdev);		
		pal_free(vp->vp.vport_name);
		pal_slab_free(vp);		
		return -ENOMEM;
	}
	
	vp->vp.vport_ip = int_gw_ip;
	vp->vp.prefix_len = (prefix_len != 0 && prefix_len < 32) ? prefix_len : 24;
	strcpy(vp->vp.vport_name, vport_name);	
	strcpy(vp->vp.uuid, uuid);
	rte_memcpy(vp->vp.vport_eth_addr, int_gw_mac, 6);

	vp->vp.vport_type = VXLAN_VPORT;
	vp->vp.vport_ops = &int_vport_ops;	
	vp->vdev = vdev;
	
	if(vp->vp.vport_ops->init((struct vport*)vp) < 0)
		goto error;
	
	write_lock_namespace(nd);
	/*add to namespace*/
	if(add_vport_to_namespace((struct vport *)vp,nd) < 0){
		write_unlock_namespace(nd);
		goto error;	
	}
	write_unlock_namespace(nd);
	
	add_int_vport_to_vport_net(vpnet,vp);

	index = get_hash_index_vni(vni);
	write_lock_vxlan_dev(index);
	add_int_vport_to_vxlan_dev(vdev,vp);
	write_unlock_vxlan_dev(index);
	
	vxlan_dev_get(vdev);

	return 0;
	
error:	
	__vxlan_dev_delete(vxlan,vdev);	
	pal_free(vp->vp.uuid);
	pal_free(vp->vp.vport_name);
	pal_slab_free(vp);
	return -EPERM;
}

/* Add static entry  */
int int_vport_add(char *vport_name,char *uuid,
			    uint8_t *int_gw_mac,__be32 int_gw_ip,uint32_t prefix_len,uint32_t vni,
			    void *nd)
{
	int err;
	struct vport_net *vpnet = &vport_nets;
	struct vxlan_dev_net *vxlan = &vxlan_dev_nets;
	struct vport *vp;
	struct pal_list_head *head; 

	if(!vport_name || !uuid)
		return -ENXIO;
		
	if(strlen(vport_name) > VPORT_NAME_MAX)
		return -ENXIO;
	
	if(strlen(uuid) > VPORT_UUID_LENGTH)
		return -ENXIO;

	if (vni >= VXLAN_VID_MASK)
		return -ERANGE;

	if(!pal_is_valid_ether_addr(int_gw_mac))
		return -ENXIO;
	
	pal_spinlock_lock(&vpnet->hash_lock);
	vp= __find_vport_nolock(vport_name);
	if (vp) {	
			pal_spinlock_unlock(&vpnet->hash_lock);
			return -EEXIST;
	} else {
		head = get_nd_vport_head(nd); 
		if(find_vport_ip_from_list(head,int_gw_ip) == 1){
			PAL_DEBUG("repeat ip in the namespace %x!\n",int_gw_ip);
			pal_spinlock_unlock(&vpnet->hash_lock);
			return -EEXIST;
		}
		
		err = __int_vport_create(vpnet,vxlan,vport_name,uuid,int_gw_mac,int_gw_ip,prefix_len,vni,nd);
	}	
	pal_spinlock_unlock(&vpnet->hash_lock);
	
	return err;
}

static void int_vport_free(struct int_vport *vp)
{
	if(vp) {
		if(vp->vp.vport_name){
			pal_free(vp->vp.vport_name);
			vp->vp.vport_name = NULL;
		}
		if(vp->vp.uuid){
			pal_free(vp->vp.uuid);
			vp->vp.uuid = NULL;
		}
		pal_slab_free(vp);
	}
}

/*must held lock*/
static void __int_vport_destroy(struct vport_net *vpnet,
						struct vxlan_dev_net *vxlan, struct int_vport *vp)
{
	void *nd;
	uint32_t index;	
	
	vp->vp.vport_ops->close((struct vport *)vp);

	nd = vp->vp.private;
	write_lock_namespace(nd);
	/*delete from namespace*/
	remove_vport_from_namespace((struct vport *)vp,vp->vp.private);
	write_unlock_namespace(nd);
		
	remove_int_vport_from_vport_net(vpnet,vp);

	index = get_hash_index_vni(vp->vdev->vni);
	write_lock_vxlan_dev(index);
	remove_int_vport_from_vxlan_dev(vp->vdev,vp);
	write_unlock_vxlan_dev(index);

	vxlan_dev_release(vp->vdev);
	__vxlan_dev_delete(vxlan,vp->vdev);
	int_vport_free(vp);
}

/*
* delete a vxlan_vport, and vpnet->hash_lock must be held 
*/
int int_vport_delete(struct vport_net *vpnet,struct int_vport *vp)
{
	struct vxlan_dev_net *vxlan = &vxlan_dev_nets;	

	__int_vport_destroy(vpnet,vxlan,vp);	

	return 0;
}

int vxlan_dev_net_init(void)
{
	uint16_t h;
	struct vxlan_dev_net *vxlan = &vxlan_dev_nets;

	vxlan->addrcnt = 0;
	vxlan->addrmax = VXLAN_DEV_NUM_MAX;
		
	for (h = 0; h < VNI_HASH_SIZE; ++h){	
		pal_rwlock_init(&vxlan->vxlan_dev_array[h].hash_lock);
		PAL_INIT_HLIST_HEAD(&vxlan->vxlan_dev_array[h].head);
	}
	
	return 0;
}

void vxlan_slab_init(int numa_id)
{
    int_vport_slab = pal_slab_create("int_vport", INT_VPORT_SLAB_SIZE, 
		sizeof(struct int_vport), numa_id, 0);
	
	if (!int_vport_slab) {
		PAL_PANIC("create int_vport slab failed\n");
	}
	
    vxlan_dev_slab = pal_slab_create("vxlan_dev", VXLAN_DEV_SLAB_SIZE, 
		sizeof(struct vxlan_dev), numa_id, 0);
	
	if (!vxlan_dev_slab) {
		PAL_PANIC("create vxlan_dev slab failed\n");
	}
}
