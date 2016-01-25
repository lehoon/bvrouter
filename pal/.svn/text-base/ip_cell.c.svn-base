#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "pal_phy_vport.h"
#include "pal_ip_cell.h"
#include "pal_error.h"
#include "vtep.h"
#include "pal_malloc.h"
#include "pal_slab.h"

static struct pal_slab *ip_cell_slab = NULL;

/*
* ip_pool is  consist of ext_gw_ip/floating ip /vtep ip;
*/
struct ip_cell_pool ip_pool;

/* Look up ip cell in ip_pool */
static struct ip_cell *__find_ip_cell_nolock(__be32 ip)
{
	struct ip_cell *ipcell;
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(ipcell,hnode,ip_cell_head(&ip_pool,ip), hlist) {
		if (ipcell->ip == ip)
			return ipcell;
	}

	return NULL;
}

static struct ip_cell * __bvrouter __find_ip_cell_nolock_index(__be32 ip,uint32_t index)
{
	struct ip_cell *ipcell;
	struct pal_hlist_node *hnode;

	pal_hlist_for_each_entry(ipcell,hnode,ip_cell_head_index(&ip_pool,index), hlist) {
		if (ipcell->ip == ip)
			return ipcell;
	}

	return NULL;
}

int find_ip_cell_info(__be32 ip,struct ip_cell_info *info)
{
	uint32_t index;
	struct ip_cell *ipcell;

	index = get_hash_index_ip(ip);
	read_lock_ip_cell(index);
	ipcell = __find_ip_cell_nolock_index(ip,index);
	if(!ipcell){
		read_unlock_ip_cell(index);
		return -1;
	}else{
		info->ip = ipcell->ip;
		info->type = ipcell->type;
		if(ipcell->vp){
			mac_copy(info->eth_addr,ipcell->vp->vp.vport_eth_addr);
		}else if(info->type == LOCAL_IP){
			mac_copy(info->eth_addr,get_vtep_mac());
		}
	 }
	read_unlock_ip_cell(index);

	return 0;
}

struct phy_vport * __bvrouter find_get_phy_vport(__be32 ip)
{
	 uint32_t index;
	 struct ip_cell *ipcell;
	 struct phy_vport *vport;
	 int lcore_id = rte_lcore_id();

	 index = get_hash_index_ip(ip);

	 read_lock_ip_cell(index);
	 ipcell = __find_ip_cell_nolock_index(ip,index);
	 if(unlikely(!ipcell)){
		read_unlock_ip_cell(index);
		return NULL;
	 }else{
	 	vport = ipcell->vp;
	 	if(likely((long)vport)){
			if(unlikely(!(vport->port_state & PHY_VPORT_USEING))){
				read_unlock_ip_cell(index);
				return NULL;
			}
			vport->use_count[lcore_id]++;
	 	}
	 }
	 read_unlock_ip_cell(index);

	 return vport;
}

static void __ip_cell_destroy(struct ip_cell_pool *ippool, struct ip_cell *ipcell);


 /* Add a new ip cell -- assumes lock held */
static int __ip_cell_create(struct ip_cell_pool *ippool,
				 __be32 ip, ip_cell_type type,
				 struct phy_vport *vport)
{
	 struct ip_cell *ipcell;

	 ipcell = __find_ip_cell_nolock(ip);
    if (ipcell) {
        if (ipcell->type == FLOATING_IP || ipcell->type == EXT_GW_IP) {
            if (!strcmp(vport->vp.vport_name, ipcell->vp->vp.vport_name)) {
                return -EEXIST;
            }
            else {
                __ip_cell_destroy(&ip_pool, ipcell);
            }
        }else {
            return -EEXIST;
        }
    }
    if (ippool->addrmax && ippool->addrcnt >= ippool->addrmax) {
        return -ENOSPC;
    }

    PAL_DEBUG("add ip cell %pI4\n",&ip);
    ipcell = pal_slab_alloc(ip_cell_slab);
    if (!ipcell) {
        return -ENOMEM;
    }

    ipcell->ip = ip;
    ipcell->type = type;
    ipcell->vp = vport;

    switch(type) {
        case FLOATING_IP:
            if(!vport) {
                goto error;
            }
            add_floating_ip_to_phy_vport(vport,ipcell);
            phy_vport_get(vport);
            break;
        case EXT_GW_IP:
            phy_vport_get(vport);
            break;
        case VTEP_IP:
        case GATEWAY_IP:
            if(vport) {
                PAL_PANIC("__ip_cell_create: the vport is non-null\n");
            }
            break;
        default :
            break;
    }

    add_ip_cell_to_ippool(ippool,ipcell);
    return 0;
error:
    pal_slab_free(ipcell);
    return -EFAULT;
}

/* Add static entry  */
int ip_cell_add(__be32 ip, ip_cell_type type,
				 struct phy_vport *vport)
{
	 int err;
	 uint32_t index;
	 struct ip_cell_pool *ippool = &ip_pool;

	 index = get_hash_index_ip(ip);
	 write_lock_ip_cell(index);
	 err = __ip_cell_create(ippool,ip,type,vport);
	 write_unlock_ip_cell(index);

	 return err;
}

static void ip_cell_free(struct ip_cell *ipcell)
{
	 if(ipcell) {
		 pal_slab_free(ipcell);
	 }
}

static void __ip_cell_destroy(struct ip_cell_pool *ippool, struct ip_cell *ipcell)
{
 	switch(ipcell->type){
		case FLOATING_IP:
				remove_floating_ip_from_phy_vport(ipcell->vp,ipcell);
				phy_vport_release(ipcell->vp);
				break;
		case EXT_GW_IP:
			phy_vport_release(ipcell->vp);
			break;
		case VTEP_IP:
		case GATEWAY_IP:
		default :
				break;
	}

	remove_ip_cell_from_ippool(ippool,ipcell);
	ip_cell_free(ipcell);
}

 /* Delete ip cell */
int ip_cell_delete(__be32 ip,ip_cell_type type)
{
	 int err = -ENOENT;
	 uint32_t index;
	 struct ip_cell *ipcell;
	 struct ip_cell_pool *ippool = &ip_pool;

	 index = get_hash_index_ip(ip);
	 write_lock_ip_cell(index);
	 ipcell = __find_ip_cell_nolock(ip);
	 if (ipcell) {
	 	if(ipcell->type != type){
			write_unlock_ip_cell(index);
			 return -EIO;
		}
		 __ip_cell_destroy(ippool,ipcell);
		 err = 0;
	 }
	 write_unlock_ip_cell(index);

	 return err;
}

void dump_ip_cell(struct ip_cell *ipcell)
{
	printf("IP:%d\n",ipcell->ip);
}

int ip_cell_pool_init(void)
{
	uint16_t h;
	struct ip_cell_pool *ippool = &ip_pool;

	ippool->addrcnt = 0;
	ippool->addrmax = IP_CELL_NUM_MAX;

	for (h = 0; h < IP_HASH_SIZE; ++h){
		pal_rwlock_init(&ippool->ip_cell_array[h].hash_lock);
		PAL_INIT_HLIST_HEAD(&ippool->ip_cell_array[h].head);
	}
	return 0;
}

void ip_cell_slab_init(int numa_id)
{
    ip_cell_slab = pal_slab_create("ip_cell", IP_CELL_SLAB_SIZE,
		sizeof(struct ip_cell), numa_id, 0);

	if (!ip_cell_slab) {
		PAL_PANIC("create ip_cell slab failed\n");
	}
}
