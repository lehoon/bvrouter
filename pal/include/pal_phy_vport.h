#ifndef _PAL_PHY_VPORT_H
#define _PAL_PHY_VPORT_H

#include <string.h>
#include <stdint.h>

#include "pal_vport.h"
#include "pal_list.h"
#include "pal_skb.h"
#include "pal_pktdef.h"
#include "pal_spinlock.h"
#include "pal_utils.h"
#include "pal_byteorder.h"
#include "pal_atomic.h"

#define PHY_VPORT_SLAB_SIZE 1024*10

#define PHY_VPORT_NUM_MAX    1024*10

#define PHY_VPORT_HASH_BITS	10
#define PHY_VPORT_HASH_SIZE	(1<<PHY_VPORT_HASH_BITS)
#define PHY_VPORT_HASH_MASK	(PHY_VPORT_HASH_SIZE-1)

struct phy_net {
	unsigned int	  addrcnt;
	unsigned int	  addrmax;

	pal_rwlock_t	  hash_lock_array[PHY_VPORT_HASH_SIZE];
	struct pal_hlist_head phy_vport_list[PHY_VPORT_HASH_SIZE];
};

#define PHY_VPORT_NAME_MAX  64

struct phy_vport {
	struct vport vp;		
	struct pal_hlist_node hlist_phy_vport;   
	
	struct pal_list_head  floating_list;	/*list for floating ip*/
	unsigned long 	  fl_ip_count;

	unsigned long		port_state;	
	atomic_t count;						    /*Usage count, see below. */	
	int		 use_count[MAX_CORE_NUM];	

	struct vport_stats	stats[MAX_CORE_NUM];	
};

#define phy_vport_get(x)		atomic_inc(&(x)->count)
#define phy_vport_release(x)	atomic_dec(&(x)->count)

/* vxlan_vport state bits.. */
#define PHY_VPORT_INIT				1 
#define PHY_VPORT_USEING			2 
#define PHY_VPORT_DELETEING			4 

static inline uint32_t get_hash_index_ext_ip(__be32 ext_gw_ip)
{
	return (pal_hash32(ext_gw_ip) & PHY_VPORT_HASH_MASK);
}

static inline struct pal_hlist_head *phy_vport_head(struct phy_net *phynet,__be32 ext_gw_ip)
{
	return &phynet->phy_vport_list[pal_hash32(ext_gw_ip) & PHY_VPORT_HASH_MASK];
}

static inline struct pal_hlist_head *phy_vport_head_index(struct phy_net *phynet,uint32_t index)
{
	return &phynet->phy_vport_list[index];
}

static inline void add_phy_vport_to_phy_net(struct phy_net *phynet, struct phy_vport *vp)
{
	++phynet->addrcnt;	
	/*add to phy_vport net*/
	pal_hlist_add_head(&(vp->hlist_phy_vport),
				   phy_vport_head(phynet, vp->vp.vport_ip));
}

static inline void add_phy_vport_to_vport_net(struct vport_net *vpnet, struct phy_vport *vp)
{
	++vpnet->addrcnt;
	/*add to vport net*/
	pal_hlist_add_head(&(vp->vp.hlist),
				  vport_head(vpnet, vp->vp.vport_name));
}

static inline void remove_phy_vport_from_phy_net(struct phy_net *phynet, struct phy_vport *vp)
{
	--phynet->addrcnt;
	/*delete from phy_vport net*/
	pal_hlist_del(&(vp->hlist_phy_vport));		

}

static inline void remove_phy_vport_from_vport_net(struct vport_net *vpnet, struct phy_vport *vp)
{
	--vpnet->addrcnt;
	/*delete from vport net*/
	pal_hlist_del(&(vp->vp.hlist));		
}

extern const struct vport_device_ops phy_vport_ops;
extern int phy_net_init(void);
extern void get_phy_vport(struct phy_vport *vport);
extern void put_phy_vport(struct phy_vport *vport);

extern void show_floating_ip(struct phy_vport *vport);
extern int phy_vport_add(char *vport_name,char *uuid,
			    const uint8_t *ext_gw_mac,__be32 ext_gw_ip,
			    uint32_t prefix_len,void *nd);
extern int phy_vport_delete(struct vport_net *vpnet,struct phy_vport *vp);

extern int rcv_ext_network_pkt_process(struct sk_buff  *skb);
extern void phy_vport_slab_init(int numa_id);
#endif

