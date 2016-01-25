#ifndef _PAL_VXLAN_VPORT_H
#define _PAL_VXLAN_VPORT_H

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

extern struct vxlan_dev_net vxlan_dev_nets;

#define INT_VPORT_SLAB_SIZE 2048*10
#define VXLAN_DEV_SLAB_SIZE 1024*10
#define VXLAN_FDB_SLAB_SIZE   (1024*64*10) 
#define VXLAN_ARP_SLAB_SIZE   (1024*64*10)
#define VXLAN_SKB_SLAB_SIZE   (1024*64) 

#define VPORT_NUM_MAX_PER_VXLAN_DEV 10240
#define VXLAN_DEV_NUM_MAX			20480
#define FDB_NUM_MAX_PER_VPORT 		10000

#define VTEP_VXLAN_UDP_DST_PORT 4789

#define IS_VXLAN 1
#define NO_VXLAN 0
#define ERR_VXLAN -1

#define VXLAN_F_LEARN	0x01
#define VXLAN_F_PROXY	0x02
#define VXLAN_F_RSC	0x04
#define VXLAN_F_L2MISS	0x08
#define VXLAN_F_L3MISS	0x10


#define VXLAN_N_VID	(1u << 24)
#define VXLAN_VID_MASK	(VXLAN_N_VID - 1)
/* IP header + UDP + VXLAN + Ethernet header */
#define VXLAN_HEADROOM (20 + 8 + 8 + 14)

#define VXLAN_FLAGS 0x08000000	/* struct vxlanhdr.vx_flags required value. */

#define VNI_HASH_BITS	13
#define VNI_HASH_SIZE	(1<<VNI_HASH_BITS)
#define VNI_HASH_MASK   (VNI_HASH_SIZE-1)

#define FDB_HASH_BITS	12
#define FDB_HASH_SIZE	(1<<FDB_HASH_BITS)
#define FDB_HASH_MASK   (FDB_HASH_SIZE-1)

#define INT_VPORT_HASH_BITS	4
#define INT_VPORT_HASH_SIZE	(1<<INT_VPORT_HASH_BITS)
#define INT_VPORT_HASH_MASK   (INT_VPORT_HASH_SIZE-1)

#define ARP_HASH_BITS 12
#define ARP_HASH_SIZE (1ULL << ARP_HASH_BITS)
#define ARP_HASH_MASK (ARP_HASH_SIZE - 1)

struct vxlan_arp_entry {
    struct pal_hlist_node hlist;
    __be32 ip;
    unsigned char mac_addr[6];
};

/* VXLAN protocol header */
struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

struct vxlan_rdst {
	__be32			 	remote_ip;
	__be16			 	remote_port;
	uint32_t			remote_vni;
	uint32_t			remote_ifindex;
	struct vxlan_rdst	*remote_next;
};

/* Forwarding table entry */
struct vxlan_fdb {
	struct pal_hlist_node hlist;	/* linked list of entries */
	struct vxlan_rdst remote;
	uint8_t		  eth_addr[6];
};

#define VXLAN_VPORT_NAME_MAX  64

struct arp_head_lock
{
	pal_rwlock_t		  	hash_lock;
	struct pal_hlist_head   head;
};

struct fdb_head_lock
{
	pal_rwlock_t		  	hash_lock;
	struct pal_hlist_head   head;
};

/*
* A vxlan_dev has a unique vni id and multiple int_vport,
* and has it's own fdb table and arp table.
*/
struct vxlan_dev {
	struct pal_hlist_node hlist;  /*hash on vxlan_dev table*/
	
	uint32_t	 	vni;
	__be16		  	dst_port;	
	uint8_t		  	tos;		
	uint8_t		  	ttl;	
	uint32_t		flags;	
	
	atomic_t count;	
	
	unsigned int	 fdb_cnt;	
	unsigned int	 arp_cnt;
	unsigned int	 vport_cnt;		
	unsigned int	 vport_cnt_max;	
	
	/* When delete int_vport element, you must first hold vxlan_dev lock,  then hold bvrouter lock*/
	struct pal_hlist_head int_vport_head[INT_VPORT_HASH_SIZE];	

	/* When delete fdb element,you need get it's own hash lock*/	
	/* When delete arp element,you need get it's own hash lock*/	
	struct arp_head_lock arp_array[ARP_HASH_SIZE];
	struct fdb_head_lock fdb_array[FDB_HASH_SIZE];
};

#define	vxlan_dev_get(x)		atomic_inc(&(x)->count)
#define vxlan_dev_release(x)	atomic_dec(&(x)->count)

struct vxlan_dev_head_lock{
	pal_rwlock_t		  	hash_lock;
	struct pal_hlist_head   head;
};

struct vxlan_dev_net{
	unsigned int	 addrcnt;
	unsigned int	 addrmax;
	
	struct vxlan_dev_head_lock vxlan_dev_array[VNI_HASH_SIZE];
};

/*
* Internal vport which is connected to bvrouter, the role of this vport is similar with phy_vport.
*/
struct int_vport{
	struct vport vp;		
	struct pal_hlist_node hlist;     /*hash on vxlan_dev*/
	struct vxlan_dev *vdev;

	__be16		  	src_port;
	uint32_t vni_hash_index;  
	
	struct vport_stats	stats[MAX_CORE_NUM];	
};

static inline uint32_t get_hash_index_vni(uint32_t vni)
{
	return (pal_hash32(vni) & VNI_HASH_MASK);
}

static inline uint32_t get_hash_index_mac_int_vport(uint8_t *mac)
{
	return (pal_hash_crc((void *)mac,6) & INT_VPORT_HASH_MASK);
}

static inline uint32_t get_hash_index_mac(uint8_t *mac)
{
	return (pal_hash_crc((void *)mac,6) & FDB_HASH_MASK);
}

static inline uint32_t get_hash_index_arp(uint32_t ip)
{
	return (pal_hash32(ip) & ARP_HASH_MASK);
}

static inline struct pal_hlist_head *vxlan_fdb_head(struct vxlan_dev *vdev,
						uint8_t *mac)
{	
	return &vdev->fdb_array[pal_hash_crc((void *)mac,6) & FDB_HASH_MASK].head;
}

static inline struct pal_hlist_head *vxlan_fdb_head_index(struct vxlan_dev *vdev,
						uint32_t index)
{
	return &vdev->fdb_array[index].head;
}

static inline struct pal_hlist_head *vxlan_arp_head_index(struct vxlan_dev *vdev,
						uint32_t index)
{
	return &vdev->arp_array[index].head;
}

static inline void read_lock_vxlan_arp(struct vxlan_dev *vdev,uint32_t index)
{
	pal_rwlock_read_lock(&vdev->arp_array[index].hash_lock); 
}

static inline void read_unlock_vxlan_arp(struct vxlan_dev *vdev,uint32_t index)
{
	pal_rwlock_read_unlock(&vdev->arp_array[index].hash_lock); 
}

static inline void write_lock_vxlan_arp(struct vxlan_dev *vdev,uint32_t index)
{
	pal_rwlock_write_lock(&vdev->arp_array[index].hash_lock); 
}

static inline void write_unlock_vxlan_arp(struct vxlan_dev *vdev,uint32_t index)
{
	pal_rwlock_write_unlock(&vdev->arp_array[index].hash_lock); 
}

static inline void read_lock_vxlan_fdb(struct vxlan_dev *vdev,uint32_t index)
{
	pal_rwlock_read_lock(&vdev->fdb_array[index].hash_lock); 
}

static inline void read_unlock_vxlan_fdb(struct vxlan_dev *vdev,uint32_t index)
{
	pal_rwlock_read_unlock(&vdev->fdb_array[index].hash_lock); 
}

static inline void write_lock_vxlan_fdb(struct vxlan_dev *vdev,uint32_t index)
{
	pal_rwlock_write_lock(&vdev->fdb_array[index].hash_lock); 
}

static inline void write_unlock_vxlan_fdb(struct vxlan_dev *vdev,uint32_t index)
{
	pal_rwlock_write_unlock(&vdev->fdb_array[index].hash_lock); 
}

static inline struct pal_hlist_head *vxlan_dev_head(struct vxlan_dev_net *vxlan,uint32_t vni)
{
	return &vxlan->vxlan_dev_array[pal_hash32(vni) & VNI_HASH_MASK].head;
}

static inline struct pal_hlist_head *vxlan_dev_head_index(struct vxlan_dev_net *vxlan,uint32_t index)
{
	return &vxlan->vxlan_dev_array[index].head;
}

static inline void read_lock_vxlan_dev(uint32_t index)
{
	pal_rwlock_read_lock(&vxlan_dev_nets.vxlan_dev_array[index].hash_lock); 
}

static inline void read_unlock_vxlan_dev(uint32_t index)
{
	pal_rwlock_read_unlock(&vxlan_dev_nets.vxlan_dev_array[index].hash_lock); 
}

static inline void write_lock_vxlan_dev(uint32_t index)
{
	pal_rwlock_write_lock(&vxlan_dev_nets.vxlan_dev_array[index].hash_lock); 
}

static inline void write_unlock_vxlan_dev(uint32_t index)
{
	pal_rwlock_write_unlock(&vxlan_dev_nets.vxlan_dev_array[index].hash_lock); 
}

static inline void add_vxlan_dev_to_vxlan_net(struct vxlan_dev_net *vxlan, struct vxlan_dev *vdev)
{
	++vxlan->addrcnt;	
	/*add to vxlan_dev net*/
	pal_hlist_add_head(&(vdev->hlist),
				   vxlan_dev_head(vxlan, vdev->vni));
}

static inline void add_int_vport_to_vport_net(struct vport_net *vpnet, struct int_vport *vp)
{
	++vpnet->addrcnt;
	/*add to vport net*/
	pal_hlist_add_head(&(vp->vp.hlist),
				  vport_head(vpnet, vp->vp.vport_name));
}

static inline void add_int_vport_to_vxlan_dev(struct vxlan_dev *vdev, struct int_vport *vp)
{
	++vdev->vport_cnt;
	/*add to vxlan_dev*/	
	pal_hlist_add_head(&(vp->hlist),
		&vdev->int_vport_head[get_hash_index_mac_int_vport(vp->vp.vport_eth_addr)]);
}

static inline void remove_vxlan_dev_from_vxlan_net(struct vxlan_dev_net *vxlan, struct vxlan_dev *vdev)
{
	--vxlan->addrcnt;
	/*delete from vxlan_dev net*/
	pal_hlist_del(&(vdev->hlist));		

}

static inline void remove_int_vport_from_vport_net(struct vport_net *vpnet, struct int_vport *vp)
{
	--vpnet->addrcnt;
	/*delete from vport net*/
	pal_hlist_del(&(vp->vp.hlist));		
}

static inline void remove_int_vport_from_vxlan_dev(struct vxlan_dev *vdev, struct int_vport *vp)
{
	--vdev->vport_cnt;
	/*delete from vxlan dev*/
	pal_hlist_del(&(vp->hlist));		
}

extern struct vxlan_dev *find_lock_vxlan_dev(uint32_t vni,uint32_t index);
extern struct int_vport *__find_int_vport_nolock(struct vxlan_dev *vdev,uint8_t *mac);
extern int int_vport_delete(struct vport_net *vpnet,struct int_vport *vp);
extern int int_vport_add(char *vport_name,char *uuid,
			    uint8_t *int_gw_mac,__be32 int_gw_ip,uint32_t prefix_len,uint32_t vni,
			    void *nd);

extern struct vxlan_dev *__find_vxlan_dev_nolock(uint32_t vni);
extern int vxlan_dev_net_init(void);
extern int vxlan_fdb_add( struct vxlan_dev *vport, 
			 unsigned char *mac,
			 __be32 ip, __be16 port, uint32_t vni,uint32_t ifindex);
extern int vxlan_fdb_delete(struct vxlan_dev *vport,
			     unsigned char *mac);
extern int vxlan_fdb_flush(struct vxlan_dev *vdev);
extern int vxlan_arp_flush(struct vxlan_dev *vdev);
extern int del_vxlan_arp_entry(struct vxlan_dev *vdev, __be32 ip);
extern int add_vxlan_arp_entry(struct vxlan_dev *vdev, struct vxlan_arp_entry *entry);
extern struct vxlan_arp_entry *find_vxlan_arp_entry(struct vxlan_dev *vdev, __be32 ip);
extern int vxlan_fdb_show(struct vxlan_dev *vdev);
extern void vxlan_slab_init(int numa_id);
extern void vxlan_fdb_slab_init(int numa_id);
extern void vxlan_skb_slab_init(int numa_id);
extern void vxlan_arp_slab_init(int numa_id);
extern const struct vport_device_ops int_vport_ops;

#endif

