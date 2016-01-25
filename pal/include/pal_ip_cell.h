#ifndef _PAL_IP_POOL_H
#define _PAL_IP_POOL_H

#include "pal_list.h"
#include "pal_skb.h"
#include "pal_spinlock.h"
#include "pal_utils.h"
#include "pal_byteorder.h"
#include "pal_atomic.h"
#include "pal_phy_vport.h"

#define IP_CELL_SLAB_SIZE 20480

extern struct ip_cell_pool ip_pool;

typedef enum {
  EXT_GW_IP = 0,
  FLOATING_IP,
  LOCAL_IP,
  VTEP_IP,
  GATEWAY_IP,
}ip_cell_type;

struct ip_cell{
	struct pal_hlist_node hlist;
	struct pal_list_head  list;
	__be32 	ip;
	struct phy_vport *vp;

	ip_cell_type type;
}__rte_cache_aligned;

struct ip_cell_info{
	ip_cell_type type;
	__be32 	ip;
	uint8_t	eth_addr[6];
};

#define IP_CELL_NUM_MAX			10000

#define IP_HASH_BITS	14
#define IP_HASH_SIZE	(1<<IP_HASH_BITS)
#define IP_HASH_MASK	(IP_HASH_SIZE-1)

struct ip_cell_head_lock{
	pal_rwlock_t	  hash_lock;
	struct pal_hlist_head head;
};

struct ip_cell_pool {
	unsigned int	  addrcnt;
	unsigned int	  addrmax;

	struct ip_cell_head_lock ip_cell_array[IP_HASH_SIZE];
};

static inline uint32_t get_hash_index_ip(__be32 ip)
{
	return (pal_hash32(ip) & IP_HASH_MASK);
}

static inline struct pal_hlist_head *ip_cell_head(struct ip_cell_pool *ippool,__be32 ip)
{
	return &ippool->ip_cell_array[pal_hash32(ip) & IP_HASH_MASK].head;
}

static inline struct pal_hlist_head *ip_cell_head_index(struct ip_cell_pool *ippool,uint32_t index)
{
	return &ippool->ip_cell_array[index].head;
}

static inline void read_lock_ip_cell(uint32_t index)
{
	pal_rwlock_read_lock(&ip_pool.ip_cell_array[index].hash_lock);
}

static inline void read_unlock_ip_cell(uint32_t index)
{
	pal_rwlock_read_unlock(&ip_pool.ip_cell_array[index].hash_lock);
}

static inline void write_lock_ip_cell(uint32_t index)
{
	pal_rwlock_write_lock(&ip_pool.ip_cell_array[index].hash_lock);
}

static inline void write_unlock_ip_cell(uint32_t index)
{
	pal_rwlock_write_unlock(&ip_pool.ip_cell_array[index].hash_lock);
}

static inline void add_ip_cell_to_ippool(struct ip_cell_pool *ippool,
 	struct ip_cell *ipcell)
{
	 ++ippool->addrcnt;
	 pal_hlist_add_head(&ipcell->hlist,
				 ip_cell_head(ippool, ipcell->ip));
}

 static inline void remove_ip_cell_from_ippool(struct ip_cell_pool *ippool,
 	struct ip_cell *ipcell)
{
	 --ippool->addrcnt;
	pal_hlist_del(&ipcell->hlist);

}

static inline void add_floating_ip_to_phy_vport(struct phy_vport *vport,
	 struct ip_cell *ipcell)
{
	vport->fl_ip_count++;
	pal_list_add(&ipcell->list,
			&vport->floating_list);
}

 static inline void remove_floating_ip_from_phy_vport(struct phy_vport *vport,
	  struct ip_cell *ipcell)
 {
	 vport->fl_ip_count--;
	 pal_list_del(&ipcell->list);
 }

extern void dump_ip_cell(struct ip_cell *ipcell);
extern int ip_cell_add(__be32 ip, ip_cell_type type,
				 struct phy_vport *vport);


extern struct phy_vport *find_get_phy_vport(__be32 ip);

extern int ip_cell_delete(__be32 ip,ip_cell_type type);
extern int ip_cell_pool_init(void);
extern int find_ip_cell_info(__be32 ip,struct ip_cell_info *info);
extern void ip_cell_slab_init(int numa_id);

#endif

