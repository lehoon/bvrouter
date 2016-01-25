#ifndef _PAL_VPORT_H_
#define _PAL_VPORT_H_

#include <string.h>
#include <stdint.h>

#ifdef BVROUTER
#include "bvr_namespace.h"
#endif

#include "pal_list.h"
#include "pal_skb.h"
#include "pal_spinlock.h"
#include "pal_utils.h"

#define MAX_CORE_NUM PAL_MAX_CPU

#define VPORT_NUM_MAX			20000

typedef enum {
	VXLAN_VPORT = 0,
  	PHY_VPORT,  
}vp_type;

struct vport_stats {
	unsigned long	rx_packets;
	unsigned long	tx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_bytes;
	unsigned long	rx_errors;
	unsigned long	tx_errors;
	unsigned long	rx_dropped;
	unsigned long	tx_dropped;
};

#define VPORT_NAME_MAX   64
#define VPORT_UUID_LENGTH   64

struct vport{
	struct pal_hlist_node hlist;   
	struct pal_list_head  list_nd; 
	void	*private;	

	vp_type 	vport_type;		
	
	uint8_t		vport_eth_addr[6];	
	__be32		vport_ip;		
	uint32_t	prefix_len;	/*netmask len, eg, 24,16,8,..*/

	char *		 vport_name;			
	char *		 uuid;
	const struct vport_device_ops *vport_ops;
};

struct vport_device_ops {	
	int			(*init)(struct vport *dev);	
	int			(*send)(struct sk_buff *skb,struct vport *dev);	
	int			(*recv)(struct sk_buff *skb,struct vport *dev);	
	int			(*close)(struct vport *dev);	
};

#define VPORT_HASH_BITS	10
#define VPORT_HASH_SIZE	(1 << VPORT_HASH_BITS)
#define VPORT_HASH_MASK (VPORT_HASH_SIZE - 1)

struct vport_net {
	unsigned int	  addrcnt;
	
	pal_spinlock_t	  hash_lock;
	struct pal_hlist_head vport_list[VPORT_HASH_SIZE];
};

static inline struct pal_hlist_head *vport_head(struct vport_net *vpnet,char *vport_name)
{
	uint32_t key;
	key = pal_hash_str(vport_name) & VPORT_HASH_MASK;
	return &vpnet->vport_list[key];
}

extern void delete_vport_from_list(struct pal_list_head *head);
extern int add_route_to_nd(struct vport *dev,void *nd);
extern int delete_route_from_nd(struct vport *dev,void *nd);

#ifndef BVROUTER

#define BVROUTER_DROP -1

static inline void read_lock_namespace(void *nd)
{
	nd = NULL;
}

static inline void read_unlock_namespace(void *nd)
{
	nd = NULL;
}

static inline void write_lock_namespace(void *nd)
{
	nd = NULL;
}

static inline void write_unlock_namespace(void *nd)
{
	nd = NULL;
}

static inline void add_vport_to_nd(struct vport *dev,void *nd)
{	
	dev->private = nd;
}	

static inline void delete_vport_from_nd(struct vport *dev,void *nd)
{	
	dev->private = nd;
}	

static inline struct pal_list_head *get_nd_vport_head(void *nd)
{	
	nd = NULL;
	return	NULL;
}

static inline struct route_table *get_nd_router_table(void *nd)
{	
	nd = NULL;
	return	NULL;
}

#else

#define BVROUTER_DROP 0

static inline void read_lock_namespace(void *nd)
{
	net_user_hold((struct net*)nd);
}

static inline void read_unlock_namespace(void *nd)
{
	net_user_put((struct net*)nd);
}

static inline void write_lock_namespace(void *nd)
{
	struct net *net = (struct net*)nd;
	pal_rwlock_write_lock(&net->net_lock);
}

static inline void write_unlock_namespace(void *nd)
{
	struct net *net = (struct net*)nd;
	pal_rwlock_write_unlock(&net->net_lock);
}

static inline void add_vport_to_nd(struct vport *dev,void *nd)
{	
	struct net *net = (struct net*)nd;
	
	dev->private = nd;
	pal_list_add(&dev->list_nd,&net->dev_base_head);
	net_if_hold(net);
}	

static inline void delete_vport_from_nd(struct vport *dev,void *nd)
{	
	struct net *net = (struct net*)nd;

	dev->private = NULL;
	pal_list_del(&dev->list_nd);
	net_if_put(net);
}

static inline struct pal_list_head *get_nd_vport_head(void *nd)
{	
	struct net *net = (struct net*)nd;
	return	&net->dev_base_head;
}

static inline struct route_table *get_nd_router_table(void *nd)
{	
	struct  net *net = (struct net*)nd;
	return	net->route_table;
}

#endif

static inline int add_vport_to_namespace(struct vport *dev,void *nd)
{
	if(add_route_to_nd(dev,nd) < 0)
		return -1;
	add_vport_to_nd(dev,nd);
	return 0;
}

static inline void remove_vport_from_namespace(struct vport *dev,void *nd)
{	
	delete_route_from_nd(dev,nd);
	delete_vport_from_nd(dev,nd);
}

#ifdef BVROUTER_TEXT
#define __bvrouter __attribute__((__section__(".bvrouter.text")))
#else
#define __bvrouter
#endif

extern int bvr_pkt_handler(struct sk_buff *skb, struct vport *dev);
extern struct vport_net vport_nets; 
extern struct vport *__find_vport_nolock(char *vport_name);
extern int find_vport_ip_from_list(struct pal_list_head *head,__be32 ip);
extern int vport_net_init(void);
extern int locate_eth_dst(struct vport *vp, __be32 ip, uint8_t *dst_mac);

#endif

