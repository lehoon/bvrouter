#ifndef _PAL_ROUTE_H_
#define _PAL_ROUTE_H_

#include <stdint.h> 

struct route_table;

#define PAL_ROUTE_CONNECTED	0x01	/* connected route */
#define PAL_ROUTE_COMMON	0x02	/* routes not connected */
#define PAL_ROUTE_LOCAL		0x04	/* routes to local */

/*
 * Result of a route lookup.
 */
struct fib_result {
	uint32_t 	next_hop;  /* ip address of next hop */
	uint32_t	prefix;
	uint32_t	prefixlen;
	uint32_t	sip;
	int 		route_type;
	void		*port_dev;
	struct leaf_info *li;
};

struct route_entry{
	uint32_t	prefix;       /*Destination*/
	uint32_t	prefixlen;		/*Genmask*/
	uint32_t 	next_hop; 	   /*Gateway*/
	int 		route_type;     /*Flags*/
	struct vport *dev;			/*Iface*/
};

#define MAX_ROUTE_ENTRY_NUM 64

struct route_entry_table{
	int len;
	struct route_entry r_table[MAX_ROUTE_ENTRY_NUM];
};

struct route_table *pal_rtable_new(void);
 
void pal_rtable_destroy(struct route_table *rtable);
 
int pal_route_add(struct route_table *t, uint32_t prefix, uint32_t prefixlen, uint32_t nexthop);

/**
 * @brief pal_route_add_to_net - Add a static route to net_namespace
 * @param net - net attached to vrouter
 * @param prefix - target network prefix of route
 * @param prefixlen - target network mask of route
 * @param nexthop - route nexthop as gateway
 * @param vport_name - target vport name
 * @return 
 */
int pal_route_add_to_net(void *net,
                         uint32_t prefix,
                         uint32_t prefixlen,
                         uint32_t nexthop,
                         char *vport_name);

/**
 * @brief pal_route_del_from_net - Delete a static route to net_namespace
 * @param net - net attached to vrouter
 * @param prefix - target network prefix of route
 * @param prefixlen - target network mask of route
 * @return 
 */
int pal_route_del_from_net(void *net,
                           uint32_t prefix,
                           uint32_t prefixlen);
 
int pal_route_del(struct route_table *t, uint32_t prefix, uint32_t prefix_len);
 
int pal_route_lookup(const struct route_table *rtable, uint32_t dst, struct fib_result *res);

void pal_trie_dump(const struct route_table *rtable);

void pal_trie_traverse(struct route_table *rtable,struct route_entry_table *reb);


#endif
