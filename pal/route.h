#ifndef _PALI_ROUTE_H_
#define _PALI_ROUTE_H_

#include <stdint.h>

#include "pal_route.h"
#include "pal_list.h"
#include "pal_vport.h"
#include "pal_vxlan.h"


#define ROUTE_TABLE_SLAB_SIZE 1024*10
#define LEAF_INFO_SLAB_SIZE 1024*10*5
#define LEAF_SLAB_SIZE 10240*5

#define LOCAL_TYPE_PRELEN 32

#define LPM_LOOKUP		0x01   /*longest prefix match*/
#define	NEXTHOP_AM_LOOKUP	0x02	/*Accurate match*/	
#define	SIP_AM_LOOKUP	0x04	/*Accurate match*/	

struct look_up_helper{
	uint32_t next_hop;
	uint32_t sip;
	uint32_t prefix;
	uint32_t prefix_len;
};

#define KEYLENGTH (8 * sizeof(t_key))

typedef uint32_t t_key;

#define T_TNODE 0
#define T_LEAF  1
#define NODE_TYPE_MASK	0x1UL
#define NODE_TYPE(node) (((const struct rt_trie_node *)(node))->parent & NODE_TYPE_MASK)

#define IS_TNODE(n) (!(((const struct rt_trie_node *)(n))->parent & T_LEAF))
#define IS_LEAF(n) (((const struct rt_trie_node *)(n))->parent & T_LEAF)



/*
 * Common trie tree node. 
 * Internal nodes and leaf nodes must all include this struct as their first member.
 */
struct rt_trie_node {
	unsigned long parent;    /* pointer to parent node. use LSB as a leaf/tnode indicator */
	t_key key;               /* key of trie tree */
};

/*
 * Internal node of a tree.
 */
struct tnode {
	struct rt_trie_node node;
	unsigned char pos;             /* start bits of this trie node */
	unsigned char bits;            /* length of this tnode */
	unsigned int full_children;
	unsigned int empty_children;
	struct rt_trie_node *child[0]; /* array of children */
};

/*
 * Leaf node of a tree. Represent a prefix.
 */
struct leaf {
	struct rt_trie_node node;
	struct pal_hlist_head list;  /* chain keys of different prefix length here */
};

/*
 * A prefix length of a route. one prefix can have different lengths,
 * for example, 10.0.0.0/8 and 10.0.0.0/16
 */
struct leaf_info {
	struct pal_hlist_node hlist;	
	struct pal_list_head  route_list_head;	/*list for common_route*/	
	uint32_t prefix;
	uint32_t plen;
	int type;
	uint32_t mask_plen; /* ntohl(inet_make_mask(plen)) */
	uint32_t next_hop;
	uint32_t sip;       /* source IP to use */	
	struct pal_list_head	route_list;
	struct leaf  *l;
	struct vport *port_dev;		
};

/*
 * Routing table, pointer to the root of a trie tree;
 */
struct route_table {
	struct rt_trie_node *trie;  /* points to the root of a tree */	
	int default_route_flag;
	int route_entry_count;
};

/*
* The below functions can't called by user.
*/ 
int route_add_connected(struct route_table *t, uint32_t prefix, 
			uint32_t prefixlen, uint32_t sip,struct vport *vp);
int route_add_local(struct route_table *t, uint32_t sip,struct vport *vp);
int route_add_static(struct route_table *t,
                     uint32_t prefix,
                     uint32_t prefixlen,
                     uint32_t nexthop,
                     char *vport_name);
int pal_route_del_local(struct route_table * t,uint32_t sip);
int pal_route_del_connect(struct route_table * t,uint32_t prefix,uint32_t prefix_len,uint32_t sip);
void route_slab_init(int numa_id);

#endif
