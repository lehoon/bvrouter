#ifndef _PALI_IPGROUP_H_
#define _PALI_IPGROUP_H_

#include "pal_ipgroup.h"
#include "list.h"


/* scheduler of ipgroup 
 * returns tid and should never fail */
typedef int (* pal_ipg_scheduler_t)(const struct sk_buff *skb,
                                    const struct pal_dip *dip);

/* called after new ip is added or old ip is removed
 * param ipg Ipgroup to be updated
 * param ip Ip address added or deleted
 * param add 0 if this is a remove action, 1 if it's an add action 
 */
typedef int (* pal_ipg_scheduler_update_t)(struct pal_ipgroup *ipg,
                                           struct pal_dip * dip, int add);

/*
 * used by user to configure pakcet dispatch algrithms.
 */
struct pal_ipgroup {
	char name[IPG_NAME_MAX];
	struct pal_hlist_node hlist;
	struct pal_list_head dip_list;
	pal_ipg_disttype_t disttype;
	pal_ipg_handler_t handler;
	pal_ipg_scheduler_t scheduler;
	/* update function is called with write lock held */
	pal_ipg_scheduler_update_t update; /* called when new ip is added */
	int numa;
	uint32_t flags;
	int sch_data[IPG_SCHED_DATA_SIZE/sizeof(int)];
};

/*
 * Destination IP type. Each structure represents an IP.
 */
struct pal_dip {
	struct pal_hlist_node hlist; /* worker uses this list to access dip */
	struct pal_list_head list;   /* pal_ipgroup->dip_list */
	uint32_t ip;
	uint32_t ref;
	uint8_t allow_conflict;
	/* Network interface this ip belongs to. PAL_MAX_PORT if not applied */
	unsigned port;
	struct pal_ipgroup *ipg;
	enum dip_type type; /* type of this dip. used by pal */
};

extern int ipg_add_ip(struct pal_ipgroup *ipg, uint32_t ip, 
                      uint32_t portid, enum dip_type type, int allow_conflict);

extern int pal_ipgroup_init(void);



/*
 * @brief Dispatch packet to cresponding worker or handle it ourself
 */
extern int dispatch_pkt(struct sk_buff *skb, const struct pal_dip *dip);

/*
 * @brief Schedule according to the schedule algrithm
 */
extern int ipg_schedule(struct sk_buff *skb, const struct pal_dip *dip);

/*
 * @brief get the pal ipgroup of a specified numa
 */
static inline struct pal_ipgroup *get_pal_ipg(int numa)
{
	return g_pal_config.numa[numa]->ipg.pal_ipg;
}

#endif
