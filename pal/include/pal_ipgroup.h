#ifndef _PAL_IPGROUP_H_
#define _PAL_IPGROUP_H_
#include <stdint.h>
#include "pal_skb.h"

#define IPG_NAME_MAX	32


/*
 * Packet distribute methods used by receivers
 * There are 3 kinds of typical combinations:
 * 1. 4TUPHASH and SINGLE are used for VIPs and BIPs in PPL mode
 * 2. L4SHASH and L4DHASH are used for VIPs and BIPs in CDN(DNAT only)
 * 3. RTC is used for both VIPs and BIPs in RTC mode, in this case, FDIR is needed.
 *    For more information of how to set FDIR, refer to pal_ipg_create.
 */
typedef enum {
	IPG_DIST_PPL_4TUPHASH,	/* 4-tuple hash */
	IPG_DIST_PPL_SINGLE,	/* distribute the packets to a fixed worker */
	IPG_DIST_PPL_L4SHASH,	/* use sip+sport hash to pick a worker */
	IPG_DIST_PPL_L4DHASH,	/* use dip+dport hash to pick a worker */
	IPG_DIST_RTC,		/* handle the packet on this receiver */
	IPG_DIST_MAX,
} pal_ipg_disttype_t;

/* Dip hash table bucket count */
#define IPG_DIP_HASH_OFFSET		14
#define IPG_DIP_HASH_SIZE		(1UL<<IPG_DIP_HASH_OFFSET)
#define IPG_DIP_HASH_MASK		(IPG_DIP_HASH_SIZE-1)

/* Ip group hash table bucket count */
#define IPG_HASH_OFFSET			10
#define IPG_HASH_SIZE			(1UL<<IPG_HASH_OFFSET)
#define IPG_HASH_MASK			(IPG_HASH_SIZE-1)

/* ipg schedule data array size */
#define IPG_SCHED_DATA_SIZE		1024

#define PAL_MAX_IPG_NUMA		128
#define PAL_MAX_DIP_NUMA		8192

/*
 * Callback function regisiterd with ip group. Dips from this group will all
 * be processed by this function.
 */
typedef void (*pal_ipg_handler_t)(struct sk_buff *skb);

enum dip_type {
	PAL_DIP_USER = 0,
	PAL_DIP_GW,		/* IP of gateway */
	PAL_DIP_VNIC,		/* IP of VNIC */
	PAL_DIP_NEIGHBOR	/* Real servers in the same lan with us */
};

/* Let application handle icmp packets. If 0, pal would handle icmp echo request, 
 * other types of icmp packets are DROPPED */
#define PAL_IPG_F_HANDLEICMP		(0x1)
/* Let application handle ip packets whose protocol are not tcp/udp/icmp */
#define PAL_IPG_F_HANDLEUNKNOWIPPROTO	(0x2)

/*
 * @brief Find a ipgroup by name
 * @param name Name of the ipgroup to be found
 * @return A pointer to the ip group found, or NULL on failure
 */
extern struct pal_ipgroup *pal_ipg_find(const char *name);

/*
 * @brief Add an ip to a specified ipgroup
 * @param ipg Ipgroup into which you want to add the ip
 * @param ip The ip to be added into the ipgroup
 * @param portid Nic port id to which the ip belongs, if this ip does not
 *        belong to any port (e.g. VIPs), use PAL_IPG_PORT_NONE
 * @param allow_conflict If not 0, only increase ref count of ip on conflict. 
 *			fail if the param is 0. However, type and port_id must also match
 *			even if conflict is allowed.
 * @return 0 on success, < 0 on error
 */
extern int pal_ipg_add_ip(struct pal_ipgroup *ipg, uint32_t ip, unsigned portid,
				int allow_conflict);

/*
 * @brief Delete an IP from IP groups
 * @param ip The ip to be deleted
 * @return 0 on success, -1 on failure
 */
extern int pal_ipg_del_ip(uint32_t ip, int numa);

/*
 * @brief Find pal_dip struct of an ip in the current numa node
 * @param ip IP address of the pal_dip to be found, in network byteorder.
 * @return A pointer to pal_dip struct, or NULL if not found
 */
struct pal_dip *pal_ipg_find_ip_numa(uint32_t ip, int numa);

/*
 * @brief Calculate the hash value of a dip
 */
static inline uint32_t dip_hash(uint32_t ip)
{
	return pal_hash32(ip) & IPG_DIP_HASH_MASK;
}

/*
 * @brief Get the hash table of ip group on a specific numa
 */
static inline struct pal_dip_hash_bucket *dip_hbucket_numa(uint32_t hash, int numa)
{
	return g_pal_config.numa[numa]->ipg.dip_htable + hash;
}

/*
 * @brief Get the hash table of ip group on a specific numa
 */
/* static inline struct pal_dip_hash_bucket *dip_hbucket(uint32_t hash)
{
	return dip_hbucket_numa(hash, pal_numa_id());
} */


/*
 * @brief Find pal_dip struct of an ip in the current numa node
 * @param ip IP address of the pal_dip to be found, in network byteorder.
 * @return A pointer to pal_dip struct, or NULL if not found
 * @note The read lock of this dip is held on finding
 */
static inline struct pal_dip *pal_ipg_find_ip(uint32_t ip)
{
	return pal_ipg_find_ip_numa(ip, pal_numa_id());
}

static inline void pal_ipg_put_ip_numa(uint32_t ip, int numa)
{
	uint32_t hash = dip_hash(ip);
	struct pal_dip_hash_bucket *bucket = dip_hbucket_numa(hash, numa);

	pal_rwlock_read_unlock(&bucket->rwlock);
}

static inline void pal_ipg_put_ip(uint32_t ip)
{
	pal_ipg_put_ip_numa(ip, pal_numa_id());
}


/*
 * @brief Print all dips and ip groups for debug purpose
 */
extern void pal_ipg_dump(void);

/*
 * @brief Create a new ipgroup
 * @param name Name of the ipgroup, must be unique on a numa. 
 *             Cannot change after created.
 * @param handler Function used to handle the packet by application.
 * @param disttype Algrithm used to distribute the packet.
 * @param workers A array of cpu id who can handle packets sent to the ip
 * @param worker_cnt Number of elements in workers
 * @param flags Flags to indicate the behavior on some special packets
 * @return pal_ipgroup created or NULL on failure
 * @Note: This function should only be called on initialization
 *        When you are creating an ipgroup of type RTC, the behavior of this
 *        function relies on "workers" and "n_worker" parameters:
 *        1. If n_workers is 0, then packets matching this ipgroup is 
 *           hashed to receiver using NIC RSS, and they are handled 
 *           on the receiver that receives them.
 *        2. If n_workers is 1, then all IPs in this ipgroup is bound to this
 *           receiver with FDIR. Note that in this case, the workers parameter
 *           is actually receiver. If you use a tid which is not a receiver,
 *           pal_ipg_add_ip function would fail.
 *        3. if n_workers is neither 0 nor 1, this function would fail.
 */

extern struct pal_ipgroup *pal_ipg_create(const char *name,
                              pal_ipg_handler_t handler,
                              pal_ipg_disttype_t disttype,
                              const int *workers, int n_worker,
                              int numa, uint32_t flags);

#endif
