#include <rte_memzone.h>
#include <rte_ethdev.h>
#include "ipgroup.h"
#include "cpu.h"
#include "slab.h"
#include "malloc.h"
#include "netif.h"
#include "pktdef.h"

/*
 * @brief Calculate the hash value of an ip group
 */
static inline uint32_t ipgroup_hash(struct pal_ipgroup *ipg)
{
	return pal_hash_str(ipg->name) & IPG_HASH_MASK;
}

/*
 * @brief Find a ipgroup by name
 * @param name Name of the ipgroup to be found
 * @return A pointer to the ip group found, or NULL on failure
 */
#if 0
struct pal_ipgroup *pal_ipg_find(const char __unused *name)
{
	/* TODO: implement this */
	return NULL;
}
#endif

/*
 * @brief Get the slab of dip struct on a specific numa
 */
static inline struct pal_slab *dip_slab_numa(int numa)
{
	return g_pal_config.numa[numa]->ipg.dip_slab;
}


/*
 * @brief Get the slab of ip group struct on a specific numa
 */
static inline struct pal_slab *ipg_slab_numa(int numa)
{
	return g_pal_config.numa[numa]->ipg.ipg_slab;
}

/*
 * @brief Get the hash table of ip group on a specific numa
 */
static inline struct pal_hlist_head *ipg_htable_numa(int numa)
{
	return g_pal_config.numa[numa]->ipg.ipg_htable;
}

/*
 * @brief Insert a ipgroup into the hash list
 */
static inline void ipgroup_insert(struct pal_ipgroup *ipg)
{
	uint32_t hash = ipgroup_hash(ipg);

	pal_hlist_add_head(&ipg->hlist, &ipg_htable_numa(ipg->numa)[hash]);
}

/*
 * used in qsort function
 */
static int int_compare(const void *a, const void *b)
{
	if (*(const int *)a < *(const int *)b)
		return -1;

	if (*(const int *)a > *(const int *)b)
		return 1;

	return 0;
}

/*
 * Do common checks for piplined schedulers, including:
 * 1. all workers must be threads running in worker mode;
 * 2. all workers must be on the same numa with ipgroup;
 * 3. worker array must have no duplicated elements;
 */
static int ipg_ppl_basic_check(const int *worker, unsigned n_worker, int numa)
{
	unsigned i;
	int workers[PAL_MAX_THREAD];

	/* thread mode and numa check */
	for (i = 0; i < n_worker; i++) {
		if (pal_thread_conf(worker[i])->mode != PAL_THREAD_WORKER) {
			PAL_ERROR("ipg handler mode must be worker\n");
			return -1;
		}
 
		if (pal_tid_to_numa(worker[i]) != numa) {
			PAL_ERROR("ipg numa unmatch with worker(worker numa:%d, ipg numa:%d\n",
					pal_tid_to_numa(worker[i]), numa);
			return -1;
		}
	}

	/* duplication check. sort workers first */
	if (n_worker > PAL_MAX_THREAD) {
		PAL_ERROR("worker count larger than PAL_MAX_THREAD\n");
		return -1;
	}
	memcpy(workers, worker, n_worker * sizeof(int));
	qsort(workers, n_worker, sizeof(*workers), int_compare);
	for (i = 0; i < n_worker - 1; i++) {
		if(workers[i] == workers[i + 1]) {
			PAL_ERROR("duplicated worker %d in ipgroup\n", workers[i]);
			return -1;
		}
	}

	return 0;
}

static int ipg_4tuphash_check(const int *worker, unsigned n_worker, int numa)
{
	if (ipg_ppl_basic_check(worker, n_worker, numa) < 0)
		return -1;

	return 0;
}

/*
 * 4-tuple hash init function.
 * this scheduler store number of workers in the first slot of sch_data,
 * and worker list in the following slots.
 */
static void ipg_4tuphash_init(const int *worker, unsigned n_worker, 
                             struct pal_ipgroup *ipg)
{
	ipg->sch_data[0] = n_worker;
	memcpy(&ipg->sch_data[1], worker, sizeof(*worker) * n_worker);
	qsort(&ipg->sch_data[1], n_worker, sizeof(*worker), int_compare);

	return;
}

/*
 * schedule according to 4-tuple hash results.
 * note this scheduler utilizes rss hash value generated by nic.
 */
static int ipg_4tuphash_scheduler(const struct sk_buff *skb,
                                  const struct pal_dip *dip)
{
	int n_worker;
	int index;

	n_worker = dip->ipg->sch_data[0];
	/* Reuse hash value generated by nic */
	/* TODO: optimize the modulo operation */
	index = (skb->mbuf.pkt.hash.rss % n_worker) + 1;

	return dip->ipg->sch_data[index];
}

static int ipg_single_check(const int *worker, unsigned n_worker, int numa)
{
	/* keep in mind why it is called SINGLE scheduler */
	if (n_worker != 1) {
		PAL_ERROR("single scheduler must have one and only one worker\n");
		return -1;
	}

	if (ipg_ppl_basic_check(worker, n_worker, numa) < 0)
		return -1;

	return 0;
}

/*
 * single scheduler init function.
 * this scheduler store number of workers in the first slot of sch_data,
 * and worker list in the following slots.
 */
static void ipg_single_init(const int *worker, __unused unsigned n_worker, 
                             struct pal_ipgroup *ipg)
{
	ipg->sch_data[0] = worker[0];

	return;
}

static int ipg_single_scheduler(__unused const struct sk_buff *skb,
                                  const struct pal_dip *dip)
{
	return dip->ipg->sch_data[0];
}

static int ipg_l4shash_scheduler(__unused const struct sk_buff *skb,
                                  __unused const struct pal_dip *dip)
{
	return 0;
}

static int ipg_l4dhash_scheduler(__unused const struct sk_buff *skb,
                                  __unused const struct pal_dip *dip)
{
	return 0;
}

/*
 * RTC rules: 
 *    1. If n_workers is 0, then packets matching this ipgroup is 
 *       hashed to receiver using NIC RSS, and they are handled 
 *       on the receiver that receives them.
 *    2. If n_workers is 1, then all IPs in this ipgroup is bound to this
 *       receiver with FDIR. Note that in this case, the workers parameter
 *       is actually receiver. If you use a tid which is not a receiver,
 *       this function would fail.
 */
static int ipg_rtc_check(const int *worker, unsigned n_worker, int numa)
{
	unsigned port_id;
	struct rte_eth_fdir fdir_info;

	if (n_worker > 1) {
		PAL_ERROR("RTC scheduler must have no more than one handler\n");
		return -1;
	}

	/* does not need to check worker array if n_worker is 0 */
	if (n_worker == 0)
		return 0;

	/* in RTC mode, pkts handlers must be receiver processes themselves */
	if (pal_thread_mode(worker[0]) != PAL_THREAD_RECEIVER) {
		PAL_ERROR("Handler of RTC scheduler must be receiver\n");
		return -1;
	}

	if (pal_tid_to_numa(worker[0]) != numa) {
		PAL_ERROR("Handler of RTC scheduler is on wrong numa\n");
		return -1;
	}

	/* TODO: currently we check every port for fdir support status even if
	 * applications only want to use fdir on some specific ports.
	 * This behavior is OK for now, but should be changed later, for example,
	 * when mellanox NIC is used.
	 */
	for (port_id = 0; port_id < (unsigned)pal_phys_port_count(); port_id++) {
		if (!pal_port_enabled(port_id))
			continue;
		/* we donot care about fdir_info */
		if (rte_eth_dev_fdir_get_infos(port_id, &fdir_info) < 0)
			PAL_ERROR("port %u does not support fdir, return %d, fdirmode=%d\n", 
			port_id, rte_eth_dev_fdir_get_infos(port_id, &fdir_info),
			rte_eth_devices[port_id].data->dev_conf.fdir_conf.mode);
	}

	return 0;
}

/*
 * Run-to-complete scheduler init function.
 * this scheduler store number of workers in the first slot of sch_data,
 * and worker list in the following slots.
 */
static void ipg_rtc_init(const int *worker, unsigned n_worker, 
                             struct pal_ipgroup *ipg)
{
	unsigned port_id;
	static int fdir_inited = 0; /* only need to init once */
	struct rte_fdir_masks fdir_mask;

	/* nothing to init if n_worker is 0. Just use RSS to hash the packets.*/
	if (n_worker == 0) {
		ipg->sch_data[0] = -1;
		return;
	}

	ipg->sch_data[0] = worker[0];

	if (fdir_inited)
		return ;

	memset(&fdir_mask, 0, sizeof(fdir_mask));
	fdir_mask.only_ip_flow = 1;
	fdir_mask.dst_ipv4_mask = 0xFFFFFFFFU;

	for (port_id = 0; port_id < (unsigned)pal_phys_port_count(); port_id++) {
		if (!pal_port_enabled(port_id))
			continue;
		if (rte_eth_dev_fdir_set_masks(port_id, &fdir_mask) < 0)
			PAL_PANIC("init fdir of port %u failed\n", port_id);
	}

	fdir_inited = 1;

	return;
}

/*
 * @brief update flow director settings whenever a new ip is added or reomved
 */
static int ipg_rtc_update(struct pal_ipgroup *ipg,
                          struct pal_dip *dip, int add)
{
	int tid = ipg->sch_data[0];
	unsigned port_id, n_port, rxq;
	struct rte_fdir_filter fdir_filter;

	/* tid < 0 means do not use fdir. refer to ipg_rtc_init function*/
	if (tid < 0)
		return 0;

	memset(&fdir_filter, 0, sizeof(fdir_filter));
	fdir_filter.ip_dst.ipv4_addr = dip->ip;

	/* if port is specified, bind the ip to this port only. */
	if (dip->port != PAL_PORT_NONE) {
		port_id = dip->port;
		rxq = pal_thread_conf(tid)->rxq[port_id];
		if (add) {
			if (rte_eth_dev_fdir_add_perfect_filter(port_id, 
				              &fdir_filter, 0, rxq, 0) < 0)
				return -1;
		} else {
			if (rte_eth_dev_fdir_remove_perfect_filter(port_id, 
				              &fdir_filter, 0) < 0)
				return -1;
		}

		return 0;
	}

	/* port is not specified, bind the ip to all ports */
	n_port = (unsigned)pal_phys_port_count();
	for (port_id = 0; port_id < n_port; port_id++) {
		if (!pal_port_enabled(port_id))
			continue;
		rxq = pal_thread_conf(tid)->rxq[port_id];
		if (add) {
			if (rte_eth_dev_fdir_add_perfect_filter(port_id, 
			              &fdir_filter, 0, rxq, 0) < 0)
				break;
		} else {
			if (rte_eth_dev_fdir_remove_perfect_filter(port_id, 
			              &fdir_filter, 0) < 0)
				break;
		}
	}

	/* all ports are configured succefully */
	if (port_id == n_port)
		return 0;

	/* roll back */
	for (port_id--; (int)port_id >= 0; port_id--) {
		if (!pal_port_enabled(port_id))
			continue;
		rxq = pal_thread_conf(tid)->rxq[port_id];
		if (add) {
			if (rte_eth_dev_fdir_remove_perfect_filter(port_id, 
			              &fdir_filter, 0) < 0)
				PAL_ERROR("rtc add ip roll back failed\n");
		} else {
			if (rte_eth_dev_fdir_add_perfect_filter(port_id, 
			              &fdir_filter, 0, rxq, 0) < 0)
				PAL_ERROR("rtc remove ip roll back failed\n");
		}
	}

	return -1;
}

static int ipg_rtc_scheduler(__unused const struct sk_buff *skb,
                                  __unused const struct pal_dip *dip)
{
	return pal_thread_id();
}

/* ipgroup schedulers */
static struct {
	/* schedule a worker to handle a packet */
	pal_ipg_scheduler_t scheduler;
	pal_ipg_scheduler_update_t update;
	/* validate worker and numa settings */
	int (* check)(const int *worker, unsigned n_worker, int numa);
	/* initialize data used for scheduling */
	void (* init)(const int *worker, unsigned n_worker, struct pal_ipgroup *ipg);
} ipg_schedulers[IPG_DIST_MAX + 1] = {
	[IPG_DIST_PPL_4TUPHASH] = {
		.scheduler = ipg_4tuphash_scheduler,
		.check = ipg_4tuphash_check,
		.init = ipg_4tuphash_init,
	},
	[IPG_DIST_PPL_SINGLE] = {
		.scheduler = ipg_single_scheduler,
		.check = ipg_single_check,
		.init = ipg_single_init,
	},
	[IPG_DIST_PPL_L4SHASH] = {
		.scheduler = ipg_l4shash_scheduler,
		.check = NULL,
		.init = NULL,
	},
	[IPG_DIST_PPL_L4DHASH] = {
		.scheduler = ipg_l4dhash_scheduler,
		.check = NULL,
		.init = NULL,
	},
	[IPG_DIST_RTC] = {
		.scheduler = ipg_rtc_scheduler,
		.check = ipg_rtc_check,
		.init = ipg_rtc_init,
		.update = ipg_rtc_update,
	},
	/* used for system ipgroup */
	[IPG_DIST_MAX] = {
		.scheduler = NULL,
		.check = NULL,
		.init = NULL,
	},
};

/* Create an ip group. this is not called directly by applications */
static struct pal_ipgroup *ipg_create(const char *name,
                              pal_ipg_handler_t handler,
                              pal_ipg_disttype_t disttype,
                              const int *workers, int n_worker,
                              int numa, uint32_t flags)
{
	struct pal_ipgroup *ipg;

	if (ipg_schedulers[disttype].check && 
	    ipg_schedulers[disttype].check(workers, n_worker, numa) < 0)
		return NULL;

	ipg = (struct pal_ipgroup *)pal_slab_alloc(ipg_slab_numa(numa));
	if (ipg == NULL) {
		PAL_ERROR("ip group alloc failed\n");
		return NULL;
	}
	PAL_INIT_LIST_HEAD(&ipg->dip_list);

	strcpy(ipg->name, name);
	ipg->disttype = disttype;
	ipg->handler = handler;
	ipg->numa = numa;
	ipg->flags = flags;

	ipg->scheduler = ipg_schedulers[disttype].scheduler;
	ipg->update = ipg_schedulers[disttype].update;
	if (ipg_schedulers[disttype].init)
		ipg_schedulers[disttype].init(workers, n_worker, ipg);

	ipgroup_insert(ipg);

	return ipg;
}

/*
 * @brief Create a new ipgroup
 * @param name Name of the ipgroup, must be unique on a numa. 
 *             Cannot change after created.
 * @param handler Function used to handle the packet by application.
 * @param disttype Algrithm used to distribute the packet.
 * @param workers A array of cpu id who can handle packets sent to the ip
 * @param n_worker Number of elements in workers
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
struct pal_ipgroup *pal_ipg_create(const char *name,
                              pal_ipg_handler_t handler,
                              pal_ipg_disttype_t disttype,
                              const int *workers, int n_worker,
                              int numa, uint32_t flags)
{
	int i;

	ASSERT(strlen(name) < IPG_NAME_MAX);
	/* ASSERT(pal_ipg_find(name) == NULL); */
	ASSERT(disttype < IPG_DIST_MAX);
	ASSERT(handler != NULL);

	if (n_worker > PAL_MAX_THREAD) {
		PAL_DEBUG("%s: too many workers(%u)\n", __FUNCTION__, n_worker);
		return NULL;
	}

	for (i = 0; i < n_worker; i++) {
		if(!pal_thread_enabled(i)) {
			PAL_DEBUG("worker %u not enabled.\n", workers[i]);
			return NULL;
		}
	}

	return ipg_create(name, handler, disttype, workers, n_worker, numa, flags);
}

/*
 * @brief Create an ip group for pal. This ip group is only used to classify
 *        the IPs.
 */
static inline struct pal_ipgroup *ipg_create_for_pal(int numa)
{
	char name[IPG_NAME_MAX];

	snprintf(name, IPG_NAME_MAX, "PAL_IPG_%u", numa);

	return ipg_create(name, NULL, IPG_DIST_MAX, NULL, 0, numa, 0);
}


/*
 * @brief Alloc and init ipgroup hash table and slab on a spefic numa node
 * @note This function panics on error
 */
static void ipgroup_init_numa(int numa)
{
	unsigned i;
	struct ipgroup_conf *conf = &g_pal_config.numa[numa]->ipg;
	char buf[RTE_MEMZONE_NAMESIZE];

	/* alloc hash table for ip group */
	conf->ipg_htable = pal_malloc(IPG_HASH_SIZE * sizeof(*conf->ipg_htable));
	if (conf->ipg_htable == NULL)
		PAL_PANIC("alloc ipgroup hash table failed\n");
	for (i = 0; i < IPG_HASH_SIZE; i++) {
		PAL_INIT_HLIST_HEAD(&conf->ipg_htable[i]);
	}

	/* alloc hash table for dip */
	conf->dip_htable = pal_malloc(IPG_DIP_HASH_SIZE * sizeof(*conf->dip_htable));
	if (conf->dip_htable == NULL) {
		PAL_PANIC("alloc dip hash table failed\n");
	}
	for (i = 0; i < IPG_DIP_HASH_SIZE; i++) {
		PAL_INIT_HLIST_HEAD(&conf->dip_htable[i].hhead);
		pal_rwlock_init(&conf->dip_htable[i].rwlock);
	}

	/* create slab for ipgroups */
	snprintf(buf, RTE_MEMZONE_NAMESIZE, "PAL_IPGROUP_%u", numa);
	conf->ipg_slab = pal_slab_create(buf, PAL_MAX_IPG_NUMA, 
	                                 sizeof(struct pal_ipgroup), numa, 0);
	if (conf->ipg_slab == NULL) {
		PAL_PANIC("create ipgroup slab failed\n");
	}

	/* create slab for dips */
	snprintf(buf, RTE_MEMZONE_NAMESIZE, "PAL_DIP_%u", numa);
	conf->dip_slab = pal_slab_create(buf, PAL_MAX_DIP_NUMA, 
                                         sizeof(struct pal_dip), numa, 0);
	if (conf->dip_slab == NULL) {
		PAL_PANIC("create dip slab failed\n");
	}

	/* Create a special ip group. disttype and handlers are not available
	 * in this ip group.
	 * This is used for IPs which are only needed to be classified but 
	 * not to be dispatched. 
	 * For example, if we receive an arp reply, we must find out where
	 * does it from. We achieve this by looking up the dip struct and looking
	 * into *type* field, the dispatch algrithms are not used
	 */
	g_pal_config.numa[numa]->ipg.pal_ipg = ipg_create_for_pal(numa);
	if (g_pal_config.numa[numa]->ipg.pal_ipg == NULL) {
		PAL_PANIC("create ipg for pal on numa %d failed\n", numa);
	}

	return;
}

static inline struct pal_dip *__pal_ipg_find_ip(uint32_t ip,
                                        struct pal_hlist_head *hhead)
{
	struct pal_hlist_node *hnode;
	struct pal_dip *dip;

	pal_hlist_for_each_entry (dip, hnode, hhead, hlist) {
		if (dip->ip == ip)
			return dip;
	}

	return NULL;
}

/*
 * @brief Add an ip to a specified ipgroup
 * @param ipg Ipgroup into which you want to add the ip
 * @param ip The ip to be added into the ipgroup
 * @param portid Nic port id to which the ip belongs, if this ip does not
 *        belong to any port (e.g. VIPs), use PAL_IPG_PORT_NONE
 * @prarm type Type of this dip. Used by pal and cannot be set by user app
 * @param allow_conflict If not 0, only increase ref count of ip on conflict. 
 *			or fail if the param is 0. However, type and port_id must also match
 *			even if conflict is allowed.
 * @return 0 on success, < 0 on error
 */
int ipg_add_ip(struct pal_ipgroup *ipg, uint32_t ip, 
				uint32_t port_id, enum dip_type type, int allow_conflict)
{
	uint32_t hash;
	struct pal_dip *dip, *dip_old;
	struct pal_dip_hash_bucket *bucket;

	/* PAL_PORT_NONE means this ip does not belong to a specific port. e.g, VIPs*/
	if (port_id != PAL_PORT_NONE) {
		if (port_id >= PAL_MAX_PORT) {
			PAL_ERROR("ipg add ip failed, invalid portid %u\n", port_id);
			return -1;
		}

		if (ipg->numa != pal_port_numa(port_id)) {
			PAL_ERROR("ip "NIPQUAD_FMT" add on ip group %s of different numa\n",
					NIPQUAD(ip), ipg->name);
			return -1;
		}
	}

	dip_old = pal_ipg_find_ip_numa(ip, ipg->numa);
	if (dip_old != NULL) {
		/* to add a vip multiple times, all parameters of this vip must match */
		if (!allow_conflict || !dip_old->allow_conflict 
				|| port_id != dip_old->port || type != dip_old->type 
				|| dip_old->ipg != ipg) {
			PAL_ERROR("add ip error: "NIPQUAD_FMT" exists.\n", NIPQUAD(ip));
			pal_ipg_put_ip_numa(ip, ipg->numa);
			return -1;
		}

		/* just increase the ref count if this ip exists */
		dip_old->ref++;
		PAL_DEBUG("ipg add ip: "NIPQUAD_FMT" exists, increase ref to %u\n",
				NIPQUAD(dip_old->ip), dip_old->ref);
		pal_ipg_put_ip_numa(ip, ipg->numa);
		return 0;
	}

	dip = pal_slab_alloc(dip_slab_numa(ipg->numa));
	if (dip == NULL) {
		PAL_ERROR("alloc dip failed\n");
		return -1;
	}

	hash = dip_hash(ip);
	bucket = dip_hbucket_numa(hash, ipg->numa);
	dip->ip = ip;
	dip->port = port_id;
	dip->ipg = ipg;
	dip->type = type;
	dip->ref = 1;
	dip->allow_conflict = allow_conflict;
	pal_rwlock_write_lock(&bucket->rwlock);
	/* check again after we get the write lock */
	if (__pal_ipg_find_ip(ip, &bucket->hhead)) {
		pal_rwlock_write_unlock(&bucket->rwlock);
		pal_slab_free(dip);
		PAL_ERROR("add ip error: "NIPQUAD_FMT" exists.\n", NIPQUAD(ip));
		return -1;
	}
	pal_list_add(&dip->list, &ipg->dip_list);
	pal_hlist_add_head(&dip->hlist, &(bucket->hhead));

	if (ipg->update && ipg->update(ipg, dip, 1) < 0) {
		pal_hlist_del(&dip->hlist);
		pal_list_del(&dip->list);
		pal_rwlock_write_unlock(&bucket->rwlock);
		pal_slab_free(dip);
		PAL_ERROR("add dip failed, update ipgroup failed\n");
		return -1;
	}

	pal_rwlock_write_unlock(&bucket->rwlock);
	return 0;
}

/*
 * @brief Add an ip to a specified ipgroup
 * @param ipg Ipgroup into which you want to add the ip
 * @param ip The ip to be added into the ipgroup
 * @param portid Nic port id to which the ip belongs, if this ip does not
 *        belong to any single port (e.g. VIPs), use PAL_PORT_NONE
 * @param allow_conflict If not 0, only increase ref count of ip on conflict. 
 *			fail if the param is 0. However, type and port_id must also match
 *			even if conflict is allowed.
 * @return 0 on success, < 0 on error
 */
int pal_ipg_add_ip(struct pal_ipgroup *ipg, uint32_t ip, uint32_t port_id, 
                   int allow_conflict)
{
	return ipg_add_ip(ipg, ip, port_id, PAL_DIP_USER, allow_conflict);
}

/*
 * @brief Delete an ip from ip group
 * @param ip Ip to delete
 * @return 0 on success or this ip does not exist, -1 on failure
 */
int pal_ipg_del_ip(uint32_t ip, int numa)
{
	struct pal_dip *dip;
	uint32_t hash = dip_hash(ip);
	struct pal_dip_hash_bucket *bucket = dip_hbucket_numa(hash, numa);

	pal_rwlock_write_lock(&bucket->rwlock);
	dip = __pal_ipg_find_ip(ip, &bucket->hhead);
	if (dip == NULL) {
		PAL_DEBUG("ipg del ip: dip "NIPQUAD_FMT" does not exist.\n", NIPQUAD(ip));
		pal_rwlock_write_unlock(&bucket->rwlock);
		/* return 0 or -1? */
		return 0;
	}

	if (--dip->ref == 0) {
		pal_hlist_del(&dip->hlist);
		pal_list_del(&dip->list);
		if (dip->ipg->update) {
			if (dip->ipg->update(dip->ipg, dip, 0) < 0) {
				PAL_ERROR("ipgroup: del dip update failed");
			}
			/* continue with the deleting process even if update failed */
		}
		pal_slab_free(dip);
	}
	pal_rwlock_write_unlock(&bucket->rwlock);

	return 0;
}

/*
 * @brief init ipgroup hash table and dip hash table
 * @return 0 on success, -1 on failure
 */
int pal_ipgroup_init(void)
{
	int numa;

	PAL_FOR_EACH_NUMA (numa) {
		ipgroup_init_numa(numa);
	}

	return 0;
}

/*
 * @brief Find pal_dip struct of an ip in the current numa node
 * @param ip IP address of the pal_dip to be found, in network byteorder.
 * @return A pointer to pal_dip struct, or NULL if not found
 */
struct pal_dip *pal_ipg_find_ip_numa(uint32_t ip, int numa)
{
	uint32_t hash = dip_hash(ip);
	struct pal_dip_hash_bucket *bucket = dip_hbucket_numa(hash, numa);
	struct pal_dip *dip;

	pal_rwlock_read_lock(&bucket->rwlock);
	dip = __pal_ipg_find_ip(ip, &bucket->hhead);
	if (dip == NULL)
		pal_rwlock_read_unlock(&bucket->rwlock);

	return dip;
}

void pal_ipg_dump(void)
{
	unsigned i;
	int numa;
	struct pal_dip *dip;
	struct pal_ipgroup *ipg;
	struct pal_hlist_node *node;
	char ip_str[32];

	PAL_FOR_EACH_NUMA (numa) {
		PAL_LOG("|---------------NUMA %1u------------------|\n", numa);
		for (i = 0; i < IPG_HASH_SIZE; i++) {
			pal_hlist_for_each_entry (ipg, node, &ipg_htable_numa(numa)[i], hlist) {
				PAL_LOG("|name: %-32s |\n", ipg->name);
				pal_list_for_each_entry (dip, &ipg->dip_list, list) {
					sprintf(ip_str, NIPQUAD_FMT",", NIPQUAD(dip->ip));
					PAL_LOG("|    %-16s port %-2u           |\n", 
							ip_str, dip->port);
				}
			}
		}
		PAL_LOG("|---------------NUMA %1u end--------------|\n", numa);
	}
}

