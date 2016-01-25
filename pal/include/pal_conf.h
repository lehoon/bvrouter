#ifndef _PAL_CONF_H_
#define _PAL_CONF_H_
#include <stdint.h>
#include <pthread.h>
#include <rte_kni.h>
#include <pal_spinlock.h>
#include <pal_list.h>
#include "pal_ip_frag_reassemble.h"

/* max number of threads */
#define PAL_MAX_THREAD		16

#define PAL_MAX_RECEIVER	64

/* max number of numas */
#define PAL_MAX_NUMA		2

/* max number of cpu cores */
#define PAL_MAX_CPU		16

/* max number of network interfaces, including physical ones and logical ones.*/
#define PAL_MAX_PORT		12

/* X86 is little endian */
#define PAL_CONFIG_LITTLE_ENDIAN

#define BITS_PER_LONG		(sizeof(long) * 8)

/* max length of a thread's name */
#define PAL_THREAD_NAME_MAX	32


/*
 * Callback functions used by custom threads
 */
typedef int (*pal_thread_func_t)(void *arg);

/* delcare of structures deinfed in other header files */
struct pal_slab;

/*
 * configuration structure used by application.
 */
struct pal_config {
	uint32_t magic;
	/* memory config */
	uint8_t mem_channel;
	uint8_t l2_enabled;

	/* thread config */
	struct {
		/* which core does this thread be bound to.
		 * if not set, the thread would run on core *tid* */
		int cpu;
		unsigned mode;
		/* how many MICROseconds should we sleep after handling a batch
		 * of packets. This is only meaningful to worker and receiver
		 * threads. If you don't want them to sleep, leave this unset.
		 */
		unsigned sleep;
		pal_thread_func_t func;
		void *arg;
		/* name of the thread. pal would choose a name if not set */
		char name[PAL_THREAD_NAME_MAX];
	} thread[PAL_MAX_THREAD];

	struct {
		/* this ip is set on the vnic.
		 * if it is 0, pal would ignore the port. */
		uint32_t ip;
		uint32_t gw_ip;
		uint32_t netmask;
		/* leave this zero if you want the system to set it */
		uint8_t mac[6];
		uint8_t port_id;
		/* used for identify whether this port is a bonding interface */
		uint8_t slaves_cnt;
		/* slave port ids for this bonding interface*/
		uint8_t slaves[4];
	} port[PAL_MAX_PORT];
};

/* hash bucket used in ipgroup */
struct pal_dip_hash_bucket {
	struct pal_hlist_head hhead;
	pal_rwlock_t   rwlock;
};

/*
 * Configurations of ipgroups and dips
 */
struct ipgroup_conf {
	struct pal_hlist_head *ipg_htable;
	struct pal_dip_hash_bucket *dip_htable;

	struct pal_slab *ipg_slab;
	struct pal_slab *dip_slab;

	struct pal_ipgroup *def_ipg; /* default ip group */
	struct pal_ipgroup *pal_ipg; /* used by pal to classify IPs */
};

struct numa_conf {
	int n_worker;  /* number of workers on this numa */
	int n_receiver;/* number of receivers on this numa */
	int n_custom;  /* number of custom threads on this numa */
	int n_thread;  /* total number of threads on this numa */

	struct ipgroup_conf ipg;
};

struct cpu_conf{
	/* numa id of this cpu */
	int numa;
};

/* Arp configuration. Including arp table and arp thread config */
struct arp_conf {
	uint8_t l2_enabled;
	int tid;	/* arp thread id. PAL_MAX_THREAD if not enabled */
	struct pal_slab *skb_slab;
	/* mac table */
};

/* Vnic configuration.*/
struct vnic_conf {
	int tid;  /* Id of the vnic thread */
    struct pal_slab *dump_pool;
};

struct pal_tcp_stats {
	uint64_t rx_pkts;    /* received tcp pkts */
	uint64_t rx_bytes;   /* received tcp bytes */
	uint64_t csum_err;   /* tcp pkts whose checksum are not correct */
	uint64_t trunc_pkts; /* truncated tcp pkts */
};

struct pal_udp_stats {
	uint64_t rx_pkts;    /* received udp pkts */
	uint64_t rx_bytes;   /* received udp bytes */
	uint64_t csum_err;   /* udp pkts whose checksum are not correct */
	uint64_t trunc_pkts; /* truncated udp pkts */
};

struct pal_icmp_stats {
	uint64_t rx_pkts;    /* received icmp pkts */
	uint64_t rx_bytes;   /* received icmp bytes */
	uint64_t reply_pkts; /* icmp reply pkts sent by us. including failed ones */
	uint64_t reply_failure;  /* icmp reply pkts failed to transmit */
	uint64_t csum_err;       /* icmp pkts whose checksum are invalid */
	uint64_t trunc_pkts;     /* truncated icmp pkts */
	uint64_t not_echo_pkts;  /* none echo request icmp pkts received */
	uint64_t not_echo_bytes; /* none echo request icmp bytes received */
};

struct pal_ip_stats {
	uint64_t rx_pkts;  /* number of ip pkts received */
	uint64_t rx_bytes; /* number of ip bytes received */

	uint64_t csum_err; /* number of pkts whose checksum are not correct */
	uint64_t unknown_proto_pkts;  /* unknown l4 protocol. (not udp/tcp/icmp)*/
	uint64_t unknown_proto_bytes;
	uint64_t unknown_dst; /* number of pkts whose destination IPs are invalid */
	uint64_t trunc_pkts;  /* truncated ip packets */
	uint64_t dispatch_rtc; /* pkts dispatched by run-to-complete scheduler.*/
	uint64_t dispatch_ppl; /* pkts dispatched by pipeline scheduler. including failed ones */
	uint64_t dispatch_ppl_err; /* pkts failed to be dispatched by ppl scheduler */
	struct pal_tcp_stats tcp;
	struct pal_udp_stats udp;
	struct pal_icmp_stats icmp;
};

struct pal_arp_stats {
	uint64_t rx_pkts;    /* received arp pkts */
	uint64_t rx_bytes;   /* received arp bytes */
	uint64_t rx_reply;   /* received arp replies */
	uint64_t rx_request; /* received arp request */
	uint64_t port_err;   /* arp targted at one port but received from another port */
	uint64_t tx_reply;   /* transmitted arp reply pkts. including failed ones */
	uint64_t tx_reply_err; /* arp reply pkts failed to transmit */
	uint64_t tx_request; /* transmitted arp reply pkts. including failed ones */
	uint64_t tx_request_err; /* arp request pkts failed to transmit */
	uint64_t unknown_dst;  /* arp pkts targted at unkonwn host */
	uint64_t unknown_op;   /* arp pkts not reply or request */
};

struct pal_port_stats {
	uint64_t rx_pkts;  /* pkts received from the port */
	uint64_t rx_bytes; /* bytes received from the port */
	uint64_t trunc_pkts;   /* l2 truncated pkts */
	uint64_t tx_pkts;  /* pkts transmitted from the port, including failed ones. */
	uint64_t tx_bytes; /* bytes transmitted from the port, including failed ones. */
	uint64_t tx_err;   /* pkts failed to transmit from the port */
	uint64_t unknown_pkts; /* number of pkts whose l3 protocol are not ip or arp */
	uint64_t unknown_bytes; /* unknown l3 protocol */
};

struct pal_tap_stats {
	uint64_t totap_pkts;   /* pkts sent to tap. including failed ones */
	uint64_t totap_bytes;  /* bytes sent to tap. including failed ones */
	uint64_t totap_err_pkts;  /* pkts failed to send to tap */
	uint64_t totap_err_bytes; /* bytes failed to send to tap */
	uint64_t fromtap_pkts;    /* pkts sent from tap to physical nic */
	uint64_t fromtap_bytes;   /* bytes sent from tap to physical nic */
	uint64_t port_err;        /* pkts targeted at a tap but received
	                           * from a wrong physical port */
};

/* NOTE: all member must be type of uint64_t,
 * or pal_get_stats_summary would go wrong*/
struct pal_stats {
	struct pal_tap_stats tap;
	struct pal_ip_stats ip;
	struct pal_arp_stats arp;
	struct pal_port_stats ports[PAL_MAX_PORT];
};

#define MAX_PKT_SEND_BURST 64
struct mbuf_buffer {
    unsigned int len;
    uint64_t last_send;
    struct rte_mbuf *m_table[MAX_PKT_SEND_BURST];
};

struct thread_conf {
	pal_thread_func_t main_func;  /* main function of each thread */
	void *arg;     /* arguments of the main functions */
	char name[PAL_THREAD_NAME_MAX];
	pthread_t ptid;   /* thread id generated by libpthread */

	/* f, ret and state are used by pal_remote_launch */
	pal_thread_func_t f;
	int ret;
	uint8_t state;

	/* these two fields are uesed to issue asynchronous commands to threads */
	uint8_t cmd;
	void *cmd_arg;

	/* cycle count used to calculate cpu usage */
	uint8_t working;  /* indicates whether this thread is working or idle */
	uint64_t work_cycles;
	uint64_t idle_cycles;
	uint64_t start_cycle; /* tsc value when entering working or idle state */

	struct pal_fifo	*pkt_q[PAL_MAX_THREAD]; /* receiver -> worker/vnic/arp */

	/* slab used to allocate skbs for dumping */
	struct pal_slab *dump_skbpool;

	/*used for ip fragment*/
	struct ip_fragment_conf ip_fragment_config;

	/*used for ip reassemble*/
	struct ip_reassemble_conf ip_reassemble_config;

	int numa;
	int cpu;
	unsigned sleep;
	uint8_t dump_q;
	uint8_t mode;  /* running mode of each thread */
	uint8_t rxq[PAL_MAX_PORT];
	uint8_t txq[PAL_MAX_PORT];
    struct mbuf_buffer tx_mbuf[PAL_MAX_PORT];
    uint64_t flush_count;
	int m2s[2];  /* pipe used by master to send messages to slaves */
	int s2m[2];  /* pipe used by slaves to send messages to master */
	struct pal_stats stats;
};

/*
 * port configuration structure
 */
struct port_conf {
	struct rte_kni *vnic;
    struct pal_slab *vnic_skbpool;
	char name[RTE_KNI_NAMESIZE];
	int numa;
	uint8_t n_rxq; /* Number of rx queues allocated */
	uint8_t n_txq; /* Number of tx queues allocated */
	uint8_t port_type; /* phys port or logical port */
	uint8_t port_id;
	uint8_t gw_mac_valid;
	uint8_t status; /* port link status 1:up 0:down */
	uint8_t mac[6];
	uint8_t gw_mac[6];
	uint32_t netmask;
	uint32_t gw_ip;
	uint32_t vnic_ip;
};

/* system configuration */
struct sys_conf {
	int n_port;      /* total port count. equals to n_physport + n_logicport */
	int n_physport;  /* physical port count */
	int n_logicport; /* logical port count */
	int n_thread;    /* thread count in the system */

	struct rte_kni *dump_vnic;
};


/*
 * Global configuration struct. All pal configurations are stored in this struct.
 */
struct pal_global_config {
	struct cpu_conf *cpu[PAL_MAX_CPU];
	struct numa_conf *numa[PAL_MAX_NUMA];
	struct thread_conf *thread[PAL_MAX_THREAD];
	struct port_conf *port[PAL_MAX_PORT];
	struct arp_conf arp;
	struct vnic_conf vnic;
	struct sys_conf sys; /* system configuration */
};

extern struct pal_global_config g_pal_config;

/*
 * @brief Initilize pal configuration struct
 */
void pal_conf_init(struct pal_config *conf);

/*
 * @brief Initialize platform abstraction layer, including cpus, ipgroups,
 *        NIC ports, packet queues, threads, etc.
 * @param conf Configurations provided by caller.
 * @note This functions panics on failures, as most initialization process
 *       cannot be undone.
 */
void pal_init(struct pal_config *conf);

/*
 * @brief Start the whole program. All pal configuration must be set
 *        before calling this function
 */
int pal_start(void);

/*
 * @brief Get summarized stats. stats from all threads are summed
 */
void pal_get_stats_summary(struct pal_stats *stats);

/*
 * @brief Get stats from all threads.
 * @note 1. This function does not set stats of unused thread to 0,
 *       caller should set them to 0 before calling or ignore the
 *       data in them after returning.
 *       2. array size of stats must be no less than the max thread id
 */
void pal_get_stats(struct pal_stats *stats[]);

#endif
