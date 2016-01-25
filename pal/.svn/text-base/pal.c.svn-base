#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <rte_lcore.h>
#include <rte_ethdev.h>

#include "conf.h"
#include "thread.h"
#include "utils.h"
#include "cpu.h"
#include "netif.h"
#include "ipgroup.h"
#include "receiver.h"
#include "arp.h"
#include "vnic.h"
#include "jiffies.h"
#include "timer.h"

#include <sys/prctl.h>


/*
 * @brief init hardware platform
 */
static void platform_init(const struct pal_config *conf)
{
	int ret;
	int argc = 3;
	char arg0[] = "pal";
	char arg_cores[((PAL_MAX_CPU + 3) / 4) + sizeof("-c 0x")] = "-c 0x";
	char arg_memch[16] = "-n ";
	char *argv[] = {arg0, arg_cores, arg_memch};
	int i, tid;
	unsigned bitmask;
	char hex2ascii[] = {"0123456789abcdef"};
	int cpus[PAL_MAX_CPU];
	int cpu;

	for (i = 0; i < PAL_MAX_CPU; i++)
		cpus[i] = 0;
	/* generate args for rte_eal_init "-c 0x** -n *" */
	for (tid = 0; tid < PAL_MAX_THREAD; tid++) {
		if (conf->thread[tid].mode == PAL_THREAD_NONE)
			continue;
		cpu = conf->thread[tid].cpu;
		if (cpu == -1) {
			if(tid > PAL_MAX_CPU) {
				fprintf(stderr, "invalid cpu id %d\n", tid);
				exit(-1);
			}
			cpus[tid] = 1;
		} else if (cpu < 0 || cpu >= PAL_MAX_CPU) {
			fprintf(stderr, "invalid cpu id %d\n", cpu);
			exit(-1);
		} else {
			cpus[cpu] = 1;
		}
	}

	/* generate the args like "-c 0x1f" */
	arg_cores[sizeof(arg_cores) - 1] = 0;
	bitmask = 0;
	for (cpu = 0; cpu < PAL_MAX_CPU;) {
		if (cpus[cpu] == 1) {
			bitmask |= (1 << (cpu % 4));
		}
		if (++cpu % 4 != 0)
			continue;

		arg_cores[sizeof(arg_cores) - cpu / 4 - 1] = hex2ascii[bitmask];
		bitmask = 0;
	}
	if ((PAL_MAX_CPU % 4) != 0)
		arg_cores[sizeof(arg_cores) - PAL_MAX_CPU / 4 - 2] = hex2ascii[bitmask];

	/* generate the args like "-n 2" */
	snprintf(arg_memch + strlen(arg_memch), 
	            sizeof(arg_memch) - strlen(arg_memch), 
	            "%u", conf->mem_channel);

	/* Initialise eal */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		PAL_PANIC("Cannot init EAL\n");
}

/*
 * initialize pal configuration struct
 */
static inline void pal_glb_conf_init(void)
{
	/* I know this is not necessary... */
	memset(&g_pal_config, 0, sizeof(g_pal_config));

	g_pal_config.arp.tid = PAL_MAX_THREAD;
	g_pal_config.vnic.tid = PAL_MAX_THREAD;
}


void pal_init(struct pal_config *conf)
{
	if (conf->magic != PAL_CONF_MAGIC)
		PAL_PANIC("pal_config not initialized, call pal_conf_init first\n");

	pal_glb_conf_init();
	
	/* Initialize underlying platform */
	platform_init(conf);

	/* alloc numa config struct */
	pal_cpu_init();

	/* init thread working mode */
	pal_thread_init(conf);

	pal_ipgroup_init();

	pal_ports_init(conf);

	pal_disq_init();

	pal_arp_init();

	pal_jiffies_init();

	pal_timers_init();
}

/* start the pakcet loop of pal */
int pal_start(void)
{
	int mode;
	int tid;
	unsigned port_id;
	unsigned numa;
	struct thread_conf *thconf;

	/* set main thread name */
	if (prctl(PR_SET_NAME, "pal_main", 0, 0, 0) < 0)
		PAL_PANIC("set thread pal_main failed\n");

	/* start all threads */
	PAL_FOR_EACH_THREAD (tid) {
		numa = pal_tid_to_numa(tid);
		thconf = pal_thread_conf(tid);
		mode = thconf->mode;
		if (thconf->main_func == NULL)
			PAL_PANIC("thread %u main function is NULL\n", tid);

		mode = pal_remote_launch(thconf->main_func, thconf->arg, tid);
	}

	/* Bring up dump vnic, must come after starting of vnic thread because
	 * kni needs vnic thread to handle up/down request */
	pal_bring_up_nic("dump0");

	/* Bring up all other vnics, must come after vnic threads for the same
	 * reason as dump vnic */
	if (vnic_enabled()) {
		for (port_id = 0; port_id < PAL_MAX_PORT; port_id++) {
			if (!pal_port_enabled(port_id) ||
			               pal_port_conf(port_id)->vnic == NULL)
				continue;
			pal_bring_up_nic(pal_port_conf(port_id)->name);
		}
	}

	PAL_LOG("main thread waiting for all threads\n");
	pal_wait_all_threads();
	PAL_LOG("main thread waiting for all threads over\n");

	return 0;
}

/*
 * @brief Get stats from all threads.
 * @note 1. This function does not set stats of unused thread to 0,
 *       caller should set them to 0 before calling or ignore the 
 *       data in it after returning.
 *       2. array size of stats must be no less than the thread id in use
 */
void pal_get_stats(struct pal_stats *stats[])
{
	int tid;

	PAL_FOR_EACH_THREAD (tid) {
		memcpy(stats[tid], &pal_thread_conf(tid)->stats, sizeof(*stats[0]));
	}
}

void pal_get_stats_summary(struct pal_stats *stats)
{
	int tid;
	unsigned i;
	uint64_t *p, *q;

	memset(stats, 0, sizeof(*stats));
	PAL_FOR_EACH_THREAD (tid) {
		p = (uint64_t *)stats;
		q = (uint64_t *)&pal_thread_conf(tid)->stats;
		/* perfoemance here is not critical but we can still consider 
		 * using AVX instrunctions */
		for (i = 0; i < (sizeof(*stats) / sizeof(*p)); i++) {
			*p += *q;
		}
	}
}


