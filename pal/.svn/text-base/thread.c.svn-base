#include <unistd.h>
#include <stdio.h>
#define __USE_GNU /* CPU_ZERO needs this */
#include <sched.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <errno.h>

#include <rte_lcore.h>

#include "thread.h"
#include "conf.h"
#include "utils.h"
#include "receiver.h"
#include "worker.h"
#include "arp.h"
#include "vnic.h"
#include "malloc.h"

/**
 * State of an thread.
 */
enum pal_thread_state {
	PAL_THREAD_WAIT,       /* waiting a new command */
	PAL_THREAD_RUNNING,    /* executing command */
	PAL_THREAD_FINISHED,   /* command executed */
};

/*
 * @brief Used in pal_create_thread_on_cpu, this is called a boot thread.
 *        This function bind it self to the specified cpu, and then invoke
 *        the real thread function
 */
static void *boot_thread(void *data)
{
	int tid = PAL_MAX_THREAD, cpu;
	pthread_t ptid;
	pal_thread_func_t func = (pal_thread_func_t)data;
	struct thread_conf *thconf = NULL;

	ptid = pthread_self();

	/* retrieve our tid from the configuration structure */
	PAL_FOR_EACH_THREAD (tid) {
		thconf = pal_thread_conf(tid);
		if (thconf == NULL)
			continue;

		if (thconf->ptid == ptid)
			break;
	}
	if (tid == PAL_MAX_THREAD)
		PAL_PANIC("Cannot get thread id\n");

	cpu = thconf->cpu;

	/* set _lcore_id for dpdk so that those dpdk functions works well
	 * TODO: reconsider whether we need this */
	RTE_PER_LCORE(_lcore_id) = cpu;
	PAL_PER_THREAD(_thread_id) = tid;

	func(NULL);

	return NULL;
}


/*
 * create a new thread on a specified cpu
 */
static int pal_spawn_thread(pal_thread_func_t func, int cpu, pthread_t *tid)
{
	int r;
	cpu_set_t cpuset;
	pthread_attr_t attr;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);

	r = pthread_attr_init(&attr);
	if (r != 0) {
		PAL_ERROR("init attr for new thread failed\n");
		return -1;
	}

	r = pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset);
	if (r != 0) {
		PAL_ERROR("set cpu affinity for new thread failed\n");
		return -1;
	}

	if (pthread_create(tid == NULL?NULL:tid, &attr, boot_thread, (void *)func) != 0)
		PAL_PANIC("Create thread failed (pthred).");

	return 0;
}

/* main loop of threads */
static int pal_thread_loop(__unused void *arg)
{
	char c;
	int n, ret;
	int m2s, s2m;
	struct thread_conf *thconf = pal_thread_conf(pal_thread_id());

	PAL_LOG("Thread %d is ready on cpu %d\n", pal_thread_id(), thconf->cpu);

	m2s = thconf->m2s[0];
	s2m = thconf->s2m[1];

	/* read on our pipe to get commands */
	while (1) {
		void *fct_arg;

		/* wait command */
		do {
			n = read(m2s, &c, 1);
		} while (n < 0 && errno == EINTR);

		if (n <= 0)
			PAL_PANIC("cannot read on configuration pipe\n");

		thconf->state = PAL_THREAD_RUNNING;

		/* send ack */
		n = 0;
		while (n == 0 || (n < 0 && errno == EINTR))
			n = write(s2m, &c, 1);
		if (n < 0)
			PAL_PANIC("cannot write on configuration pipe\n");

		if (thconf->f == NULL)
			PAL_PANIC("NULL function pointer\n");

		/* call the function and store the return value */
		fct_arg = thconf->arg;
		ret = thconf->f(fct_arg);
		thconf->ret = ret;
		rte_wmb();
		thconf->state = PAL_THREAD_FINISHED;
	}

	/* should never return */
	return 0;
}

/*
 * @brief set the name of a thread;
 */
static int thread_name_init(void *data)
{
	char *user_name = (char *)data;
	char name[PAL_THREAD_NAME_MAX];
	int tid = pal_thread_id();
	int mode = pal_thread_mode(tid);

	/* if user set a name explicitly, use it */
	if (user_name[0] != '\0') {
		/* add a 0 in the end to protect the memory */
		user_name[PAL_THREAD_NAME_MAX - 1] = 0;
		if (prctl(PR_SET_NAME, user_name, 0, 0, 0) < 0)
			PAL_PANIC("set name for thread %d failed\n", tid);
		return 0;
	}

	/* user does not set any name, generate one */
	switch (mode) {
	case PAL_THREAD_WORKER:
		snprintf(name, PAL_THREAD_NAME_MAX, "pal_worker_%d", tid);
		break;
	case PAL_THREAD_RECEIVER:
		snprintf(name, PAL_THREAD_NAME_MAX, "pal_receiver_%d", tid);
		break;
	case PAL_THREAD_CUSTOM:
		snprintf(name, PAL_THREAD_NAME_MAX, "pal_custom_%d", tid);
		break;
	case PAL_THREAD_ARP:
		snprintf(name, PAL_THREAD_NAME_MAX, "pal_arp_%d", tid);
		break;
	case PAL_THREAD_VNIC:
		snprintf(name, PAL_THREAD_NAME_MAX, "pal_vnic_%d", tid);
		break;
	default:
		PAL_PANIC("unknown thread mode: %d\n", mode);
	}

	if (prctl(PR_SET_NAME, name, 0, 0, 0) < 0)
		PAL_PANIC("set name for thread %d failed\n", tid);

	return 0;
}

/*
 * @brief Assign per-thread thread_conf pointer;
 */
static int thconf_ptr_init(void *data)
{
	PAL_PER_THREAD(_thconf) = (struct thread_conf *)data;

	return 0;
}

/*
 * @brief init working mode of each thread
 * @node this function panics on error
 */
void pal_thread_init(const struct pal_config *conf)
{
	int cpu, tid, ret, cpus[PAL_MAX_CPU];
	unsigned mode, numa;
	char name[PAL_THREAD_NAME_MAX];
	struct thread_conf *thconf;
	struct numa_conf *numa_conf;
	struct rte_mempool *pktmbuf_pool;

	BUILD_BUG_ON(PAL_MAX_THREAD > 127);

	/* disable arp and vnic by default */
	g_pal_config.arp.tid = PAL_MAX_THREAD;
	g_pal_config.vnic.tid = PAL_MAX_THREAD;

	memset(cpus, 0, sizeof(cpus));
	for (tid = 0; tid < PAL_MAX_THREAD; tid++) {
		if (conf->thread[tid].mode == PAL_THREAD_NONE)
			continue;

		cpu = conf->thread[tid].cpu;
		if (cpu == -1)
			cpu = tid;
		if (!pal_cpu_enabled(cpu))
			PAL_PANIC("thread %d's cpu %d not enabled\n", tid, cpu);
		cpus[cpu]++;
		numa = pal_cpu_to_numa(cpu);
		numa_conf = g_pal_config.numa[numa];
		numa_conf->n_thread++;

		/* alloc configuration struct for thread config */
		thconf = (struct thread_conf *)pal_zalloc_numa(sizeof(*thconf), numa);
		if (thconf == NULL)
			PAL_PANIC("alloc thread conf failed\n");
		g_pal_config.thread[tid] = thconf;

		mode = conf->thread[tid].mode;
		thconf->mode = mode;
		thconf->cpu = cpu;
		thconf->numa = numa;
		switch (mode) {
		case PAL_THREAD_CUSTOM:
			if (conf->thread[tid].func == NULL) {
				PAL_PANIC("custom thread %d func NULL\n", tid);
			}
			thconf->main_func = conf->thread[tid].func;
			thconf->arg = conf->thread[tid].arg;
			numa_conf->n_custom++;
			break;
		case PAL_THREAD_RECEIVER:
			thconf->main_func = receiver_loop;
			thconf->sleep = conf->thread[tid].sleep;
			numa_conf->n_receiver++;

			/*create indirect_pool for ip_fragmentation */
			snprintf(name, sizeof(name), "indirect_pool_%d", tid);
			pktmbuf_pool = rte_mempool_create(name, 4096*8, MBUF_SIZE,
				0, sizeof(struct rte_pktmbuf_pool_private),
				rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init,
				NULL, numa, MEMPOOL_F_SC_GET);
			if (pktmbuf_pool == NULL)
				PAL_PANIC("Could not initialise mbuf pool\n");

			thconf->ip_fragment_config.rxqueue.indirect_pool = pktmbuf_pool;

			/*init for ip reassembe*/
			thconf->ip_reassemble_config.death_row.cnt = 0;

			break;
		case PAL_THREAD_WORKER:
			thconf->main_func = worker_loop;
			thconf->sleep = conf->thread[tid].sleep;
			numa_conf->n_worker++;
			break;
		case PAL_THREAD_ARP:
			if (g_pal_config.arp.tid != PAL_MAX_THREAD)
				PAL_PANIC("More than one arp thread found\n");
			g_pal_config.arp.tid = tid;
			thconf->main_func = arp_loop;
			if (conf->l2_enabled)
				pal_enable_l2(tid);
			break;
		case PAL_THREAD_VNIC:
			if (vnic_enabled())
				PAL_PANIC("More than one tap thread found\n");
			thconf->main_func = vnic_loop;
			pal_enable_vnic(tid);
			break;
		default:
			PAL_PANIC("invliad thread mode: %u\n", mode);
		}

		/* each thread has a dumpq, althgough some are never used */
		thconf->dump_q = g_pal_config.sys.n_thread;
		g_pal_config.sys.n_thread++;
		snprintf(name, sizeof(name), "dump_skb_%d", tid);
		thconf->dump_skbpool = pal_skb_slab_create_numa(name, 2048, pal_tid_to_numa(tid));
		if (thconf->dump_skbpool == NULL)
			PAL_PANIC("create dump skbpool failed\n");

		/*
		 * create communication pipes between master thread
		 * and children
		 */
		if (pipe(thconf->m2s) < 0)
			PAL_PANIC("Cannot create pipe\n");
		if (pipe(thconf->s2m) < 0)
			PAL_PANIC("Cannot create pipe\n");

		thconf->state = PAL_THREAD_WAIT;

		if (cpus[cpu] > 1 || (unsigned)cpu == rte_lcore_id()) {
			/* This cpu has more than one thread, use pthread to
			 * create new thread. */
			ret = pal_spawn_thread(pal_thread_loop, cpu,
			                      &pal_thread_conf(tid)->ptid);
			if (ret < 0) {
				PAL_PANIC("create thread %d failed\n", tid);
			}
		} else {
			/* first thread on this cpu. use dpdk thread */
			thconf->ptid = lcore_config[cpu].thread_id;
			/* First thread on this cpu, just use DPDK thread. */
			rte_eal_remote_launch((int (*)(void *))boot_thread,
			                             pal_thread_loop, cpu);
		}
	}

	PAL_FOR_EACH_THREAD (tid) {
		memcpy(name, conf->thread[tid].name, PAL_THREAD_NAME_MAX);
		pal_remote_launch(thread_name_init, name, tid);
	}
	pal_wait_all_threads();

	PAL_FOR_EACH_THREAD (tid) {
		pal_remote_launch(thconf_ptr_init, pal_thread_conf(tid), tid);
	}
	pal_wait_all_threads();

	if (g_pal_config.arp.tid == PAL_MAX_THREAD) {
		PAL_PANIC("No arp thread specified\n");
	}

	if (g_pal_config.vnic.tid == PAL_MAX_THREAD) {
		PAL_PANIC("No vnic thread specified\n");
	}
}

/*
 * Send a message to a slave thread identified by tid to call a
 * function f with argument arg. Once the execution is done, the
 * remote thread switch in FINISHED state.
 */
int pal_remote_launch(int (*f)(void *), void *arg, int tid)
{
	int n;
	char c = 0;
	struct thread_conf *thconf = pal_thread_conf(tid);
	int m2s = thconf->m2s[1];
	int s2m = thconf->s2m[0];

	if (thconf->state != PAL_THREAD_WAIT) {
		PAL_LOG("state wrong \n");
		return -1;
	}

	thconf->f = f;
	thconf->arg = arg;

	/* send message */
	n = 0;
	while (n == 0 || (n < 0 && errno == EINTR)) {
		n = write(m2s, &c, 1);
	}
	if (n < 0)
		PAL_PANIC("Sending start message to remote thread failed.\n");

	/* wait ack */
	do {
		n = read(s2m, &c, 1);
	} while (n < 0 && errno == EINTR);

	if (n <= 0)
		PAL_PANIC("Reading ack message from remote thread failed.\n");

	return 0;
}

/*
 * Wait until a thread finished its job.
 */
int pal_wait_thread(int tid)
{
	struct thread_conf *thconf = pal_thread_conf(tid);

	if (thconf->state == PAL_THREAD_WAIT)
		return 0;

	while (thconf->state != PAL_THREAD_WAIT &&
	       thconf->state != PAL_THREAD_FINISHED)
		usleep(100000);

	rte_rmb();

	/* we are in finished state, go to wait state */
	thconf->state = PAL_THREAD_WAIT;
	return thconf->ret;
}

/*
 * @brief Get cpu usage of all threads
 * @note Cpu usage information is always valid for worker/receiver threads.
 *       For other threads, use linux standard way to get cpu usage.
 * @note This function calcuates the average cpu usage from last time the
 *       function is called. So if you want cpu usage of the latest second,
 *       be sure to call this function once every second.
 */
void pal_get_cpu_usage(struct pal_cpu_stats *cpu_stats)
{
	int tid;

	PAL_FOR_EACH_WORKER (tid) {
		pal_thread_conf(tid)->cmd_arg = &cpu_stats->cpu_usage[tid];
		pal_mb();
		pal_thread_conf(tid)->cmd = PAL_THCMD_GET_CPUUSAGE;
	}

	PAL_FOR_EACH_RECEIVER (tid) {
		pal_thread_conf(tid)->cmd_arg = &cpu_stats->cpu_usage[tid];
		pal_mb();
		pal_thread_conf(tid)->cmd = PAL_THCMD_GET_CPUUSAGE;
	}

	PAL_FOR_EACH_THREAD (tid) {
		while (pal_thread_conf(tid)->cmd != PAL_THCMD_NOCMD)
			usleep(1000);
	}

#if 0
	int tid;
	struct thread_conf *thconf;
	uint64_t total_cycles;
	uint64_t tsc;

	PAL_FOR_EACH_THREAD (tid) {
		tsc = pal_rdtsc();
		thconf = pal_thread_conf(tid);
		total_cycles = thconf->work_cycles + thconf->idle_cycles
				+ tsc - thconf->start_cycle;
		if (thconf->working) {
			thconf->work_cycles += tsc - thconf->start_cycle;
		}
		if (total_cycles == 0) {
			cpu_stats->cpu_usage[tid] = 0;
		} else {
			cpu_stats->cpu_usage[tid] = thconf->work_cycles * 100 / total_cycles;
			PAL_DEBUG("----thread %d, usage: %lu/%lu\n", tid, thconf->work_cycles, total_cycles);
		}

		thconf->work_cycles = 0;
		thconf->idle_cycles = 0;
		thconf->start_cycle = tsc;
	}
#endif
}


/*
 * @brief handle commands issued by other threads.
 */
void pal_thread_handle_cmd(uint8_t cmd, void *arg)
{
	/* TODO: reorginize this funtion when there are more commands */
	if (cmd == PAL_THCMD_GET_CPUUSAGE) {
		uint64_t *usage = (uint64_t *)arg;
		struct thread_conf *thconf;
		uint64_t total_cycles;
		uint64_t tsc;

		tsc = pal_rdtsc();
		thconf = pal_cur_thread_conf();
		total_cycles = thconf->work_cycles + thconf->idle_cycles
				+ tsc - thconf->start_cycle;
		if (total_cycles == 0) {
			*usage = 0;
		} else {
			if (thconf->working) {
				thconf->work_cycles += tsc - thconf->start_cycle;
			}
			*usage = thconf->work_cycles * 100 / total_cycles;
			/* PAL_DEBUG("----thread %d, usage: %lu/%lu\n", pal_thread_id(),
					thconf->work_cycles, total_cycles); */
		}

		thconf->work_cycles = 0;
		thconf->idle_cycles = 0;
		thconf->start_cycle = tsc;
	}
}

