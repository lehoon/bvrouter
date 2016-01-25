#ifndef _PAL_THREAD_H_
#define _PAL_THREAD_H_
#include "pal_utils.h"
#include "pal_conf.h"
#include "pal_cycle.h"

/*
 * Thread running mode. Each thread is bound to one cpu core and its thread id
 * is identical to the cpu system id. Normally, there is only one thread runs
 * on each cpu, but you can define a custom thread and create multiple threads,
 * then bind them to one cpu.
 * NONE:     This cpu is free, no pal threads is running on it.
 * RECEIVER: This cpu runs as a receiver. It receives packets and deliver
 *           them to workers.
 * WORKER:   This cpu runs as a worker. It get packtes delivered by receivers
 *           and do the process work. The packet handler function is registerd
 *           by applications with ip group functions.
 * CUSTOM:   This cpu runs an application defined routine. Caller must provide
 *           a function when register a custom thread.
 */
enum pal_thread_mode {
	PAL_THREAD_NONE	= 0,
	PAL_THREAD_RECEIVER,
	PAL_THREAD_WORKER,
	PAL_THREAD_ARP,
	PAL_THREAD_VNIC,
	PAL_THREAD_CUSTOM,
	PAL_THERAD_MODE_MAX,
};

extern void pal_thread_init(const struct pal_config *conf);


/*
 * Macro to define a per cpu variable "var" of type "type", don't
 * use keywords like "static" or "volatile" in type, just prefix the
 * whole macro.
 */
#define PAL_DEFINE_PER_THREAD(type, name)			\
	__thread __typeof__(type) __per_cpu_##name

/*
 * Macro to declare an extern per cpu variable "var" of type "type"
 */
#define PAL_DECLARE_PER_THREAD(type, name)			\
	extern __thread __typeof__(type) __per_cpu_##name

/**
 * Read/write the per-cpu variable value
 */
#define PAL_PER_THREAD(name) (__per_cpu_##name)

PAL_DECLARE_PER_THREAD(int, _thread_id);

/* thread conf structure of each thread. accessed frequently */
PAL_DECLARE_PER_THREAD(struct thread_conf *, _thconf);

/* struct used to collect cpu usages */
struct pal_cpu_stats {
	uint64_t cpu_usage[PAL_MAX_THREAD];
};

extern void pal_get_cpu_usage(struct pal_cpu_stats *cpu_stats);

/*
 * @breif Get id of this thread
 */
static inline int pal_thread_id(void)
{
	return PAL_PER_THREAD(_thread_id);
}

/*
 * @brief Get the configuration struct of a thread.
 * @return pointer to thread_conf. or NULL if thread is not enabled.
 * @note Caller must ensure that tid falls between 0 and PAL_MAX_THREAD-1.
 */
static inline struct thread_conf *pal_thread_conf(int tid)
{
	return g_pal_config.thread[tid];
}

/*
 * @brief Test whether a thread is enabled
 * @param Id of the thread
 * @return True if thread is enabled. False otherwise
 * @note Caller must ensure that tid falls between 0 and PAL_MAX_THREAD-1
 */
static inline int pal_thread_enabled(int tid)
{
	return pal_thread_conf(tid) != NULL;
}

/*
 * @brief Get next thread.
 * @return The next valid thread sequence or PAL_MAX_THREAD
 */
static inline int pal_get_next_thread(int i)
{
	for(i++; i < PAL_MAX_THREAD; i++) {
		if(pal_thread_enabled(i))
			break;
	}

	return i;
}

/*
 * @brief Get next worker thread.
 * @return The next valid thread sequence or PAL_MAX_THREAD
 */
static inline int pal_get_next_worker(int i)
{
	for(i++; i < PAL_MAX_THREAD; i++) {
		if(pal_thread_enabled(i) 
		             && pal_thread_conf(i)->mode == PAL_THREAD_WORKER)
			break;
	}

	return i;
}

/*
 * @brief Get next receiver thread.
 * @return The next valid thread sequence or PAL_MAX_THREAD
 */
static inline int pal_get_next_receiver(int i)
{
	for(i++; i < PAL_MAX_THREAD; i++) {
		if(pal_thread_enabled(i) 
		             && pal_thread_conf(i)->mode == PAL_THREAD_RECEIVER)
			break;
	}

	return i;
}

/**
 * Launch a function on another thread.
 *
 * Sends a message to a slave thread (identified by the tid) that
 * is in the WAIT state (this is true after the first call to
 * pal_init()). This can be checked by first calling
 * pal_wait_thread(tid).
 *
 * When the remote thread receives the message, it switches to
 * the RUNNING state, then calls the function f with argument arg. Once the
 * execution is done, the remote thread switches to a FINISHED state and
 * the return value of f is stored in a local variable to be read using
 * pal_wait_thread().
 *
 * The MASTER thread returns as soon as the message is sent and knows
 * nothing about the completion of f.
 *
 * Note: This function is not designed to offer optimum
 * performance. It is just a practical way to launch a function on
 * another thread at initialization time.
 *
 * @param f
 *	 The function to be called.
 * @param arg
 *	 The argument for the function.
 * @param tid
 *	 The identifier of the thread on which the function should be executed.
 * @return
 *	 0: Success. Execution of function f started on the remote thread.
 *	 -1: Failed to launch a remote thread.
 */
int pal_remote_launch(int (*f)(void *), void *arg, int tid);

/**
 * Wait until an thread finishes its job.
 *
 * To be executed on the MASTER thread only.
 *
 * If the slave thread identified by the tid is in a FINISHED state,
 * switch to the WAIT state. If the thread is in RUNNING state, wait until
 * the thread finishes its job and moves to the FINISHED state.
 *
 * @param tid
 *	 The identifier of the thread.
 * @return
 *	 - 0: If the thread identified by the slave_id is in a WAIT state.
 *	 - The value that was returned by the previous remote launch
 *	   function call if the thread identified by the tid was in a
 *	   FINISHED or RUNNING state. In this case, it changes the state
 *	   of the thread to WAIT.
 */
int pal_wait_thread(int tid);

/*
 * Traverse each numa thread. Use this after pal_platform_init is called
 */
#define PAL_FOR_EACH_THREAD(i)			\
	for (i = pal_get_next_thread(-1);	\
	     i < PAL_MAX_THREAD;		\
	     i = pal_get_next_thread(i))

#define PAL_FOR_EACH_WORKER(i)			\
	for (i = pal_get_next_worker(-1);	\
	     i < PAL_MAX_THREAD;		\
	     i = pal_get_next_worker(i))

#define PAL_FOR_EACH_RECEIVER(i)			\
	for (i = pal_get_next_receiver(-1);	\
	     i < PAL_MAX_THREAD;		\
	     i = pal_get_next_receiver(i))

/*
 * @brief Get numa id of a thread
 */
static inline int pal_tid_to_numa(int tid)
{
	return pal_thread_conf(tid)->numa;
}

/*
 * @brief Get the mode of a thread
 */
static inline enum pal_thread_mode pal_thread_mode(int tid)
{
	return pal_thread_conf(tid)->mode;
}

/*
 * @brief Get configuration struct of current thread
 */
static inline struct thread_conf *pal_cur_thread_conf(void)
{
	return PAL_PER_THREAD(_thconf);
}

/*
 * Do a pal_wait_thread() for every thread. The return values are
 * ignored.
 */
static inline void pal_wait_all_threads(void)
{
	int tid;

	PAL_FOR_EACH_THREAD(tid) {
		pal_wait_thread(tid);
	}
}

/*
 * @breif Call this function when cpu is about to do some work, so that pal
 *        can calculate the cpu usage.
 */
static inline void pal_cpu_work(void)
{
	struct thread_conf *thconf = pal_cur_thread_conf();
	uint64_t tsc;

	/* already in working mode. do not enter again */
	if (thconf->working)
		return;

	thconf->working = 1;
	tsc = pal_rdtsc();
	thconf->idle_cycles += tsc - thconf->start_cycle;
	thconf->start_cycle = tsc;
}


/*
 * @breif Call this function when cpu is about to be idle, so that pal
 *        can calculate the cpu usage.
 */
static inline void pal_cpu_idle(void)
{
	struct thread_conf *thconf = pal_cur_thread_conf();
	uint64_t tsc;

	/* already in idle mode. do not enter again */
	if (!thconf->working)
		return;

	thconf->working = 0;
	tsc = pal_rdtsc();
	thconf->work_cycles += tsc - thconf->start_cycle;
	thconf->start_cycle = tsc;
}

#endif
