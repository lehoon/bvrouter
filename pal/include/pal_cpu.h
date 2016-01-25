#ifndef _PAL_CPU_H_
#define _PAL_CPU_H_


#include "pal_conf.h"
#include "pal_thread.h"
#include "pal_cycle.h"

#define pal_compiler_barrier() __asm__ __volatile__("": : :"memory")
#define	pal_mb() _mm_mfence()

static inline int pal_cpu_enabled(int cpu)
{
	return g_pal_config.cpu[cpu] != NULL;
}

/*
 * @brief Get the numa node id of a specified cpu
 * @param cpu System id of the cpu
 * @return Numa id of this cpu
 */
static inline int pal_cpu_to_numa(int cpu)
{
	return g_pal_config.cpu[cpu]->numa;
}

/*
 * @breif Get the cpu id on which the current thread runs
 */
static inline int pal_cpu_id(void)
{
	return pal_cur_thread_conf()->cpu;
}

/*
 * @breif Get the numa id on which the current thread runs
 */
static inline int pal_numa_id(void)
{
	return pal_cur_thread_conf()->numa;
}

/*
 * @brief Get next cpu in use. whether a cpu is in use
 *        is defined by user in the pal_config. if at least one thread is
 *        running on a cpu, then it is used.
 * @return The next valid cpu id or PAL_MAX_CPU
 */
static inline int pal_get_next_cpu(int i)
{
	for(i++; i < PAL_MAX_CPU; i++) {
		if(g_pal_config.cpu[i] != NULL)
			break;
	}

	return i;
}

/*
 * @brief Get next numa node in use. whether a numa node is in use
 *        is defined by user in the pal_config. if at least one thread is
 *        running on a numa, then it is valid.
 * @return The next valid numa id or PAL_MAX_NUMA
 */
static inline int pal_get_next_numa(int i)
{
	for(i++; i < PAL_MAX_NUMA; i++) {
		if(g_pal_config.numa[i] != NULL)
			break;
	}

	return i;
}

/*
 * Traverse every active cpu. Call this after pal_platform_init
 */
#define PAL_FOR_EACH_CPU(i)			\
	for (i = pal_get_next_cpu(-1);		\
	     i < PAL_MAX_CPU;			\
	     i = pal_get_next_cpu(i))

/*
 * Traverse each numa node. Use this after pal_platform_init is called
 */
#define PAL_FOR_EACH_NUMA(i)			\
	for (i = pal_get_next_numa(-1);		\
	     i < PAL_MAX_NUMA;			\
	     i = pal_get_next_numa(i))

#endif
