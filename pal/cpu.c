#include <string.h>

#include <rte_lcore.h>

#include "utils.h"
#include "cpu.h"
#include "malloc.h"

/*
 * @brief alloc configuration structs for numa and cpu
 * @note this function panics on error
 */
int pal_cpu_init(void)
{
	int cpu, numa;

	memset(&g_pal_config, 0, sizeof(g_pal_config));

	/* record used numa nodes */
	for(cpu = 0; cpu < PAL_MAX_CPU; cpu++) {
		if(!rte_lcore_is_enabled(cpu))
			continue;

		numa = (int)rte_lcore_to_socket_id(cpu);
		if(numa > PAL_MAX_NUMA)
			PAL_PANIC("Numa id %d > PAL_MAX_NUMA(%d)\n", numa, PAL_MAX_NUMA);

		/* alloc cpu configuration struct */
		g_pal_config.cpu[cpu] = (struct cpu_conf *)
		               pal_zalloc_numa(sizeof(struct cpu_conf), numa);
		if(g_pal_config.cpu[cpu] == NULL)
			PAL_PANIC("alloc cpu config failed\n");
		g_pal_config.cpu[cpu]->numa = numa;

		if(g_pal_config.numa[numa] != NULL)
			continue;

		/* alloc numa configuration struct */
		g_pal_config.numa[numa] = (struct numa_conf *)
		               pal_zalloc_numa(sizeof(struct numa_conf), numa);
		if(g_pal_config.numa[numa] == NULL)
			PAL_PANIC("malloc numa config failed\n");
	}

	return 0;
}

