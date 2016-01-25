#ifndef _COMMON_INCLUDES_H
#define _COMMON_INCLUDES_H

//system header includes
#include <stdint.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <glob.h>
#include <libgen.h>
#include <syslog.h>
#include <popt.h>
#include <time.h>

//dpdk header includes
#include <rte_common.h>
#include <rte_common_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_rwlock.h>
#include <rte_spinlock.h>
#include <rte_eth_bond.h>

#endif
