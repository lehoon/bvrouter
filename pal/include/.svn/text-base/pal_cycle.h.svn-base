#ifndef _PAL_CYCLE_H_
#define _PAL_CYCLE_H_

#include "rte_cycles.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Read the TSC register.
 *
 * @return
 *   The TSC for this lcore.
 */
static inline uint64_t pal_rdtsc(void)
{
	return rte_rdtsc();
}

/**
 * Get the measured frequency of the RDTSC counter
 *
 * @return
 *   The TSC frequency for this lcore
 */
static inline uint64_t pal_get_tsc_hz(void)
{
	return rte_get_tsc_hz();
}

/**
 * Return the number of TSC cycles since boot
 *
  * @return
 *   the number of cycles
 */
static inline uint64_t pal_get_tsc_cycles(void)
{
	return rte_get_tsc_cycles();
}

/**
 * Wait at least us microseconds.
 *
 * @param us
 *   The number of microseconds to wait.
 */
static inline void pal_delay_us(unsigned us)
{
	return rte_delay_us(us);
}

/**
 * Wait at least ms milliseconds.
 *
 * @param ms
 *   The number of milliseconds to wait.
 */
static inline void pal_delay_ms(unsigned ms)
{
	rte_delay_ms(ms);
}

#ifdef __cplusplus
}
#endif

#endif /* _CYCLE_H_ */

