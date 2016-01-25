#ifndef _PALI_TIMER_H_
#define _PALI_TIMER_H_
#include <unistd.h>
#include <stdint.h>
#include "pal_timer.h"
#include "list.h"

/***
 * timer_pending - is a timer pending?
 * @timer: the timer in question
 *
 * timer_pending will tell whether a given timer is currently pending,
 * or not. Callers must ensure serialization wrt. other operations done
 * to this timer, eg. interrupt contexts, or other CPUs on SMP.
 *
 * return value: 1 if the timer is pending, 0 if not.
 */
static inline int timer_pending(const struct timer_list * timer)
{
	return timer->base_vec != NULL;
}

extern void pal_timers_init(void);

#endif
