#ifndef _PAL_TIMER_H_
#define _PAL_TIMER_H_
#include "pal_list.h"

struct timer_list {
	struct pal_list_head entry;
	struct pal_list_head *base_vec;
	unsigned long long expires;
	unsigned long magic;
	void (*function)(unsigned long);
	unsigned long data;
};

#define TIMER_MAGIC	0x4b87ad6e

#define TIMER_INITIALIZER(_function, _expires, _data) {	\
		.function = (_function),			\
		.expires = (_expires),				\
		.data = (_data),				\
		.base_vec = NULL,				\
		.magic = TIMER_MAGIC,				\
}

/*
 * @brief Timer handling function. For all threads except custom threads,
 *        this function is called by pal. But in a custom thread, the whole
 *        thread is not under pal's control, so applications need to call
 *        this function by themselves.
 * @param budget How many timers should we deal with.
 */
extern void run_timer(int budget);

/***
 * init_timer - initialize a timer.
 * @timer: the timer to be initialized
 *
 * init_timer() must be done to a timer prior calling *any* of the
 * other timer functions.
 */
static inline void init_timer(struct timer_list * timer)
{
	timer->base_vec = NULL;
	timer->magic = TIMER_MAGIC;
}

/**
 * @brief modify a timer's timeout
 * @param timer The timer to be modified
 * @param expires New timeout in jiffies
 *
 * mod_timer() is a more efficient way to update the expire field of an
 * active timer (if the timer is inactive it will be activated)
 *
 * mod_timer(timer, expires) is equivalent to:
 *
 *     del_timer(timer); timer->expires = expires; add_timer(timer);
 *
 * Note that if there are multiple unserialized concurrent users of the
 * same timer, then mod_timer() is the only safe way to modify the timeout,
 * since add_timer() cannot modify an already running timer.
 *
 * The function returns whether it has modified a pending timer or not.
 * (ie. mod_timer() of an inactive timer returns 0, mod_timer() of an
 * active timer returns 1.)
 */
extern int mod_timer(struct timer_list *timer, uint64_t expires);

extern int __mod_timer(struct timer_list *timer, uint64_t expires);


/***
 * add_timer - start a timer
 * @timer: the timer to be added
 *
 * The kernel will do a ->function(->data) callback from the
 * timer interrupt at the ->expired point in the future. The
 * current time is 'jiffies'.
 *
 * The timer's ->expired, ->function (and if the handler uses it, ->data)
 * fields must be set prior calling this function.
 *
 * Timers with an ->expired field in the past will be executed in the next
 * timer tick.
 */
static inline void add_timer(struct timer_list *timer)
{
	__mod_timer(timer, timer->expires);
}

/**
 * @brief Deactive a timer.
 * @param timer The timer to be deactivated
 *
 * del_timer() deactivates a timer - this works on both active and inactive
 * timers.
 *
 * The function returns whether it has deactivated a pending timer or not.
 * (ie. del_timer() of an inactive timer returns 0, del_timer() of an
 * active timer returns 1.)
 */
extern int del_timer(struct timer_list * timer);


#endif
