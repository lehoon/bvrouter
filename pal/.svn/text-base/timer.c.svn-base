#include "timer.h"
#include "list.h"
#include "jiffies.h"
#include "utils.h"
#include "thread.h"

#define TVN_BITS (7)
#define TVR_BITS (18)
#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)
#define TVN_MASK (TVN_SIZE - 1)
#define TVR_MASK (TVR_SIZE - 1)

struct tvec {
	struct pal_list_head vec[TVN_SIZE];
};

struct tvec_root {
	struct pal_list_head vec[TVR_SIZE];
};

struct tvec_base {
	unsigned long long timer_jiffies;
	struct timer_list *running_timer;
	struct tvec_root tv1;
	struct tvec tv2;
	struct tvec tv3;
};

PAL_DEFINE_PER_THREAD(struct tvec_base, _tvec_base);

static inline void init_tvec_t(struct tvec *tv)
{
	int j;
	for (j = 0; j < TVN_SIZE; j++) {
		PAL_INIT_LIST_HEAD(&tv->vec[j]);
	}

	return;
}

static inline void  init_tvec_root_t(struct tvec_root *tv)
{
	int j;
	for (j = 0; j < TVR_SIZE; j++) {
		PAL_INIT_LIST_HEAD(&tv->vec[j]);
	}
	return;
}

static struct pal_list_head *get_new_vec_head(struct tvec_base *base, 
                                              uint64_t expires)
{
	int i;
	uint64_t idx = expires - base->timer_jiffies;
	struct pal_list_head *vec;

	if (idx < TVR_SIZE) {
		i = expires & TVR_MASK;
		vec = base->tv1.vec + i;
	} else if(idx < (1 << (TVR_BITS + TVN_BITS))) {
		i = (expires >> TVR_BITS) & TVN_MASK;
		vec = base->tv2.vec + i;
	} else if((long long)idx < 0) {
		/*
		 * Can happen if you add a timer with expires == jiffies,
		 * or you set a timer to go off in the past
		 */
		vec = base->tv1.vec + ((base->timer_jiffies + 1) & TVR_MASK);
	} else {
		/* If the timeout is larger than 0xffffffff on 64-bit
		 * architectures then we use the maximum timeout:
		 */
		if(idx > 0xffffffffUL) {
			idx = 0xffffffffUL;
			expires = idx + base->timer_jiffies;
		}
		i = (expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK;
		vec = base->tv3.vec + i;
	}

	return vec;
}

/*
 * this is not needed if there is no bug in the program.
 * consider removing this function.
 */
static inline int mod_check_timer(struct timer_list *timer)
{
	if (unlikely(timer->magic != TIMER_MAGIC))
		return -1;

	if (unlikely(timer->function == NULL))
		return -1;

	return 0;
}

static inline int del_check_timer(struct timer_list *timer)
{
	if (unlikely(timer->magic != TIMER_MAGIC))
		return -1;

	return 0;
}

/* make sure timer->base_vec==NULL when you call attach_timer
 * make sure that timer is not in any list when you call attach_timer
 * make sure nobody else changes the timer when attach_timer is running
 */
static inline void attach_timer(struct timer_list *timer, 
                                struct pal_list_head *new_vec_head)
{
	pal_list_add_tail(&timer->entry, new_vec_head);
	timer->base_vec = new_vec_head;
}


static inline int detach_timer(struct timer_list * timer)
{
	struct pal_list_head *base_vec;
	base_vec = timer->base_vec;
	if(!base_vec)
		return 0;

	pal_list_del(&timer->entry);
	timer->base_vec = NULL;

	return 1;
}

/* return -1 if failed
 * return 2 on success && the timer was not attached before
 * return 1 on success && take timer from other base to my base
 * return 0 on success && not move timer from one base to another
 */
int __mod_timer(struct timer_list *timer, uint64_t expires)
{
	int ret = 0;
	struct tvec_base *host_base;
	struct pal_list_head *new_vec_head = NULL, *old_vec_head = NULL;

	/* TODO: delete the check when going online */
	if (mod_check_timer(timer) < 0 )
		return -1;

	timer->expires = expires;
	old_vec_head = timer->base_vec;
	host_base = &PAL_PER_THREAD(_tvec_base);
	new_vec_head = get_new_vec_head(host_base, expires);
	if (new_vec_head == old_vec_head )
		return 0;

	if (old_vec_head) {
		pal_list_del(&timer->entry);
		ret = 2;
	} else {
		ret = 1;
	}
	attach_timer(timer, new_vec_head);

	return ret;
}


/***
 * mod_timer - modify a timer's timeout
 * @timer: the timer to be modified
 *
 * mod_timer is a more efficient way to update the expire field of an
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
int mod_timer(struct timer_list *timer, uint64_t expires)
{
	/*
	 * This is a common optimization triggered by the
	 * networking code - if the timer is re-modified
	 * to be the same thing then just return:
	 */
	if (timer->expires == expires && timer_pending(timer))
		return 1;

	return __mod_timer(timer, expires);
}

int del_timer(struct timer_list *timer)
{
	if(del_check_timer(timer) < 0)
		return -1;

	return detach_timer(timer);
}


static int cascade(struct tvec_base *base, struct tvec *tv, int index)
{
	/* cascade all the timers from tv up one level */
	struct pal_list_head *head, *curr;
	struct pal_list_head *new_vec_head, *old_vec_head;
	struct timer_list *tmp;

	old_vec_head = tv->vec + index;
	head = old_vec_head;
	curr = head->next;
	while (curr != head) {
		tmp = pal_list_entry(curr, struct timer_list, entry);
		curr = curr->next;
		new_vec_head = get_new_vec_head(base, tmp->expires);
		if (new_vec_head != old_vec_head) {
			__pal_list_del(tmp->entry.prev, tmp->entry.next);
			attach_timer(tmp, new_vec_head);
		}
	}
	return index;
}

#define INDEX(N) (base->timer_jiffies >> (TVR_BITS + N * TVN_BITS)) & TVN_MASK

void run_timer(int budget)
{
	int index;
	uint64_t jiffies_local = jiffies;
	struct tvec_base *base = &PAL_PER_THREAD(_tvec_base);
	struct timer_list *timer = NULL;
	struct pal_list_head *vec_head = NULL;
	struct pal_list_head *head = NULL;
	/* @TODO use ctx to cfg this */

	while (budget > 0 && (jiffies_local >= base->timer_jiffies)) {
		index = base->timer_jiffies & TVR_MASK;
		vec_head = base->tv1.vec + index;
		head = vec_head;
		/* Cascade timers: */
		if ((index == 0) && ((cascade(base, &base->tv2, INDEX(0))) == 0)) {
			cascade(base, &base->tv3, INDEX(1));
		}
		while (!pal_list_empty(head) && (budget--)>0) {
			void (*fn)(unsigned long);
			unsigned long data;
			timer = pal_list_entry(head->next, struct timer_list, entry);
			fn = timer->function;
			data = timer->data;

			pal_list_del(&timer->entry);
			timer->base_vec = NULL;
			fn(data);
		}
		if (pal_list_empty(head))
			base->timer_jiffies++;
	}

	return;
}

static int init_timers(__unused void *data)
{
	struct tvec_base *tb = &PAL_PER_THREAD(_tvec_base);

	init_tvec_root_t(&tb->tv1);
	init_tvec_t(&tb->tv2);
	init_tvec_t(&tb->tv3);
	tb->timer_jiffies = jiffies;
	tb->running_timer = NULL;

	return 0;
}

void pal_timers_init(void)
{
	int tid;

	PAL_FOR_EACH_THREAD (tid) {
		pal_remote_launch(init_timers, NULL, tid);
	}

	pal_wait_all_threads();
}

