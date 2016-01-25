#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include "jiffies.h"
#include "utils.h"

/* use a global varible to store jiffies.
 * reconsider is it more cache friendly to use a per thread varible */
uint64_t jiffies;

/* miniutes since epoch */
uint64_t g_miniutes;

void pal_jiffies_init(void)
{
	BUILD_BUG_ON(HZ > 1000000 || HZ < 10);
	struct timeval tv;

	gettimeofday(&tv, NULL);

	/* the original form of the expression was:
	 * jiffies = (tv.tv_sec * 1000000 + tv.tv_usec) / (1000000 / HZ)
	 * we transformed it to avoid overflow problem */
	jiffies = tv.tv_sec * HZ + (uint64_t)tv.tv_usec * HZ / 1000000;
	g_miniutes = jiffies / (60 * HZ);
}

/*
 * update jiffies according to gettimeofday
 */
void update_jiffies(void)
{
	struct timeval tv;

	if(gettimeofday(&tv, NULL) < 0) {
		PAL_DEBUG("gettimeofday error\n");
		return;
	}

	jiffies = tv.tv_sec * HZ + (uint64_t)tv.tv_usec * HZ / 1000000;
	g_miniutes = jiffies / (60 * HZ);
}

