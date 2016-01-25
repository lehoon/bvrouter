#include <unistd.h>
#include "conf.h"
#include "utils.h"
#include "worker.h"
#include "ipgroup.h"
#include "receiver.h"
#include "timer.h"
#include "thread.h"

int worker_loop(__unused void *arg)
{
	struct pal_fifo *rcvfifo[PAL_MAX_THREAD];
	int i;
	int rcvfifo_cnt = 0;
	struct thread_conf *thconf = pal_cur_thread_conf();
	unsigned sleep = pal_cur_thread_conf()->sleep;
	struct sk_buff *skb;
	pal_ipg_handler_t func;

	for(i = 0; i < PAL_MAX_THREAD; i++) {
		if(pal_dispatch_fifo(i) != NULL) {
			rcvfifo[rcvfifo_cnt++] = pal_dispatch_fifo(i);
		}
	}

	pal_cpu_idle();
	while(1) {
		for(i = 0; i < rcvfifo_cnt; i++) {
			skb = (struct sk_buff *)pal_fifo_dequeue_sc(rcvfifo[i]);
			if(skb == NULL) {
				if(unlikely(sleep))
					usleep(sleep);
				continue;
			}

			pal_cpu_work();
			/*PAL_LOG("got one packet, worker %d\n", pal_thread_id());*/
			func = (pal_ipg_handler_t)skb->private_data;
			skb->private_data = NULL;
			func(skb);
			pal_cpu_idle();
		}

		if (thconf->cmd) {
			pal_cpu_work();
			pal_thread_handle_cmd(thconf->cmd, thconf->cmd_arg);
			thconf->cmd = 0;
			pal_cpu_idle();
		}

		run_timer(100);
	}

	return 0;
}

