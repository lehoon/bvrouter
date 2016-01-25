/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL$
* @brief		monitor thread init methods definition
* @author		jorenwu(wujiaoren@baidu.com)
* @date			$Date$
* @version		$Revision$ by $Author$
***********************************************************************
*/
#include "common_includes.h"
#include "monitor_thread.h"
#include "pal_cycle.h"
#include "bvrouter_config.h"
#include "logger.h"
extern br_conf_t g_bvrouter_conf_info;
static void do_1m_work(void)
{
	return;
}

static void do_1s_work(void)
{
	return;
}

static void do_100ms_work(void)
{
	return;
}

static void do_10ms_work(void)
{
	return;
}

static void do_1ms_work(void)
{
	return;
}

/**
 * @brief monitor thread
 */
int monitor_process_thread(__unused void *data)
{
	uint64_t cur_cycle = 0;

	uint64_t ms_1_cnt = pal_get_tsc_hz() / 1000;
	uint64_t ms_10_cnt = pal_get_tsc_hz() / 100;
	uint64_t ms_100_cnt = pal_get_tsc_hz() / 10;
	uint64_t second_cnt = pal_get_tsc_hz();
	uint64_t minute_cnt = second_cnt*60;

	uint64_t last_1ms_cnt = 0;
	uint64_t last_10ms_cnt = 0;
	uint64_t last_100ms_cnt = 0;
	uint64_t last_second_cnt = 0;

    uint64_t last_poll_cnt = 0;

	uint64_t last_minute_cnt = 0;

	while(1)
	{
//		update_jiffies();
		cur_cycle = pal_get_tsc_cycles();

		if(cur_cycle - last_1ms_cnt > ms_1_cnt)
		{
			do_1ms_work();
			last_1ms_cnt = cur_cycle;
		}

		if(cur_cycle - last_10ms_cnt > ms_10_cnt)
		{
			do_10ms_work();
			last_10ms_cnt = cur_cycle;
		}

		if(cur_cycle - last_100ms_cnt > ms_100_cnt)
		{
			do_100ms_work();
			last_100ms_cnt = cur_cycle;
		}

		if(cur_cycle - last_second_cnt > second_cnt)
		{
			do_1s_work();
			last_second_cnt = cur_cycle;
		}

        if(cur_cycle - last_poll_cnt > g_bvrouter_conf_info.port_stat_itl * second_cnt)
        {
            /*set port polling 0 every interval
               (no need to set port polling every interval
               ,set it when call get interface)*/

            last_poll_cnt = cur_cycle;

        }

		if(cur_cycle - last_minute_cnt > minute_cnt)
		{
			do_1m_work();
			last_minute_cnt = cur_cycle;
		}

		usleep(1000);
	}
}
