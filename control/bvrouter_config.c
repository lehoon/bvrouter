/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL$
* @brief		bvrouter configure file parser methods definition
* @author		jorenwu(wujiaoren@baidu.com)
* @date			$Date$
* @version		$Revision$ by $Author$
***********************************************************************
*/

#include "common_includes.h"

#include "bvrouter_config.h"
#include "parser.h"
#include "logger.h"
#include "util.h"

extern char *g_conf_file;

br_conf_t g_bvrouter_conf_info;

/**
* @brief is the strvec size equal to cnt+1
* @param[in] strvec the string vector
* @param[in] the expected size of strvec
* @return 0=equal, -1=not equal
*/
static int check_param_cnt(vector strvec, uint32_t cnt)
{
	char *key = NULL;
	/* cnt锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟� */
	if (VECTOR_SIZE(strvec) != (cnt+1)) {
		key = VECTOR_SLOT(strvec, 0);
		if (key) {
			log_print("\"%s\" params count is %u, but need %u\n",
				key, (VECTOR_SIZE(strvec) - 1), cnt);
		} else {
			log_print("params count is %u, but need %u\n",
				(VECTOR_SIZE(strvec) - 1), cnt);
		}
		return -1;
	}
	return 0;
}

/**
* @brief is the strvec size equal to 2, but do nothing with strvect
* @param[in] strvec the string vector
* @return 0=equal, -1=not equal
*/
static int dft_handler(vector strvec)
{
    /*锟斤拷锟斤拷锟斤拷锟斤拷为1锟斤拷['{']*/
    if(check_param_cnt(strvec,1) < 0)
    {
        goto err;
    }

    return 0;

err:
    return -1;
}

static bound_interface_t *alloc_bi_info(char *name)
{
	bound_interface_t *bi;

	if(NULL == name)
		return NULL;

	bi = (bound_interface_t *)malloc(sizeof(bound_interface_t));
	if(!bi)
	{
		log_print("alloc_bi_info error:cannot alloc bounding interface.");
		return NULL;
	}

	memset(bi, 0, sizeof(bound_interface_t));

	memcpy(bi->name, name, 22);
	bi->name[21]='\0';

	return bi;
}

/**
* @brief the bounding interface parse handler
* @param[in] strvec the string vector
* @return 0=success, -1=failed
*/
static int bi_handler(vector strvec)
{
	if(!strvec)
	{
		log_print("bi_handler with NULL strvec.\n");
		return -1;
	}

	/* bounding interace MUST have a name*/
	if(check_param_cnt(strvec, 2) < 0)
	{
		return -1;
	}

	bound_interface_t *bi = alloc_bi_info(VECTOR_SLOT(strvec,1));
	if(!bi)
		return -1;

	list_add_tail(&bi->l, &g_bvrouter_conf_info.bound_interfaces);

	return 0;
}

/**
* @brief the bounding interface's mode parse handler
* @param[in] strvec the string vector
* @return 0=success, -1=failed
*/
static int mode_handler(vector strvec)
{
	if(!strvec)
	{
		log_print("mode_handler: with NULL strvec.\n");
		return -1;
	}

	/* bounding interace MUST have a mode*/
	if(check_param_cnt(strvec, 1) < 0)
	{
		return -1;
	}

	bound_interface_t *bi = list_tail_data(
		&(g_bvrouter_conf_info.bound_interfaces),
		bound_interface_t, l);
	if(!bi)
		return -1;

	bi->mode = bvrouter_atoi(VECTOR_SLOT(strvec,1));
	if(bi->mode > 4)
	{
		log_print("mode_handler: the mode of bounding interface is wrong");
		return -1;
	}

	return 0;
}

/**
* @brief the bounding interface's mac parse handler
* @param[in] strvec the string vector
* @return 0=success, -1=failed
*/
static int mac_handler(vector strvec)
{
	if(!strvec)
	{
		log_print("mac_handler: with NULL strvec.\n");
		return -1;
	}

	/* bounding interace MUST have a mac address*/
	if(check_param_cnt(strvec, 1) < 0)
	{
		return -1;
	}

	bound_interface_t *bi = list_tail_data(&(g_bvrouter_conf_info.bound_interfaces),
			bound_interface_t, l);
	if(!bi)
		return -1;

	mac_str_to_bin(VECTOR_SLOT(strvec,1), bi->mac);

	return 0;
}

/**
 * * @brief the bounding interface's ip parse handler
 * * @param[in] strvec the string vector
 * * @return 0=success, -1=failed
 * */
static int ip_handler(vector strvec)
{
	uint32_t ip;

        if(!strvec)
        {
                log_print("ip_handler: with NULL strvec.\n");
                return -1;
        }

        /* bounding interace MUST have a ip address*/
        if(check_param_cnt(strvec, 1) < 0)
        {
                return -1;
        }

	if(inet_pton(AF_INET, VECTOR_SLOT(strvec, 1), &ip) <= 0)
	{
		log_print("ip_handler: wrong ip format.");
		return -1;
	}

        bound_interface_t *bi = list_tail_data(&(g_bvrouter_conf_info.bound_interfaces),
                        bound_interface_t, l);
        if(!bi)
                return -1;

	bi->ip = ip;

        return 0;
}

/**
 *  @brief the bounding interface's gateway ip parse handler
 *  @param[in] strvec the string vector
 *  @return 0=success, -1=failed
 */
static int gwip_handler(vector strvec)
{
        uint32_t ip;

        if(!strvec)
        {
                log_print("gwip_handler: with NULL strvec.\n");
                return -1;
        }

        /* bounding interace MUST have a gateway address*/
        if(check_param_cnt(strvec, 1) < 0)
        {
                return -1;
        }

        if(inet_pton(AF_INET, VECTOR_SLOT(strvec, 1), &ip) <= 0)
        {
                log_print("ip_handler: wrong ip format.");
                return -1;
        }

        bound_interface_t *bi = list_tail_data(&(g_bvrouter_conf_info.bound_interfaces),
                        bound_interface_t, l);
        if(!bi)
                return -1;

        bi->gw_ip = ip;

	return 0;
}


/**
 *  @brief the bounding interface's vtep ip parser
 *  @param[in] strvec the string vector
 *  @return 0=success, -1=failed
 */
static int vtepip_handler(vector strvec)
{
    uint32_t ip;

    if(!strvec)
    {
        log_print("vtep ip_handler: with NULL strvec.\n");
        return -1;
    }

    /* bounding interace MUST have a gateway address*/
    if(check_param_cnt(strvec, 1) < 0)
    {
        return -1;
    }

    if(inet_pton(AF_INET, VECTOR_SLOT(strvec, 1), &ip) <= 0)
    {
        log_print("ip_handler: wrong ip format.");
        return -1;
    }

    bound_interface_t *bi = list_tail_data(&(g_bvrouter_conf_info.bound_interfaces),
        bound_interface_t, l);

    if(!bi) {
        return -1;
    }

    bi->vtep_ip = ip;

	return 0;
}




/**
 *  @brief the bounding interface's netmask parse handler
 *  @param[in] strvec the string vector
 *  @return 0=success, -1=failed
 */
static int netmask_handler(vector strvec)
{
        uint32_t netmask;

        if(!strvec)
        {
                log_print("netmask_handler: with NULL strvec.\n");
                return -1;
        }

        /* bounding interace MUST have a gateway address*/
        if(check_param_cnt(strvec, 1) < 0)
        {
                return -1;
        }

        if(inet_pton(AF_INET, VECTOR_SLOT(strvec, 1), &netmask) <= 0)
        {
                log_print("netmask_handler: wrong ip format.");
                return -1;
        }

        bound_interface_t *bi = list_tail_data(&(g_bvrouter_conf_info.bound_interfaces),
                        bound_interface_t, l);
        if(!bi)
                return -1;

        bi->netmask = netmask;

	return 0;
}

/**
 * @brief the bounding interface's ip parse handler
 * @param[in] strvec the string vector
 * @return 0=success, -1=failed
 */
static int slaves_handler(vector strvec)
{
        unsigned int idx;
        int pi;

        if(!strvec)
        {
                log_print("slaves_handler: with NULL strvec.\n");
                return -1;
        }

        bound_interface_t *bi = list_tail_data(&(g_bvrouter_conf_info.bound_interfaces),
                        bound_interface_t, l);
        if(!bi)
                return -1;

	for(idx=1; idx<VECTOR_SIZE(strvec); idx++)
	{
		pi = bvrouter_atoi(VECTOR_SLOT(strvec, idx));
		if(pi <0 || pi > 4)
		{
			log_print("slaves_handler: the port id is not in (0,4) range.");
			return -1;
		}
		bi->slave_ports[bi->slave_ports_cnt] = pi;
		bi->slave_ports_cnt++;
	}

	return 0;
}

/**
 * @brief the bounding interface locate on which socket parse handler
 * @param[in] strvec the string vector
 * @return 0=success, -1=failed
 */
static int si_handler(vector strvec)
{
        if(!strvec)
        {
                log_print("si_handler: with NULL strvec.\n");
                return -1;
        }

        if(check_param_cnt(strvec, 1) < 0)
        {
                return -1;
        }

        bound_interface_t *bi = list_tail_data(&(g_bvrouter_conf_info.bound_interfaces),
                        bound_interface_t, l);
        if(!bi)
                return -1;

        bi->socket_id = bvrouter_atoi(VECTOR_SLOT(strvec, 1));
	if(bi->socket_id > 4)
	{
		log_print("slaves_handler: wrong socket id value");
		return -1;
	}

	return 0;
}

/**
 * @brief the bounding interface which are worker cpu processing parse handler
 * @param[in] strvec the string vector
 * @return 0=success, -1=failed
 */
static int wc_handler(vector strvec)
{
	unsigned int idx;
    int cpu;

        if(!strvec)
        {
                log_print("wc_handler: with NULL strvec.\n");
                return -1;
        }

        bound_interface_t *bi = list_tail_data(&(g_bvrouter_conf_info.bound_interfaces),
                        bound_interface_t, l);
        if(!bi)
                return -1;

	for(idx=1; idx <VECTOR_SIZE(strvec); idx++)
	{
		cpu = bvrouter_atoi(VECTOR_SLOT(strvec, idx));
		if(cpu < 0 || cpu > MAX_CPU_NUMBER)
		{
			log_print("wc_handler: wrong cpu id.");
			return -1;
		}
		bi->worker_cpus[bi->worker_cpus_cnt] = cpu;
		bi->worker_cpus_cnt++;
	}

        return 0;
}

/**
 * @brief the bounding interface which are slowpath cpu processing parse handler
 * @param[in] strvec the string vector
 * @return 0=success, -1=failed
 */
static int sc_handler(vector strvec)
{
        unsigned  int idx;
        int cpu;

        if(!strvec)
        {
                log_print("sc_handler: with NULL strvec.\n");
                return -1;
        }

        bound_interface_t *bi = list_tail_data(&(g_bvrouter_conf_info.bound_interfaces),
                        bound_interface_t, l);
        if(!bi)
                return -1;

        for(idx=1; idx <VECTOR_SIZE(strvec); idx++)
        {
                cpu = bvrouter_atoi(VECTOR_SLOT(strvec, idx));
                if(cpu < 0 || cpu > MAX_CPU_NUMBER)
                {
                        log_print("sc_handler: wrong cpu id.");
                        return -1;
                }
                bi->slowpath_cpus[bi->slowpath_cpus_cnt] = cpu;
                bi->slowpath_cpus_cnt++;
        }

        return 0;
}

/**
 *  @brief the control cpu parse hadler
 *  @param[in] strvec the string vector
 *  @return 0=success, -1=failed
 */
static int cc_handler(vector strvec)
{
       unsigned  int idx;
       int cpu;

        if(!strvec)
        {
                log_print("cc_handler: with NULL strvec.\n");
                return -1;
        }


        for(idx=1; idx <VECTOR_SIZE(strvec); idx++)
        {
                cpu = bvrouter_atoi(VECTOR_SLOT(strvec, idx));
                if(cpu < 0 || cpu > MAX_CPU_NUMBER)
                {
                        log_print("cc_handler: wrong cpu id.");
                        return -1;
                }
		g_bvrouter_conf_info.control_cpus[g_bvrouter_conf_info.control_cpus_cnt]
			= cpu;
		g_bvrouter_conf_info.control_cpus_cnt++;
        }

        return 0;
}

/**
 *  @brief the monitor cpu parse hadler
 *  @param[in] strvec the string vector
 *  @return 0=success, -1=failed
 */
static int mc_handler(vector strvec)
{
        unsigned int idx;
        int cpu;

        if(!strvec)
        {
                log_print("mc_handler: with NULL strvec.\n");
                return -1;
        }


        for(idx=1; idx <VECTOR_SIZE(strvec); idx++)
        {
                cpu = bvrouter_atoi(VECTOR_SLOT(strvec, idx));
                if(cpu < 0 || cpu > MAX_CPU_NUMBER)
                {
                        log_print("mc_handler: wrong cpu id.");
                        return -1;
                }
                g_bvrouter_conf_info.monitor_cpus[g_bvrouter_conf_info.monitor_cpus_cnt]
                        = cpu;
                g_bvrouter_conf_info.monitor_cpus_cnt++;
        }

        return 0;
}

/**
 *  @brief the arp cpu parse hadler
 *  @param[in] strvec the string vector
 *  @return 0=success, -1=failed
 */
static int arp_handler(vector strvec)
{
        unsigned int idx;
        int cpu;

        if(!strvec)
        {
                log_print("arp_handler: with NULL strvec.\n");
                return -1;
        }

        for(idx=1; idx <VECTOR_SIZE(strvec); idx++)
        {
                cpu = bvrouter_atoi(VECTOR_SLOT(strvec, idx));
                if(cpu < 0 || cpu > MAX_CPU_NUMBER)
                {
                        log_print("arp_handler: wrong cpu id.");
                        return -1;
                }
                g_bvrouter_conf_info.arp_cpus[g_bvrouter_conf_info.arp_cpus_cnt]
                        = cpu;
                g_bvrouter_conf_info.arp_cpus_cnt++;
        }

        return 0;
}

/**
 *  @brief the vnic cpu parse hadler
 *  @param[in] strvec the string vector
 *  @return 0=success, -1=failed
 */
static int vnic_handler(vector strvec)
{
        unsigned int idx;
        int cpu;

        if(!strvec)
        {
                log_print("vnic_handler: with NULL strvec.\n");
                return -1;
        }

        for(idx=1; idx <VECTOR_SIZE(strvec); idx++)
        {
                cpu = bvrouter_atoi(VECTOR_SLOT(strvec, idx));
                if(cpu < 0 || cpu > MAX_CPU_NUMBER)
                {
                        log_print("vnic_handler: wrong cpu id.");
                        return -1;
                }
                g_bvrouter_conf_info.vnic_cpus[g_bvrouter_conf_info.vnic_cpus_cnt]
                        = cpu;
                g_bvrouter_conf_info.vnic_cpus_cnt++;
        }

        return 0;
}

/**
 * @brief key word register
 * @return 0 success
 */
static int init_cfg_keywords(void)
{
	install_keyword_root("bvrouter", &dft_handler);

	install_keyword("bonding_interface", &bi_handler);
	install_sublevel();
	install_keyword("mode", &mode_handler);
	install_keyword("mac", &mac_handler);
    install_keyword("vtep_ip", &vtepip_handler);
	install_keyword("ip", &ip_handler);
	install_keyword("gw_ip", &gwip_handler);

	install_keyword("netmask", &netmask_handler);
	install_keyword("slaves", &slaves_handler);
	install_keyword("socket_id", &si_handler);
	install_keyword("worker_cpu", &wc_handler);
	install_keyword("slowpath_cpu", &sc_handler);
	install_sublevel_end();

	install_keyword("control_cpu", &cc_handler);
	install_keyword("monitor_cpu", &mc_handler);
	install_keyword("arp_cpu", &arp_handler);
	install_keyword("vnic_cpu", &vnic_handler);

	return 0;
}

/**
 * @brief load the configure file as the bvrouter's parameters
 * @return -1=failed, other=ok
 */
int load_bvrouter_config(void)
{
	int ret = 0;

	if(NULL == g_conf_file)
	{
		log_print("bvrouter's config file haven't defined.");
		return -1;
	}

	ret=init_data(g_conf_file, init_cfg_keywords);
	if(ret<0)
	{
		log_print("bvrouter config file parsing failed.");
		return -1;
	}

    /*add by zhangyu init static param*/
    g_bvrouter_conf_info.port_update = 0;
    g_bvrouter_conf_info.port_stat_itl = 2;


	return ret;
}

/**
 * brief dump the configuration info
 * @return void
 */
void dump_bvrouter_config(void)
{
	unsigned int idx = 0;
	bound_interface_t *bi = NULL;

	for(idx=0; idx < g_bvrouter_conf_info.control_cpus_cnt; idx++)
	{
		log_print("the control cpu %u", g_bvrouter_conf_info.control_cpus[idx]);
	}

	for(idx=0; idx < g_bvrouter_conf_info.monitor_cpus_cnt; idx++)
	{
		log_print("the monitor cpu %u", g_bvrouter_conf_info.monitor_cpus[idx]);
	}

	for(idx=0; idx < g_bvrouter_conf_info.arp_cpus_cnt; idx++)
	{
		log_print("the arp cpu %u", g_bvrouter_conf_info.arp_cpus[idx]);
	}

	for(idx=0; idx < g_bvrouter_conf_info.vnic_cpus_cnt; idx++)
	{
		log_print("the vnic cpu %u", g_bvrouter_conf_info.vnic_cpus[idx]);
	}

	list_for_each_entry(bi, &g_bvrouter_conf_info.bound_interfaces, l)
	{
		log_print("the %s interface's ip %s", bi->name, trans_ip(bi->ip));
		log_print("the %s interface's gw_ip %s", bi->name, trans_ip(bi->gw_ip));
		log_print("the %s interface's netmask %s", bi->name, trans_ip(bi->netmask));
		for(idx=0; idx < bi->slave_ports_cnt; idx++)
		{
			log_print("the %s interface's slave port %u", bi->name, bi->slave_ports[idx]);
		}

		for(idx=0; idx<bi->worker_cpus_cnt; idx++)
		{
			log_print("the %s interface's worker cpu: %u",
					bi->name, bi->worker_cpus[idx]);
		}

		for(idx=0; idx<bi->slowpath_cpus_cnt; idx++)
		{
			log_print("the %s interface's slowpath cpu: %u",
								bi->name, bi->slowpath_cpus[idx]);
		}
	}
}
