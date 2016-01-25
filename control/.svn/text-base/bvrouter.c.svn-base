/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL$
* @brief		bvrouter main entry
* @author		jorenwu(wujiaoren@baidu.com)
* @date			$Date$
* @version		$Revision$ by $Author$
***********************************************************************
*/
#include <fcntl.h>

#include "common_includes.h"

#include "pal_cpu.h"
#include "pal_conf.h"
#include "pal_thread.h"
#include "pal_skb.h"
#include "pal_pktdef.h"
#include "pal_ipgroup.h"
#include "pal_netif.h"
#include "receiver.h"
#include "bvrouter.h"
#include "bvrouter_config.h"
#include "logger.h"
#include "control_thread.h"
#include "monitor_thread.h"
#include "slowpath_thread.h"
#include "bvr_arp.h"
#include "bvr_ver.h"
//#include "bvr_ctl.h"
#include "bvr_namespace.h"
#include "bvr_netfilter.h"

char *g_conf_file=NULL;
static int g_daemon_conf = 0;
extern int log_console;
extern int log_debug;
extern br_conf_t g_bvrouter_conf_info;

/**
*@brief		the help of bvrouter program
*@return void
*/
static void print_usage(void)
{
    fprintf(stderr,
        "\nbvrouter usage: bvrouter [-hv] [-f config_file] [-d directory]\n"
        "\tOptions:\n"
        "\t\t --version, -v \t\t\t\t Display the version id.\n"
        "\t\t --help, -h \t\t\t\t Display this short inlined help screen.\n"
        "\t\t --conf-file, -f path_to_conf_file \t Use the specified configuration file.\n"
        "\t\t --daemon, -m \t\t\t\t start bvrouter as daemon process.\n"
        "\t\t --log_to_console, -c \t\t\t print log to console.\n"
        "\t\t --log-debug, -d \t\t\t print debug log.\n"
        );
}


static int parse_cmdline(int argc, char **argv)
{
	poptContext context;
	char *conf = NULL;
	int c;

	struct poptOption options_table[] = {
		{"version", 'v', POPT_ARG_NONE, NULL, 'v', NULL, NULL},
		{"help", 'h', POPT_ARG_NONE, NULL, 'h', NULL, NULL},
		{"conf-file", 'f', POPT_ARG_STRING, &conf, 'f', NULL, NULL},
        {"daemon", 'm', POPT_ARG_NONE, NULL, 'm', NULL, NULL},
        {"log-to-console", 'c', POPT_ARG_NONE, NULL, 'c', NULL, NULL},
        {"log-debug", 'd', POPT_ARG_NONE, NULL, 'd', NULL, NULL},
		{NULL, 0, 0, NULL, 0, NULL, NULL}
	};

	context = poptGetContext(PROG, argc, (const char **) argv,
							options_table, 0);
	while((c = poptGetNextOpt(context)) >= 0)
	{
		switch (c)
		{
			case 'v':
                fprintf(stderr, "tag:           %s\n", BVR_TAG);
                fprintf(stderr, "svn version:   %s\n", BVR_SVN_VERSION);
                fprintf(stderr, "build_time:    %s\n", BVR_BUILD_TIME);
				exit(0);
				break;
			case 'h':
				print_usage();
				exit(0);
				break;
			case 'f':
				g_conf_file = conf;
				break;
            case 'm':
                g_daemon_conf = 1;
                break;
            case 'c':
                log_console = 1;
                break;
            case 'd':
                log_debug = 1;
                break;
			default:
				return -1;
		}
	}

	/* free the allocated context */
	poptFreeContext(context);
	return 0;
}

/**
 * @brief signal handler
 */
#if 0
static void bvrouter_sig_handler(__unused int para)
{
	bound_interface_t *bi;
	list_for_each_entry(bi, &g_bvrouter_conf_info.bound_interfaces, l)
	{
		rte_eth_dev_stop(bi->port_id);
	}

	exit(0);
}
#endif
/**
 * @brief signal handler init
 * @return -1=failed, 0=success
 */
static int bvrouter_signal_init(void)
{
#if 0
	if(signal(SIGINT,bvrouter_sig_handler) == SIG_ERR)
    {
        perror("signal SIGUSR1");
        return -1;
    }
    if(signal(SIGTERM,bvrouter_sig_handler) == SIG_ERR)
    {
        perror("signal SIGUSR1");
        return -1;
    }
#endif
    signal(SIGPIPE, SIG_IGN);	/* ignore SIGPIPE */
    signal(SIGSYS, SIG_IGN);	/* ignore SIGSYS */
	return 0;
}


static void bvrouter_daemonize(void)
{
    pid_t pid;

    if ((pid = fork()) < 0) {
        log_print("Fork daemon process failed: %s\n.", strerror(errno));
        exit(0);
    } else if (pid != 0) {
        /* parent process exit */
        exit(0);
    }

    if (setsid() < 0) {
        log_print("Setsid() failed: %s.\n", strerror(errno));
        exit(0);
    }

    if (0 != fork())
        exit(0);
}


static int bvrouter_running_check(void)
{
    int ret;
    pid_t pid;
    const char *pid_filename = "/var/run/bvrouter.pid";
    FILE *pid_file = fopen(pid_filename, "r+");
    if (pid_file == NULL) {
        goto write_pid;
    }

    ret = fscanf(pid_file, "%d", &pid);
    if (ret == EOF && ferror(pid_file) != 0) {
        log_print("read pid file error.\n");
        fclose(pid_file);
        return -1;
    }
    /*send a invalid signal to test whether the process exist*/
    if(!kill(pid, 0)) {
        log_print("bvrouter already exist.\n");
        fclose(pid_file);
        return -1;
    }
    fclose(pid_file);

write_pid:
    /* create new pid file */
    pid_file = fopen(pid_filename, "w+");
    if (pid_file == NULL) {
        log_print("\nCreate new pid file failed.\n");
        return -1;
    }

    fprintf(pid_file, "%d", getpid());
    fclose(pid_file);
    return 0;
}

/* set global palconf */
static int pal_conf_set(struct pal_config *palconf)
{
	bound_interface_t *bi;
	int idx = 0;
	int tid = 0;
	int pid = 0;
	int ppid = 0;

	/* pal config memory init */
	pal_conf_init(palconf);

	//this value is confirmed by HIC team
	palconf->mem_channel = 3;

	//set all workers with receiver thread type
	list_for_each_entry(bi, &g_bvrouter_conf_info.bound_interfaces, l)
	{
		for(idx=0; idx<bi->worker_cpus_cnt; idx++)
		{
			palconf->thread[tid].mode = PAL_THREAD_RECEIVER;
			palconf->thread[tid].cpu = bi->worker_cpus[idx];
			sprintf(palconf->thread[tid].name, "pal_recv_%d_%d",
					palconf->thread[tid].cpu, tid);

			tid++;
		}

		//set slowpath thread type
		for(idx=0; idx<bi->slowpath_cpus_cnt; idx++)
		{
			palconf->thread[tid].mode = PAL_THREAD_CUSTOM;
			palconf->thread[tid].func = slowpath_process_thread;
			palconf->thread[tid].arg = NULL;
			palconf->thread[tid].cpu = bi->slowpath_cpus[idx];
			sprintf(palconf->thread[tid].name, "pal_slowpath_%d", tid);
			tid++;
		}

		//set port configuration
		palconf->port[pid].ip = bi->ip;
		palconf->port[pid].gw_ip = bi->gw_ip;
		palconf->port[pid].netmask = bi->netmask;
		memcpy(palconf->port[pid].mac, bi->mac, 6);
		ppid = pid;
		pid++;
		for(idx=0; idx < bi->slave_ports_cnt; idx++)
		{
			palconf->port[ppid].slaves[idx] = bi->slave_ports[idx];
			palconf->port[ppid].slaves_cnt++;
			//add slave ports into pal_config with nothing
			pid++;
		}

		//l2_init(bi->ip, bi->mac, bi->gw_ip);
	}

	//set control thread type
	for(idx=0; idx < g_bvrouter_conf_info.control_cpus_cnt; idx++)
	{
		palconf->thread[tid].mode = PAL_THREAD_CUSTOM;
		palconf->thread[tid].func = control_process_thread;
		palconf->thread[tid].arg = NULL;
		//FIX: I think that 1 control thread is enough
		palconf->thread[tid].cpu = g_bvrouter_conf_info.control_cpus[idx];
		sprintf(palconf->thread[tid].name, "pal_ctl_%d", tid);
		tid++;
	}

	//set monitor thread type
	for(idx=0; idx < g_bvrouter_conf_info.monitor_cpus_cnt; idx++)
	{
		palconf->thread[tid].mode = PAL_THREAD_CUSTOM;
		palconf->thread[tid].func = monitor_process_thread;
		palconf->thread[tid].arg = NULL;
		palconf->thread[tid].cpu = g_bvrouter_conf_info.monitor_cpus[idx];
		sprintf(palconf->thread[tid].name, "pal_mon_%d", tid);
		tid++;
	}


	//set arp thread type
	for(idx=0; idx < g_bvrouter_conf_info.arp_cpus_cnt; idx++)
	{
		palconf->thread[tid].mode = PAL_THREAD_ARP;
		palconf->thread[tid].cpu = g_bvrouter_conf_info.arp_cpus[idx];
		sprintf(palconf->thread[tid].name, "pal_arp_%d", tid);
		tid++;
	}

	//set arp thread type
	for(idx=0; idx < g_bvrouter_conf_info.vnic_cpus_cnt; idx++)
	{
		palconf->thread[tid].mode = PAL_THREAD_VNIC;
		palconf->thread[tid].cpu = g_bvrouter_conf_info.vnic_cpus[idx];
		sprintf(palconf->thread[tid].name, "pal_vnic_%d", tid);
		tid++;
	}


	return 0;
}


int MAIN(int argc, char **argv)
{
	struct pal_config palconf;
	int ret;
	//must use program parameters
	if(argc<2)
	{
		print_usage();
		return -1;
	}

	//parse basic cmdline
	ret = parse_cmdline(argc, argv);
	if(ret < 0)
	{
		print_usage();
		return -1;
	}
    /*daemonrize bvrouter*/
    if (g_daemon_conf) {
        bvrouter_daemonize();
    }
    if (bvrouter_running_check() < 0) {
        return -1;
    }

	ret = bvrouter_signal_init();
	if(ret<0)
		return -1;

	//init bi list
	INIT_LIST_HEAD(&g_bvrouter_conf_info.bound_interfaces);

	//load config file parameters
	ret = load_bvrouter_config();
	if(ret < 0)
	{
		log_print("main: load config file failed.");
		return -1;
	}

	dump_bvrouter_config();

	/* set global environment confiure */
	if (pal_conf_set(&palconf) < 0)
		log_print("bgw init PAL config failed\n");

	/* pal init */
	pal_init(&palconf);

	//init log module
	log_init();

	pal_ipg_dump();

    int numa_id = 0;
    bound_interface_t *bi = NULL;

    list_for_each_entry(bi, &g_bvrouter_conf_info.bound_interfaces, l)
	{
        /*only one bond interface and pal use global variable to store vtep,
          so I do not know why use a bond port list*/
        memcpy(bi->mac, palconf.port[0].mac, 6);
        bi->port_id = palconf.port[0].port_id;
        BVR_DEBUG("bond port id %d\n", bi->port_id);
        BVR_DEBUG("vtep ip "NIPQUAD_FMT" local ip "NIPQUAD_FMT" local mac "MACPRINT_FMT" gw ip "NIPQUAD_FMT"\n",
            NIPQUAD(bi->vtep_ip), NIPQUAD(bi->ip), MACPRINT(bi->mac), NIPQUAD(bi->gw_ip));
        l2_init(bi->vtep_ip, bi->ip, bi->mac, bi->gw_ip);
        numa_id = bi->socket_id;
    }

    if (bvr_arp_init(numa_id) || nf_init(numa_id) || namespace_init(numa_id))
    {
		BVR_ERROR("main: init subsys failed\n");
		return -1;
    }

    l2_slab_init(numa_id);
	/* threads start*/
	pal_start();

	return 0;
}
