/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL$
* @brief		bvrouter configure file parser methods entry
* @author		jorenwu(wujiaoren@baidu.com)
* @date			$Date$
* @version		$Revision$ by $Author$
***********************************************************************
*/

#ifndef _BVROUTER_CONFIG_H
#define _BVROUTER_CONFIG_H

#include "common_includes.h"
#include "bvrouter_list.h"
#include "bvr_ver.h"
#define PROG "bvrouter"
#define VERSION_STRING "1.0.0.0"
#define MAX_CPU_NUMBER 32
#define MAX_NAME_SIZE 32

typedef struct bound_interface
{
	list l;
	unsigned char name[MAX_NAME_SIZE];
	uint8_t port_id;
	uint8_t mode;
	uint8_t socket_id;
	uint8_t slave_ports_cnt;
	uint8_t worker_cpus_cnt;
	uint8_t slowpath_cpus_cnt;
	uint8_t mac[6];
	uint32_t ip;
	uint32_t gw_ip;
    uint32_t vtep_ip;
	uint32_t netmask;
	uint8_t slave_ports[4];
	uint8_t worker_cpus[MAX_CPU_NUMBER];
	uint8_t slowpath_cpus[MAX_CPU_NUMBER];
}bound_interface_t;

typedef struct bvrouter_conf
{
	list bound_interfaces;

	uint8_t control_cpus_cnt;
	uint8_t monitor_cpus_cnt;
	uint8_t arp_cpus_cnt;
	uint8_t vnic_cpus_cnt;
    uint8_t port_update;   //wether need to polling port or not
    uint8_t port_stat_itl;  //every interval to update the port status
	uint8_t control_cpus[MAX_CPU_NUMBER];
	uint8_t monitor_cpus[MAX_CPU_NUMBER];
	uint8_t arp_cpus[MAX_CPU_NUMBER];
	uint8_t vnic_cpus[MAX_CPU_NUMBER];
}br_conf_t;

extern int load_bvrouter_config(void);
extern void dump_bvrouter_config(void);

#endif
