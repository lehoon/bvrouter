/**
**********************************************************************
*
* Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL: https://svn.baidu.com/sys/ip/trunk/uinpv2/includes/util.h $
* @brief			list�ӿڶ���
* @author		jorenwu(wujiaoren@baidu.com)
* @date			2012/04/21
* @version		$Id: util.h 8911 2013-03-13 06:43:33Z zhangyu09 $
***********************************************************************
*/

#ifndef _UTIL_H
#define _UTIL_H

#include "common_includes.h"

extern void *xalloc(unsigned long size);
extern void *zalloc(unsigned long size);
extern void xfree(void *p);

#define MALLOC(n)    (zalloc(n))
#define FREE(p)      (xfree((void *)(p)))
#define REALLOC(p,n) (realloc((p),(n)))

extern int bvrouter_atoi(char *str);
extern uint8_t ifmask_to_depth(uint32_t if_net);
extern inline char *trans_ip(uint32_t ip);
extern int mac_str_to_bin(char *str, uint8_t *mac);

#endif
