/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL$
* @brief		bonding interface init methods entry
* @author		jorenwu(wujiaoren@baidu.com)
* @date			$Date$
* @version		$Revision$ by $Author$
***********************************************************************
*/

#ifndef _BONDING_INIT_H
#define _BONDING_INIT_H

extern int create_bonded_device(char *name, uint8_t mode, uint8_t socket_id);
extern int add_slaves_to_bonded_device(int port_id, uint8_t *slaves,
		uint8_t slaves_nb);
extern int remove_slaves_from_bonded_device(int port_id, uint8_t *slaves,
		uint8_t slaves_nb);

#endif
