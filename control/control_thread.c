/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL$
* @brief		control thread init methods definition
* @author		jorenwu(wujiaoren@baidu.com)
* @date			$Date$
* @version		$Revision$ by $Author$
***********************************************************************
*/
#include "control_thread.h"

/**
 * @brief control thread
 */
int control_process_thread(__unused void *data)
{
    bvr_controlplane_process();

    return 0;
}
