 /**
**********************************************************************
*
* Copyright (c) 2013 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL$
* @brief		log function definition
* @author		jorenwu(wujiaoren@baidu.com)
* @date			$Date: 2013-02-21 16:45:46 +0800 (Thu, 21 Feb 2013) $
* @version		$Revision: 8608 $ by $Author: wujiaoren $
***********************************************************************
*/


#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include "logger.h"
#include <string.h>
int log_debug = 0;
int log_console = 0;

void log_init(void)
{
    openlog("bvrouter",LOG_CONS|LOG_NDELAY|LOG_PID, LOG_LOCAL5);
}


/**
*@brief print a program message and return
*/
void log_print(const char* fmt,...)
{
	va_list ap;
	char buf[256];
	va_start(ap, fmt);
	vsnprintf(buf, 256, fmt, ap);
	va_end(ap);
	strcat(buf, "\n");
    syslog(LOG_INFO, "%s", buf);
	return;
}

