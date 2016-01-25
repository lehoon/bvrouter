 /**
**********************************************************************
*
* Copyright (c) 2013 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL: https://svn.baidu.com/sys/ip/trunk/uinpv2/includes/uinp_log.h $
* @brief		log function entries
* @author		jorenwu(wujiaoren@baidu.com)
* @date			$Date: 2013-08-08 18:38:21 +0800 (Thu, 08 Aug 2013) $
* @version		$Revision: 10889 $ by $Author: wangyanfei01 $
***********************************************************************
*/

#ifndef _LOGGER_H
#define _LOGGER_H

#include <stdio.h>


void log_init(void);

void log_print(const char*,...);

extern int log_console;
extern int log_debug;

#define BVR_DEBUG(format, msg...)\
    if (log_debug) {\
        if (log_console) { \
            fprintf(stderr, "BVR_DEBUG: %s: %d: ", __FILE__, __LINE__);\
            fprintf(stderr, format, ##msg);\
        } else { \
            syslog(LOG_LOCAL5 | LOG_WARNING, "BVR_DEBUG: %s: %d: "format"\n", __FILE__, __LINE__, ##msg);\
        }\
    }

#define BVR_WARNING(format, msg...)\
    if (log_console) { \
        fprintf(stderr, "BVR_WARNING: %s: %d: ", __FILE__, __LINE__);\
        fprintf(stderr, format, ##msg);\
    } else { \
        syslog(LOG_LOCAL5 | LOG_WARNING, "BVR_WARNING: %s: %d: "format"\n", __FILE__, __LINE__, ##msg);\
    }


#define BVR_ERROR(format, msg...)\
    if (log_console) { \
        fprintf(stderr, "BVR_ERROR: %s: %d: ", __FILE__, __LINE__);\
        fprintf(stderr, format, ##msg);\
    } else { \
        syslog(LOG_LOCAL5 | LOG_ERR, "BVR_WARNING: %s: %d: "format"\n", __FILE__, __LINE__, ##msg);\
    }


#define BVR_PANIC(format, msg...)\
    if (log_console) { \
        fprintf(stderr, "BVR_PANIC: %s: %d: ", __FILE__, __LINE__);\
        fprintf(stderr, format, ##msg);\
        abort();\
    } else { \
        syslog(LOG_LOCAL5 | LOG_ERR, "BVR_WARNING: %s: %d: "format"\n", __FILE__, __LINE__, ##msg);\
        abort();\
    }

#endif	/* _LOGGER_H */

