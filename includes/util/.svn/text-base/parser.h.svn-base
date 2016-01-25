/**
**********************************************************************
*
* Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL: https://svn.baidu.com/sys/ip/trunk/uinp/util/parser.h $
* @brief			list接口定义
* @author		jorenwu(wujiaoren@baidu.com)
* @date			2012/04/21
* @version		$Id: parser.h 8322 2013-01-22 09:16:30Z wujiaoren $
***********************************************************************
*/

#ifndef _PARSER_H
#define _PARSER_H

#include "common_includes.h"

/* local includes */
#include "vector.h"

/* Global definitions */
#define SOB  "{"
#define EOB  "}"
#define MAXBUF	1024

/* Prototypes */
extern int install_keyword_root(const char *string, int (*handler) (vector));
extern void install_sublevel(void);
extern void install_sublevel_end(void);
extern int install_keyword(const char *string, int (*handler) (vector));
extern void dump_keywords(vector keydump, unsigned int level);
extern void free_keywords(vector keywords_vec);
extern int alloc_strvec(char *string, vector *ret_vec);
extern int read_line_no_include(char *buf, int size);
extern int init_data(char *conf_file, int (*init_keywords) (void));

#endif

