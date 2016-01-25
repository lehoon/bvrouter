/**
**********************************************************************
* 
* Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL: https://svn.baidu.com/sys/ip/trunk/uinpv2/includes/uinp_vector.h $
* @brief			vector½Ó¿ÚÉùÃ÷
* @author		$Author: jorenwu$ (wujiaoren@baidu.com)
* @date			2012/04/19
* @version		$Id: uinp_vector.h 8624 2013-02-25 05:44:05Z wujiaoren $
***********************************************************************
*/

#ifndef _VECTOR_H
#define _VECTOR_H

/* vector definition */
struct _vector {
	unsigned int allocated;
	void **slot;
};
typedef struct _vector *vector;

#define VECTOR_DEFAULT_SIZE 1
#define VECTOR_SLOT(V,E) ((V)->slot[(E)])
#define VECTOR_SIZE(V)   ((V)->allocated)

#define vector_foreach_slot(v,p,i) \
	for (i = 0; i < (v)->allocated && ((p) = (v)->slot[i]); i++)

/* Prototypes */
extern vector vector_alloc(void);
extern int vector_alloc_slot(vector v);
extern void vector_free(vector v);
extern void free_strvec(vector strvec);
extern void vector_set_slot(vector v, void *value);
extern void vector_del_slot(vector v, unsigned int slot);
extern void vector_insert_slot(vector v, unsigned int slot, void *value);
extern void vector_dump(vector v);
extern void dump_strvec(vector strvec);

#endif

