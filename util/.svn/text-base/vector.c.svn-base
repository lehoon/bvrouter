/**
**********************************************************************
*
* Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL: https://svn.baidu.com/sys/ip/trunk/uinp/util/vector.c $
* @brief			vector接口定义
* @author		jorenwu(wujiaoren@baidu.com)
* @date			2012/04/21
* @version		$Id: uinp_vector.c 8341 2013-01-24 03:40:28Z wujiaoren $
***********************************************************************
*/

#include "common_includes.h"

#include "util.h"
#include "vector.h"
#include "logger.h"

/*
 * Initialize vector struct.
 * allocalted 'size' slot elements then return vector.
 */
vector
vector_alloc(void)
{
	vector v = (vector) MALLOC(sizeof (struct _vector));

	return v;
}

/* allocated one slot */
int
vector_alloc_slot(vector v)
{
	if (!v)
		return -1;

	v->allocated += VECTOR_DEFAULT_SIZE;
	if (v->slot)
		v->slot = REALLOC(v->slot, sizeof (void *) * v->allocated);
	else
		v->slot = (void *) MALLOC(sizeof (void *) * v->allocated);

	if (v->slot == NULL)
		return -1;

	return 0;
}

/* Insert a value into a specific slot */
void
vector_insert_slot(vector v, unsigned int slot, void *value)
{
	/* fix it */
#if 1
	unsigned int i;

	vector_alloc_slot(v);
	for (i = (v->allocated / VECTOR_DEFAULT_SIZE) - 2; i >= slot; i--)
		v->slot[i + 1] = v->slot[i];
	v->slot[slot] = value;
#endif
}

/* Del a slot */
void
vector_del_slot(vector v, unsigned int slot)
{
	/* fix it */
#if 1
	unsigned int i;

	if (!v->allocated || slot > ((v->allocated/VECTOR_DEFAULT_SIZE) - 1))
		return;

	for (i = slot + 1; i < (v->allocated / VECTOR_DEFAULT_SIZE); i++)
		v->slot[i - 1] = v->slot[i];

	v->allocated -= VECTOR_DEFAULT_SIZE;

	if (!v->allocated)
		v->slot = NULL;
	else
		v->slot = (void *) MALLOC(sizeof (void *) * v->allocated);

	v = REALLOC(v->slot, sizeof (void *) * v->allocated);
#endif
}

/* Free memory vector allocation */
void
vector_free(vector v)
{
	if (!v)
		return;
	FREE(v->slot);
	FREE(v);
}

void
free_strvec(vector strvec)
{
	unsigned int i;
	char *str;

	if (!strvec)
		return;

	for (i = 0; i < VECTOR_SIZE(strvec); i++)
		if ((str = VECTOR_SLOT(strvec, i)) != NULL)
			FREE(str);

	vector_free(strvec);
}

/* Set a vector slot value */
void
vector_set_slot(vector v, void *value)
{
	unsigned int i;

	if (!v)
		return;
	i = v->allocated - 1;

	v->slot[i] = value;
}

/* dump vector slots */
void
vector_dump(vector v)
{
	unsigned int i;

	if (!v)
		return;

	log_print("vector size : %d\n", v->allocated);

	for (i = 0; i < v->allocated; i++)
		if (v->slot[i] != NULL)
			log_print("  Slot [%d]: %p\n", i, VECTOR_SLOT(v, i));
}

void
dump_strvec(vector strvec)
{
	unsigned int i;
	char *str;

	if (!strvec)
		return;

	log_print("string vector : ");

	for (i = 0; i < VECTOR_SIZE(strvec); i++) {
		str = VECTOR_SLOT(strvec, i);
		log_print("[%i]=%s ", i, str);
	}

	log_print("\n");
}

