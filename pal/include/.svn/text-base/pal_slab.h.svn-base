#ifndef _PAL_SLAB_H_
#define _PAL_SLAB_H_
#include <rte_mempool.h>

#include "pal_utils.h"

/* just a simple wrap */
struct pal_slab {
	struct rte_mempool pool;
};

/*
 * @brief Create a new slab which can be used to alloc specified size of elements
 * @param name Name of this slab, used mainly for debug. Must be unique
 * @param elem_cnt Number of elements this slab can alloc. Cannot be modified.
 * @param elem_size Size of one element
 * @param numa Numa id on which this slab is created
 * @param flags Only one flag currently:
 *        PAL_SLAB_SHARED If set, the slab will be created on a shared hugepage,
 *               or it is created on the cpu's private page. The purpose of this
 *               flag is to optimize hugepage TLP hit rate.
 * @return The newly created slab, or NULL on failure
 * @note  1. Slabs cannot be destroyed
 *        2. All memory is alloced at slab creation and cannot be freed.
 *           So estimate your memory requirements carefully
 *        3. This function is not thread safe
 */
static inline struct pal_slab *pal_slab_create(const char* name,                
             unsigned elem_cnt, unsigned elem_size, int numa, unsigned flags);

/*
 * @brief Alloc multiple objects from a slab
 * @param slab A pointer to the slab
 * @param obj_table A pointer to a void * pointer (object) that will be filled
 * @param n The number of objects to get from the mempool to obj_table
 * @return 0 on success, -1 on failure
 * @note This function has a 'none or all' behavior. If less than n objects
 *       are available, then none is alloced. If you need an "as more as possible"
 *       behavior, please contact the maintainer.
 */
static inline int pal_slab_alloc_bulk(struct pal_slab *slab, 
                                  void **obj_table, unsigned n);

/*
 * @brief Alloc an object from a slab
 * @param slab A pointer to the slab
 * @return Pointer to the newly alloced object, or NULL on failure
 */
static inline void *pal_slab_alloc(struct pal_slab *slab);

/*
 * @brief Free an object to its slab
 * @param obj The object you want to free
 */
static inline void pal_slab_free(void *obj);


/* TODO: use simple list and PAL_SLAB_SHARED to optimize this function */
/*
 * @brief Create a slab from which you can alloc memory chunks
 * @param name Name of this slab, musb be unique
 * @param elem_cnt Number of elements in this slab. This number is fixed after
 *        creation, the slab cannot expand and shrink dynamically.
 * @param elem_size Size of one element.
 * @param numa
 * @param flags Currently not used. You should set it to 0.
 */
static inline struct pal_slab *pal_slab_create(const char* name, 
               unsigned elem_cnt, unsigned elem_size, int numa,
               __unused unsigned flags)
{
	struct rte_mempool *mempool;

	mempool = rte_mempool_create(name, 
	                   elem_cnt, elem_size + sizeof(struct pal_slab *), 
	                   0, 0, NULL, NULL, NULL, NULL, 
	                   numa, MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);

	return (struct pal_slab *)mempool;
}

/* TODO: use simple list and PAL_SLAB_SHARED to optimize this function */
/*
 * @brief Create a slab from which you can alloc memory chunks
 * @param name Name of this slab, musb be unique
 * @param elem_cnt Number of elements in this slab. This number is fixed after
 *        creation, the slab cannot expand and shrink dynamically.
 * @param elem_size Size of one element.
 * @param numa
 * @param flags Currently not used. You should set it to 0.
 */
static inline struct pal_slab *pal_slab_create_multipc(const char* name, 
               unsigned elem_cnt, unsigned elem_size, int numa,
               __unused unsigned flags)
{
	struct rte_mempool *mempool;

	mempool = rte_mempool_create(name, 
	                   elem_cnt, elem_size + sizeof(struct pal_slab *), 
	                   0, 0, NULL, NULL, NULL, NULL, 
	                   numa, 0);

	return (struct pal_slab *)mempool;
}

/*
 * @brief Alloc a bulk of elements from a slab
 * @param slab Slab from which to alloc the elements
 * @param obj_table A pointer to an array of pointers to store the pointer to
 *                  the alloced elements.
 * @param n Number of elements to alloc
 * @return 0 on success, -1 on failure
 */
static inline int pal_slab_alloc_bulk(struct pal_slab *slab, 
                                  void **obj_table, unsigned n)
{
	unsigned i;

	if(rte_mempool_get_bulk(&slab->pool, obj_table, n) != 0)
		return -1;

	for(i = 0; i < n; i++) {
		/* store pointer to the slab before the memory */
		/* @TODO performance maybe decrease? because NOT align to cache line  */
		*((unsigned long *)(obj_table[i])) = (unsigned long)slab;
		obj_table[i] = (void *)((unsigned long *)obj_table[i] + 1);

	}

	return 0;
}

static inline void *pal_slab_alloc(struct pal_slab *slab)
{
	void *obj = NULL;

	if(pal_slab_alloc_bulk(slab, &obj, 1) != 0) {
		return NULL;
	}
	return obj;
}

static inline void pal_slab_free(void *obj)
{
	struct pal_slab *slab;

	/* retrieve the pointer to the slab from the head room of the object */
	obj = (unsigned long *)obj - 1;
	slab = (struct pal_slab *) *(unsigned long *)obj;
	rte_mempool_put_bulk(&slab->pool, &obj, 1);
}

#endif
