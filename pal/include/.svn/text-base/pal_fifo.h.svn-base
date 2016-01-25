#ifndef _PAL_FIFO_H_
#define _PAL_FIFO_H_

#include <rte_ring.h>

struct pal_fifo;

#define PAL_FIFO_NAME_MAX	32

/*
 * @brief Create a fifo with single producer and single customer
 * @param name Name of the fifo.
 * @param count Maximum number of elements this ring can hold. Must be power of 2
 * @param numa Numa node on which the ring is to be created
 * @return Pointer to the newly created fifo, or NULL on failure
 * @note Fifos cannot be destroyed
 */
static inline struct pal_fifo *pal_fifo_create_spsc(const char *name,
                                            unsigned count, unsigned numa)
{
	return (struct pal_fifo *)rte_ring_create(name, count, numa, 
	                                       RING_F_SP_ENQ | RING_F_SC_DEQ);
}

/*
 * @brief Enqueue an object into the specified single-producer-fifo
 * @param fifo Pointer to the fifo
 * @param obj The object to be enqueued
 * @return 0 on success, none 0 on failure(may be > 0 or < 0)
 * @note This function is not multi-producer safe
 */
static inline int pal_fifo_enqueue_sp(struct pal_fifo *fifo, void *obj)
{
	return __rte_ring_sp_do_enqueue((struct rte_ring *)fifo, &obj, 1,
	                                            RTE_RING_QUEUE_FIXED);
}

/*
 * @brief Dequeue an object from a single-customer-fifo
 * @param fifo Pointer to the fifo
 * @return Pointer to The object dequeued, or NULL on failure
 * @note This function is not multi-customer safe
 */
static inline void *pal_fifo_dequeue_sc(struct pal_fifo *fifo)
{
	void *obj;

	if(__rte_ring_sc_do_dequeue((struct rte_ring *)fifo, &obj, 1,
	                                      RTE_RING_QUEUE_FIXED) < 0)
		return NULL;

	return obj;
}


#endif
