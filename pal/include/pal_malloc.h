#ifndef _PAL_MALLOC_H_
#define _PAL_MALLOC_H_
#include <string.h>
#include <rte_malloc.h>

#define PAL_ALIGN_SIZE		(sizeof(void *))

/*
 * @brief Allocate memory from a specified numa node
 * @param size Size of memory to be allocated
 * @param numa_id Id of numa on which the memory should be allocated
 * @return Pointer to the newly allocated memory, or NULL on failure
 * @note This function should NEVER be used in a dataplane thread because it
 *       need to grab a global lock and do linear search
 */
static inline void *pal_malloc_numa(size_t size, int numa_id)
{
	return rte_malloc_socket(NULL, size, PAL_ALIGN_SIZE, numa_id);
}

/*
 * @brief Allocate memory from the numa of the current thread
 * @param size Size of memory to be allocated
 * @return Pointer to the newly allocated memory, or NULL on failure
 * @note This function should NEVER be used in a dataplane thread because it
 *       need to grab a global lock and do linear search
 */
static inline void *pal_malloc(size_t size)
{
	return rte_malloc(NULL, size, PAL_ALIGN_SIZE);
}

/*
 * @brief Replacement function for realloc(), using huge-page memory. Reserved area
 *        memory is resized, preserving contents. In NUMA systems, the new area
 *        resides on the same NUMA socket as the old area.
 * @param ptr Pointer to old memory
 * @param size Size of memory to allocate. If this is 0, memory is freed.
 * @return Pointer to the newly allocated memory, or NULL on failure
 * @note This function should NEVER be used in a dataplane thread because it
 *       need to grab a global lock and do linear search
 */
static inline void *pal_realloc(void *ptr, size_t size)
{
	return rte_realloc(ptr, size, PAL_ALIGN_SIZE);
}

static inline void *pal_zalloc_numa(size_t size, int numa_id)
{
	void *ptr = pal_malloc_numa(size, numa_id);

	if (ptr != NULL)
		memset(ptr, 0, size);
	return ptr;
}

/*
 * @brief Free a piece of memory allocated  by pal_malloc[_numa] function
 * @parma mem Pointer to the memory to be freed
 */
static inline void pal_free(void *mem)
{
	rte_free(mem);
}


#endif
