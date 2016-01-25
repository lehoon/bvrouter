#ifndef _PAL_SPINLOCK_H_
#define _PAL_SPINLOCK_H_
#include <rte_spinlock.h>
#include <rte_rwlock.h>

typedef rte_spinlock_t	pal_spinlock_t;

/**
 * A static spinlock initializer.
 */
#define PAL_SPINLOCK_INITIALIZER { 0 }

/**
 * Initialize the spinlock to an unlocked state.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static inline void
pal_spinlock_init(pal_spinlock_t *sl)
{
	rte_spinlock_init((rte_spinlock_t *)sl);
}

/**
 * Take the spinlock.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static inline void
pal_spinlock_lock(pal_spinlock_t *sl)
{
	rte_spinlock_lock((rte_spinlock_t *)sl);
}

/**
 * Release the spinlock.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static inline void
pal_spinlock_unlock(pal_spinlock_t *sl)
{
	rte_spinlock_unlock((rte_spinlock_t *)sl);
}

/**
 * Try to take the lock.
 *
 * @param sl
 *   A pointer to the spinlock.
 * @return
 *   1 if the lock is successfully taken; 0 otherwise.
 */
static inline int
pal_spinlock_trylock(pal_spinlock_t *sl)
{
	return rte_spinlock_trylock((rte_spinlock_t *)sl);
}

/**
 * Test if the lock is taken.
 *
 * @param sl
 *   A pointer to the spinlock.
 * @return
 *   1 if the lock is currently taken; 0 otherwise.
 */
static inline int pal_spinlock_is_locked(pal_spinlock_t *sl)
{
	return rte_spinlock_is_locked((rte_spinlock_t *)sl);
}

/**
 * The rte_rwlock_t type.
 *
 * cnt is -1 when write lock is held, and > 0 when read locks are held.
 */
typedef rte_rwlock_t	pal_rwlock_t;

/**
 * A static rwlock initializer.
 */
#define PAL_RWLOCK_INITIALIZER { 0 }

/**
 * Initialize the rwlock to an unlocked state.
 *
 * @param rwl
 *   A pointer to the rwlock structure.
 */
static inline void
pal_rwlock_init(pal_rwlock_t *rwl)
{
	rte_rwlock_init((rte_rwlock_t *)rwl);
}

/**
 * Take a read lock. Loop until the lock is held.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static inline void
pal_rwlock_read_lock(pal_rwlock_t *rwl)
{
	rte_rwlock_read_lock((rte_rwlock_t *)rwl);
}

/**
 * Try to take the read lock.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 * @return
 *   1 if the lock is successfully taken; 0 otherwise.
 */
 static inline int
 pal_rwlock_read_trylock(pal_rwlock_t *rwl)
{
	int32_t x;
	int success = 0;

	while (success == 0) {
		x = rwl->cnt;
		/* write lock is held */
		if (x < 0) {
			return 0;
		}
		success = rte_atomic32_cmpset((volatile uint32_t *)&rwl->cnt,
									x, x + 1);
	}
	return 1;
}

/**
 * Release a read lock.
 *
 * @param rwl
 *   A pointer to the rwlock structure.
 */
static inline void
pal_rwlock_read_unlock(pal_rwlock_t *rwl)
{
	rte_rwlock_read_unlock((rte_rwlock_t *)rwl);
}

/**
 * Take a write lock. Loop until the lock is held.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static inline void
pal_rwlock_write_lock(pal_rwlock_t *rwl)
{
	rte_rwlock_write_lock((rte_rwlock_t *)rwl);
}

/**
 * Release a write lock.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static inline void
pal_rwlock_write_unlock(pal_rwlock_t *rwl)
{
	rte_rwlock_write_unlock((rte_rwlock_t *)rwl);
}

/**
 * Try to take the read lock.
 *
 * @param sl
 *   A pointer to the rwlock.
 * @return
 *   1 if the lock is successfully taken; 0 otherwise.
 */
#if 0
static inline void
pal_rwlock_read_trylock(__unused pal_rwlock_t *rwl)
{
	/* @TODO add read trylock code */
}
#endif
#endif /* _PAL_SPINLOCK_H_ */

