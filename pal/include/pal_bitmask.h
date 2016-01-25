#ifndef _BITMASK_H_
#define _BITMASK_H_
#include "stdint.h"
#include "pal_conf.h"

#define PAL_BITS_TO_LONGS(bits) (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define PAL_BIT_TO_LONG(bit)	

#define pal_small_const_nbits(nbits) \
		(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)

static inline void pal_bitmap_or(unsigned long *dst, const unsigned long *bitmap1,
				const unsigned long *bitmap2, int bits)
{
	int k;
	int nr = PAL_BITS_TO_LONGS(bits);

	for (k = 0; k < nr; k++)
		dst[k] = bitmap1[k] | bitmap2[k];
}


static inline int pal_bitmap_and(unsigned long *dst, const unsigned long *bitmap1,
				const unsigned long *bitmap2, int bits)
{
	int k;
	int nr = PAL_BITS_TO_LONGS(bits);
	unsigned long result = 0;

	for (k = 0; k < nr; k++)
		result |= (dst[k] = bitmap1[k] & bitmap2[k]);
	return result != 0;
}

static inline int pal_bitmap_get(const unsigned long *addr, int nr)
{
	uint8_t v;

	asm("btl %2,%1; setc %0" : "=qm" (v) : "m" (*addr), "Ir" (nr));
	return v;
}

static inline void pal_bitmap_set(unsigned long *addr, int nr)
{
	asm("btsl %1,%0" : "+m" (*addr) : "Ir" (nr));
}

static inline void pal_bitmap_clear(unsigned long *addr, int nr)
{
	asm volatile("btrl %1,%0" : "+m" (*addr) : "Ir" (nr));
}

#endif
