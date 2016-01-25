#ifndef _PAL_BYTEORDER_H_
#define _PAL_BYTEORDER_H_

#include "pal_conf.h"

#ifndef __be32
#define __be16  uint16_t
#define __be32  uint32_t
#endif	

#ifdef PAL_CONFIG_LITTLE_ENDIAN
#define pal_htonl(x)		pal_bswap32(x)
#define pal_htonl_constant(x)	pal_bswap_constant32(x)
#define pal_ntohl(x)		pal_bswap32(x)
#define pal_ntohl_constant(x)	pal_bswap_constant32(x)

#define pal_htons(x)		pal_bswap16(x)
#define pal_htons_constant(x)	pal_bswap_constant16(x)
#define pal_ntohs(x)		pal_bswap16(x)
#define pal_ntohs_constant(x)	pal_bswap_constant16(x)

#elif defined PAL_CONFIG_BIG_ENDIAN
#define pal_htonl(x)		(x)
#define pal_htonl_constant(x)	(x)
#define pal_ntohl(x)		(x)
#define pal_ntohl_constant(x)	(x)

#define pal_htons(x)		(x)
#define pal_htons_constant(x)	(x)
#define pal_ntohs(x)		(x)
#define pal_ntohs_constant(x)	(x)

#else
#error	"Please define PAL_CONFIG_BIG_ENDIAN or PAL_CONFIG_LITTLE_ENDIAN in" \
	"include pal_conf.h"
#endif
/*
 * An architecture-optimized byte swap for a 16-bit value.
 *
 * Do not use this function directly. The preferred function is pal_bswap16().
 */
static inline uint16_t pal_arch_bswap16(uint16_t _x)
{
	register uint16_t x = _x;
	asm volatile ("xchgb %b[x1],%h[x2]"
		      : [x1] "=Q" (x)
		      : [x2] "0" (x)
		      );
	return x;
}

/*
 * An architecture-optimized byte swap for a 32-bit value.
 *
 * Do not use this function directly. The preferred function is pal_bswap32().
 */
static inline uint32_t pal_arch_bswap32(uint32_t _x)
{
	register uint32_t x = _x;
	asm volatile ("bswap %[x]"
		      : [x] "+r" (x)
		      );
	return x;
}


/* 
 * Swap bytes in 16 bit value.	
 * Use macro instead of inline function so it can be used in switch-case label 
 */
#define pal_bswap_constant16(x) \
		((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))

#define pal_bswap16(x)						\
		({ uint16_t __v = x;				\
		if (__builtin_constant_p(__v))			\
			__v = pal_bswap_constant16(__v);	\
		else						\
			__v = pal_arch_bswap16 (__v);		\
		__v; })
	
	
/* Swap bytes in 32 bit value.	*/
#define pal_bswap_constant32(x) \
	     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
	      (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
	
#define pal_bswap32(x) \
		({uint32_t __v = x;				\
		if (__builtin_constant_p (__v))			\
			__v = pal_bswap_constant32 (__v);	\
		else						\
			__v = pal_arch_bswap32(__v);		\
		__v; })


#endif
