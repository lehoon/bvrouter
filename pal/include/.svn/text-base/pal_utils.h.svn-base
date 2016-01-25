#ifndef _PAL_UTILS_H_
#define _PAL_UTILS_H_

#include <rte_hash_crc.h>
#include <rte_memcpy.h>
#include <stdio.h>
#include <stddef.h>

#include "pal_byteorder.h"

//#define PAL_PRINT_DEBUG

#ifdef PAL_PRINT_DEBUG
#define PAL_DEBUG(msg...)\
    do{\
		printf("PAL:DBG:"msg);\
	}while(0)
#else
#define PAL_DEBUG(msg...)
#endif

#define PAL_DEBUG_LINE(msg...) PAL_DEBUG("___%s___%d__\n",__func__,__LINE__)

#define PAL_LOG(msg...)\
	do{\
		printf("LOG:"msg);\
	}while(0)

#define PAL_WARNING(msg...)\
	do{\
		fprintf(stderr, "WARNING:"msg);\
	}while(0)

#define PAL_ERROR(msg...)\
	do{\
		fprintf(stderr, "ERROR:%s: %d: ", __FILE__, __LINE__);\
		fprintf(stderr, msg);\
	}while(0)

#define PAL_PANIC(msg...)\
	do{\
		fprintf(stderr, "PANIC: %s: %d: ", __FILE__, __LINE__);\
		fprintf(stderr, msg);\
		abort(); \
	}while(0)

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#define ASSERT(x)							\
	if (!(x)) {							\
		PAL_PANIC("assertion failed %s:%d: %s\n",		\
		           __FILE__, __LINE__, #x);			\
	}

#define __unused __attribute__((__unused__))

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

/**
 * @brief cast a member of a structure out to the containing structure
 * @param ptr	the pointer to the member.
 * @param type	the type of the container struct this is embedded in.
 * @param member	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define container_of_constant(ptr, type, member) ({			\
		typeof( ((type *)0)->member ) *__mptr = (ptr);	\
		(type *)( (const char *)__mptr - offsetof(type,member) );})

#define NIPQUAD(addr) \
	((const unsigned char *)&addr)[0], \
	((const unsigned char *)&addr)[1], \
	((const unsigned char *)&addr)[2], \
	((const unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

#define MACPRINT(mac) \
	((const unsigned char *)mac)[0], \
	((const unsigned char *)mac)[1], \
	((const unsigned char *)mac)[2], \
	((const unsigned char *)mac)[3], \
	((const unsigned char *)mac)[4], \
	((const unsigned char *)mac)[5]
#define MACPRINT_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })


#define ARRAY_SIZE(a)	(sizeof(a) / sizeof(*a))

static inline uint32_t pal_crc32(uint32_t data, uint32_t init_val)
{
	return rte_hash_crc_4byte(data, init_val);
}

static inline uint32_t pal_hash32(uint32_t val)
{
	/* TODO choose a init_val */
	return pal_crc32(val, 0x12345678);
}

static inline uint32_t pal_hash_crc(void *data, uint32_t data_len)
{	
	return rte_hash_crc(data,data_len,0x12345678);
}

static inline uint32_t pal_hash_str(const char *str)
{
	/* TODO: choose a init_value */
	uint32_t hash = 0x12345678;
	const char *p = str;

	for(; *p != '\0'; p++) {
		hash = pal_crc32((uint32_t)*p, hash);
	}

	return hash;
}

/** @brief	memcpy mac, from src to dest
 *  @param	d  the pointer address of destination
 *  @param	s  the pointer address of source
 *  @return void
 *  @note  caller must make sure the address is 2byte aligned
 */
static inline void mac_copy(uint8_t *d, uint8_t *s)
{
	uint16_t *dest = (uint16_t *)d;
	uint16_t *src  = (uint16_t *)s;

	*dest++ = *src++;
	*dest++ = *src++;
	*dest++ = *src++;

	return;
}

static inline void pal_swap_mac(void *l2_header)
{
	uint16_t* p=(uint16_t*)l2_header;
	uint16_t tmp;

	tmp    = *p;
	*p     = *(p+3);
	*(p+3) = tmp;

	p++;

	tmp    = *p;
	*p     = *(p+3);
	*(p+3) = tmp;

	p++;

	tmp    = *p;
	*p     = *(p+3);
	*(p+3) = tmp;
}

#define pal_memcpy rte_memcpy

static inline uint32_t pal_inet_make_mask(int logmask)
{
	if (logmask)
		return pal_htonl(~((1<<(32-logmask))-1));
	return 0;
}

static inline uint32_t ip_to_prefix(uint32_t sip,uint32_t prefixlen)
{
        uint32_t prefix,mask;
        mask = pal_ntohl(pal_inet_make_mask(prefixlen));
        prefix = pal_ntohl(sip) & mask;

		return pal_htonl(prefix);
}

#endif
