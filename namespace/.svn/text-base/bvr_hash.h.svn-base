/**
 * **********************************************************************
 * *
 * * Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
 * * @file          $HeadURL$
 * * @brief     hash function for bvrouter
 * * @author        zhangyu(zhangyu09@baidu.com)
 * * @date          $Date$
 * * @version       $Revision$ by $Author$
 * ***********************************************************************
 * */
#ifndef _BVR_HASH_H
#define _BVR_HASH_H

#include <rte_hash_crc.h>
#include <stdlib.h>
#include <syslog.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
//#define TEST
#ifdef TEST
#define LOG(msg...)\
    do{\
        printf("LOG:"msg);\
    }while(0)

#define WARNING(msg...)\
    do{\
        fprintf(stderr, "WARNING:"msg);\
    }while(0)

#define ERROR(msg...)\
    do{\
        fprintf(stderr, "ERROR:%s: %d: ", __FILE__, __LINE__);\
        fprintf(stderr, msg);\
    }while(0)

#define PANIC(msg...)\
    do{\
        fprintf(stderr, "PANIC: %s: %d: ", __FILE__, __LINE__);\
        fprintf(stderr, msg);\
        abort(); \
    }while(0)

#else
#define LOG(msg...)
#define WARNING(msg...)\
    do{\
        syslog(LOG_WARNING, "BVR WARNING: "msg);\
    }while(0)

#define ERROR(msg...)\
    do{\
        syslog(LOG_ERR, "BVR ERROR: "msg);\
    }while(0)

#define PANIC(msg...)\
    do{\
        fprintf(stderr, "PANIC: %s: %d: ", __FILE__, __LINE__);\
        fprintf(stderr, msg);\
        syslog(LOG_EMERG, "BVR PANIC: "msg);\
        abort(); \
    }while(0)
#endif


/*TODO:choose a proper prime number */
#define HASH_INIT_VAL  0xeaad8405

static inline u32 nn_hash_4byte(u32 data) {
    return rte_hash_crc_4byte(data, HASH_INIT_VAL);
}

/*
 * brief use string as hash key.
 */
static inline u32 nn_hash_str(char *data, u32 data_len) {
    return rte_hash_crc(data, data_len, HASH_INIT_VAL);
}

/*
 * brief hash function used by filter.
 */
static inline u32 nn_filter_rule_hash(u32 sip, u32 dip, u8 proto) {

    u32 init_val = HASH_INIT_VAL;
    u32 prot = proto;
    init_val = rte_hash_crc_4byte(sip, init_val);
    init_val = rte_hash_crc_4byte(dip, init_val);
    init_val = rte_hash_crc_4byte(prot, init_val);
    return init_val;
}
#endif
