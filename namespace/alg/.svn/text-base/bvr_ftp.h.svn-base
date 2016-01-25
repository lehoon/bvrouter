
#ifndef __BVR_ALG_FTP_H__
#define __BVR_ALG_FTP_H__

#include <string.h>

#include "pal_skb.h"

enum bvr_ftp_mode
{
    FTP_ACTIVE = 0,
    FTP_PASSIVE,
    FTP_MODE_MAX
};

enum bvr_ftp_type
{
    /* PORT command from client */
    FTP_PORT,
    /* PASV response from server */
    FTP_PASV,
    /* EPRT command from client */
    FTP_EPRT,
    /* EPSV response from server */
    FTP_EPSV,
};

typedef struct bvr_ftp_search_s {
    const char *pattern;
    u32 plen;
    char skip;
    char term;
    enum bvr_ftp_type ftptype;
    u32 (*getnum)(const char *, u32, u32 *, u16 *, char);
} bvr_ftp_search_t;

extern u32 bvr_alg_ftp_out(struct sk_buff *skb, u32 ftp_mode);
extern u32 bvr_alg_mangle_tcp_packet(struct sk_buff *skb, u32 match_offset, u32 match_len, const char *rep_buffer, u32 rep_len);

#endif

