
#include <libev/ev.h>
#include "pal_cpu.h"
#include "pal_conf.h"
#include "pal_thread.h"
#include "pal_skb.h"
#include "pal_pktdef.h"
#include "pal_utils.h"
#include "pal_ipgroup.h"
#include "pal_netif.h"
#include "pal_malloc.h"
#include "pal_vnic.h"
#include "bvr_hash.h"
#include "bvr_ftp.h"
#include "bvr_netfilter.h"
#include "logger.h"
static u32 bvr_try_rfc959(const char *, u32, u32 *, u16*, char);
static u32 bvr_try_eprt(const char *, u32, u32 *, u16 *, char);
static u32 bvr_try_epsv_response(const char *, u32, u32 *, u16 *, char);

static bvr_ftp_search_t search[FTP_MODE_MAX][2] = {
    [FTP_ACTIVE] = {
        {
            .pattern    = "PORT",
            .plen       = sizeof("PORT") - 1,
            .skip       = ' ',
            .term       = '\r',
            .ftptype    = FTP_PORT,
            .getnum     = bvr_try_rfc959,
        },
        {
            .pattern    = "EPRT",
            .plen       = sizeof("EPRT") - 1,
            .skip       = ' ',
            .term       = '\r',
            .ftptype    = FTP_EPRT,
            .getnum     = bvr_try_eprt,
        },
    },
    [FTP_PASSIVE] = {
        {
            .pattern    = "227 ",
            .plen       = sizeof("227 ") - 1,
            .skip       = '(',
            .term       = ')',
            .ftptype    = FTP_PASV,
            .getnum     = bvr_try_rfc959,
        },
        {
            .pattern    = "229 ",
            .plen       = sizeof("229 ") - 1,
            .skip       = '(',
            .term       = ')',
            .ftptype    = FTP_EPSV,
            .getnum     = bvr_try_epsv_response,
        },
    },
};

static u32 bvr_try_number(const char *data, u32 dlen, u32 array[], u32 array_size, char sep, char term)
{
    u32 i, len;

    memset(array, 0, sizeof(array[0])*array_size);

    /* Keep data pointing at next char. */
    for (i = 0, len = 0; len < dlen && i < array_size; len++, data++) {
        if (*data >= '0' && *data <= '9') {
            array[i] = array[i]*10 + *data - '0';
        }
        else if (*data == sep)
            i++;
        else {
            /* Unexpected character; true if it's the terminator and we're finished. */
            if (*data == term && i == array_size - 1)
                return len;

            BVR_DEBUG("Char %u (got %u nums) `%u' unexpected\n",
                    len, i, *data);
            return 0;
        }
    }
    BVR_DEBUG("Failed to fill %u numbers separated by %c\n",
            array_size, sep);
    return 0;
}

/* Returns 0, or length of numbers: 192,168,1,1,5,6 */
static u32 bvr_try_rfc959(const char *data, u32 dlen, u32 *ip, u16 *port, char term)
{
    u32 length;
    u32 array[6];

    length = bvr_try_number(data, dlen, array, 6, ',', term);
    if (length == 0)
        return 0;

    *ip =  pal_htonl((array[0] << 24) | (array[1] << 16) |
            (array[2] << 8) | array[3]);
    *port = pal_htons((array[4] << 8) | array[5]);
    return length;
}

/* Grab port: number up to delimiter */
static u32 bvr_get_port(const char *data, u32 start, u32 dlen, char delim, u16 *port)
{
    u16 tmp_port = 0;
    u32 i;

    for (i = start; i < dlen; i++) {
        /* Finished? */
        if (data[i] == delim) {
            if (tmp_port == 0)
                break;
            *port = pal_htons(tmp_port);
            BVR_DEBUG("bc_get_port: return %d\n", tmp_port);
            return i + 1;
        }
        else if (data[i] >= '0' && data[i] <= '9')
            tmp_port = tmp_port*10 + data[i] - '0';
        else { /* Some other crap */
            BVR_DEBUG("bc_get_port: invalid char.\n");
            break;
        }
    }
    return 0;
}

/* Returns 0, or length of numbers: |1|132.235.1.2|6275| or |2|3ffe::1|6275| */
static u32 bvr_try_eprt(const char *data, u32 dlen, u32 *ip, u16 *port, __unused char term)
{
    char delim;
    u32 length = 0;

    /* First character is delimiter, then "1" for IPv4 or "2" for IPv6,
       then delimiter again. */
    if (dlen <= 3) {
        BVR_DEBUG("EPRT: too short\n");
        return 0;
    }
    delim = data[0];
    if (isdigit(delim) || delim < 33 || delim > 126 || data[2] != delim) {
        BVR_DEBUG("try_eprt: invalid delimitter.\n");
    }

    /* Now we only support ipv4, whose protocol type must be equal to '1'. */
    if (data[1] != '1' /* && data[1] != '2' */) {
        BVR_DEBUG("EPRT: invalid protocol number.\n");
        return 0;
    }

    BVR_DEBUG("EPRT: Got %c%c%c\n", delim, data[1], delim);

    if (data[1] == '1') {
        u32 array[4];

        /* Now we have IP address. */
        length = bvr_try_number(data + 3, dlen - 3, array, 4, '.', delim);
        if (length != 0) {
            *ip = pal_htonl((array[0] << 24) | (array[1] << 16) | (array[2] << 8) | array[3]);
        }
    }

    if (length == 0) {
        return 0;
    }
    BVR_DEBUG("EPRT: Got IP address!\n");
    /* Start offset includes initial "|1|", and trailing delimiter */
    return bvr_get_port(data, 3 + length + 1, dlen, delim, port);
}

/* Returns 0, or length of numbers: |||6446| */
static u32 bvr_try_epsv_response(const char *data, u32 dlen, __unused u32 *ip, u16 *port, __unused char term)
{
    char delim;

    /* Three delimiters. */
    if (dlen <= 3) return 0;
    delim = data[0];
    if (isdigit(delim) || delim < 33 || delim > 126
            || data[1] != delim || data[2] != delim)
        return 0;

    return bvr_get_port(data, 3, dlen, delim, port);
}

static int bvr_find_pattern(const char *data, u32 dlen, const char *pattern, u32 plen,
        char skip, char term, u32 *numoff, u32 *numlen, u32 *ip, u16* port,
        u32 (*getnum)(const char *, u32, u32 *, u16 *, char))
{
    u32 i;

    BVR_DEBUG("find_pattern `%s': dlen = %d\n", pattern, dlen);
    if (dlen == 0)
        return 0;

    if (dlen <= plen) {
        /* Short packet: try for partial? */
        if (strncasecmp(data, pattern, dlen) == 0)
            return -1;
        else return 0;
    }

    if (strncasecmp(data, pattern, plen) != 0) {

        return 0;
    }

    BVR_DEBUG("Pattern matches!\n");
    /* Now we've found the constant string, try to skip
       to the 'skip' character */
    for (i = plen; data[i] != skip; i++)
        if (i == dlen - 1) return -1;

    /* Skip over the last character */
    i++;

    BVR_DEBUG("Skipped up to `%c'!\n", skip);

    *numoff = i;
    *numlen = getnum(data + i, dlen - i, ip, port, term);
    if (!*numlen)
        return -1;

    BVR_DEBUG("Match succeeded!\n");
    return 1;
}

#if 0
/* ip exists in pip list ? */
static u32 bc_ftp_check_ip(u32 ip, u32 *newip)
{
    bc_svc_t *svc;
    bc_work_ctx_t *ctx = PAL_PER_THREAD(work_ctx);

    svc = bc_get_svc_by_pip(ctx, ip);
    if (svc == NULL) {
        return HOOK_DROP;
    }

    *newip = svc->nat.eip;
    bc_put_svc_by_pip(ctx, ip);
    return HOOK_ACCEPT;
}
#endif
static u32 bvr_mangle_rfc959_packet(struct sk_buff *skb, u32 newip, u16 port, u32 matchoff, u32 matchlen)
{
    u8 *data = skb->mbuf.pkt.data;
    char buffer[sizeof("nnn,nnn,nnn,nnn,nnn,nnn")];

    sprintf(buffer, "%u,%u,%u,%u,%u,%u", NIPQUAD(newip), port&0xFF, port>>8);

    /* for my test: matchoff is greater than 1  */
    if (strlen(buffer) > matchlen) {
        matchoff -= (strlen(buffer) - matchlen);
    } else {
        memset(data + matchoff - 1, ' ', matchlen - strlen(buffer));
        matchoff += (matchlen - strlen(buffer));
    }
    matchlen = strlen(buffer);
    *(data + matchoff - 1) = '(';
    /* end */

    return bvr_alg_mangle_tcp_packet(skb, matchoff, matchlen, buffer, strlen(buffer));
}

/* |1|132.235.1.2|6275| */
static u32 bvr_mangle_eprt_packet(struct sk_buff *skb, u32 newip, u16 port, u32 matchoff, u32 matchlen)
{
    char buffer[sizeof("|1|255.255.255.255|65535|")];

    sprintf(buffer, "|1|%u.%u.%u.%u|%u|", NIPQUAD(newip), port);

    return bvr_alg_mangle_tcp_packet(skb, matchoff, matchlen, buffer, strlen(buffer));
}

/* |1|132.235.1.2|6275| */
static u32 bvr_mangle_epsv_packet(struct sk_buff *skb, __unused u32 newip, u16 port, u32 matchoff, u32 matchlen)
{
    char buffer[sizeof("|||65535|")];

    sprintf(buffer, "|||%u|", port);

    return bvr_alg_mangle_tcp_packet(skb, matchoff, matchlen, buffer, strlen(buffer));
}

static u32 (*bvr_mangle[])(struct sk_buff *, u32, u16, u32, u32)
= {
    [FTP_PORT] = bvr_mangle_rfc959_packet,
    [FTP_PASV] = bvr_mangle_rfc959_packet,
    [FTP_EPRT] = bvr_mangle_eprt_packet,
    [FTP_EPSV] = bvr_mangle_epsv_packet
};

static u32 bvr_ftp_mangle(struct sk_buff *skb, u32 ip, u16 port, enum bvr_ftp_type type, u32 matchoff, u32 matchlen)
{
    BVR_DEBUG("bc_ftp_mangle: type %d, off %u len %u\n", type, matchoff, matchlen);

    if (!bvr_mangle[type](skb, ip, port, matchoff, matchlen))
    {
        BVR_DEBUG("bc_ftp_mangle: mangle failed.\n");
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static void bvr_mangle_contents(struct sk_buff *skb, u32 match_offset, u32 match_len, const char *rep_buffer, u32 rep_len)
{

    u8 *data = skb->mbuf.pkt.data;
    u32 data_len = skb->mbuf.pkt.data_len;
//  struct ip_hdr *iph = skb_ip_header(skb);
//  struct tcp_hdr *tcph = skb_tcp_header(skb);
//  u32 len = data_len + iph->ihl * 4 + tcph->doff * 4;

    /* move post-replacement */
    memmove(data + match_offset + rep_len, data + match_offset + match_len,
            data_len - (match_offset + match_len));

    /* insert data from buffer */
    memcpy(data + match_offset, rep_buffer, rep_len);
    /*we never make skb len changed,rep_len the same as match_len */
#if 0
    s32 seq_offset = rep_len - match_len;
    /* update skb info */
    if (rep_len > match_len) {
        BVR_DEBUG("bc_mangle_contents: Extending packet by %u from %u bytes\n", rep_len - match_len, len);
        skb_append(skb, rep_len - match_len);
    } else {
        BVR_DEBUG("bc_mangle_contents: Shrinking packet from %u from %u bytes\n", match_len - rep_len, len);
        skb_adjust(skb, match_len - rep_len);
    }

    /* fix IP hdr checksum information */
    iph->tot_len = pal_htons(len + seq_offset);
#endif
}


/* Generic function for mangling variable-length address changes
 * (like the PORT XXX,XXX,XXX,XXX,XXX,XXX command in FTP).
 *
 * Takes care about all the nasty sequence number changes, checksumming,
 * skb enlargement, ...
 *
 * */
u32 bvr_alg_mangle_tcp_packet(struct sk_buff *skb, u32 match_offset, u32 match_len, const char *rep_buffer, u32 rep_len)
{
    struct ip_hdr *iph = skb_ip_header(skb);
    u32 pkt_len = skb->mbuf.pkt.data_len + ((u8 *)skb_data(skb) - (u8 *)skb_l2_header(skb));

    if (rep_len > match_len && (rep_len - match_len) + pkt_len > PAL_MAX_PKT_SIZE) {
        BVR_ERROR("bc_alg_mangle_tcp_packet: mangle failed, must enlarge the packet size.\n");
        return 0;
    }

    bvr_mangle_contents(skb, match_offset, match_len, rep_buffer, rep_len);

    /* TODO: maybe A problem */
    //if (rep_len != match_len) {
    //  bc_replace_tcp_seq(skb, (int)rep_len - (int)match_len);
    //}

    skb_iptcp_csum_offload(skb, iph->saddr, iph->daddr, pal_ntohs(iph->tot_len) - (iph->ihl << 2), iph->ihl << 2);
    return 1;
}

u32 bvr_alg_ftp_out(struct sk_buff *skb, u32 ftp_mode)
{
    u16 port;
    u32 i, j = 0, ret = 0;
    int found = 0;
    u32 ip, data_len, newip = 0, matchlen = 0, matchoff = 0;
    const char *data;
    struct ip_hdr *iph = skb_ip_header(skb);
    struct tcp_hdr *tcph = skb_tcp_header(skb);

    skb_pull(skb, tcph->doff * 4);

    data_len = skb_len(skb);
    data = skb_data(skb);

    for (i = FTP_ACTIVE; i < FTP_MODE_MAX; i++) {
        if (ftp_mode != FTP_MODE_MAX && ftp_mode != i) {
            continue;
        }
        for (j = 0; j < 2; j++) {
            found = bvr_find_pattern(data, data_len,
                    search[i][j].pattern,
                    search[i][j].plen,
                    search[i][j].skip,
                    search[i][j].term,
                    &matchoff, &matchlen,
                    &ip, &port,
                    search[i][j].getnum);
            if (found) goto match_end;
        }
    }

match_end:
    if (found == -1)
    {
        BVR_DEBUG("bvr_alg_ftp_out: partial %s %u+%u\n", search[i][j].pattern, pal_ntohl(tcph->seq), data_len);
        ret = NF_DROP;
        goto ftp_out;
    } else if (found == 0) {
        goto ftp_out;
    }

    BVR_DEBUG("bvr_alg_ftp_out: match `%.*s' (%u bytes at %u)\n", matchlen, data + matchoff, matchlen, pal_ntohl(tcph->seq) + matchoff);

    /*FIXME:is that OK? ALG after snat*/
    if (likely(ip != iph->saddr)) {
        newip = iph->saddr;
    }else{
        goto ftp_out;
    }

    /* mangle the packet */
    ret = bvr_ftp_mangle(skb, newip, port, search[i][j].ftptype, matchoff, matchlen);

ftp_out:
    skb_push(skb, tcph->doff * 4);
    return ret;
}

