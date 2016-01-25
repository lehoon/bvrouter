/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file         $HeadURL: $
* @brief        network node controlplane api
* @author       zhangyu(zhangyu09@baidu.com)
* @date         $Date:$
* @version      $Id: $
***********************************************************************
*/

#ifndef _CTL_H
#define _CTL_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libev/ev.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "pal_utils.h"
#include "bvr_hash.h"

#define NN_MSG_MAGIC_NUM 0x20140101
#define NN_CTL_MAX_MSG_LENGTH       (64 * 1024 * 1024)



typedef struct nn_msg_prefix {
    u32     msg_len;        /* length of msg, not include the prefix part */
    u32     magic_num;      /* make sure this is a valid client */
    u32     version;        /* version id*/
    u32     cmd_id;         /* cmd num*/
    u32     ret_state;      /* state of execution*/
} __attribute__((packed)) nn_msg_prefix_t;


struct listen_ev {
    struct ev_io    ev;
    int     n_conn;         /* number of active connections */
};

struct conn_ev {
    struct ev_io        ev;
    struct listen_ev    *listen_ev;
    nn_msg_prefix_t msg_prefix;
    u32         rcvd;       /* bytes already read after read_until call */
    u32         toread;     /* bytes left to be read before calling cb */
    int         needfree;   /* if this is 1, buf pointer must be freed on error */
    int         (* cb)(struct conn_ev *ev);
    void        *buf;
};

#define NAME_SIZE 64
typedef struct nn_msg_handler_info_s
{
    u32 (*handler)(struct conn_ev *ev);
    u8  name[NAME_SIZE];
} nn_msg_handler_info_t;

enum {

    NN_CMD_ID_TEST              = 1,
    NN_CMD_ID_ADD_NAMESPACE     = 2,    /*add a namespace*/
    NN_CMD_ID_DEL_NAMESPACE     = 3,    /*delete a namespace*/
    NN_CMD_ID_LIST_NAMESPACE    = 4,    /*list all namespaces*/
    NN_CMD_ID_SHOW_NAMESPACE    = 5,    /*show a namesapce*/
    NN_CMD_ID_ADD_NF_RULE       = 6,    /*add a netfilter rule*/
    NN_CMD_ID_DEL_NF_RULE       = 7,    /*delete a netfilter rule*/
    NN_CMD_ID_SHOW_NF_RULE      = 8,    /*show all netfilter rules*/
    NN_CMD_ID_FLUSH_NF_RULE     = 9,    /*flush all rules in bvrouter table*/

    NN_CMD_ID_ADD_ARP_ENTRY     = 10,   /*add a arp entry*/
    NN_CMD_ID_DEL_ARP_ENTRY     = 11,   /*delete a arp entry*/
    NN_CMD_ID_SHOW_ARP_ENTRIES  = 12,   /*show all arp entries*/
    NN_CMD_ID_ADD_INT_IF        = 13,   /*add a internal interface*/
    NN_CMD_ID_ADD_EXT_IF        = 14,   /*add a external interface*/
    NN_CMD_ID_DEL_IF            = 15,   /*delete a interface*/
    NN_CMD_ID_SHOW_IFS          = 16,   /*show all interfaces*/
    NN_CMD_ID_ADD_IP            = 17,   /*add floating ip*/
    NN_CMD_ID_DEL_IP            = 18,   /*deleye floating ip*/
    NN_CMD_ID_ADD_FDB_ENTRY     = 19,   /*add fdb entry*/
    NN_CMD_ID_DEL_FDB_ENTRY     = 20,   /*delete fdb entry*/
    NN_CMD_ID_SHOW_FDB_ENTRIES  = 21,   /*show fdb entries*/
    NN_CMD_ID_LIST_ALL_IFS      = 22,   /*show all interfaces name*/
    NN_CMD_ID_SHOW_IFS_STAT     = 23,   /*show all interface status for supervisor*/
    NN_CMD_ID_SHOW_CPU_USAGE    = 24,   /*show cpu usage for supervisor*/
    NN_CMD_ID_SHOW_ROUTE_TABLE  = 25,
    NN_CMD_ID_GET_PORT_POLLING  = 26,
    NN_CMD_ID_SET_PORT_STAT_INT = 27,
    NN_CMD_ID_SHOW_PORT_LINK_STATUS = 28,
    NN_CMD_ID_SET_PORT_LINK_STATUS = 29,
    NN_CMD_ID_ADD_ROUTE         = 30,   /*add route item*/
    NN_CMD_ID_DEL_ROUTE         = 31,   /*delete route item*/

    NN_CMD_ID_MAX_CMD,

    NN_CMD_ID_NO_CMD,
};

/* return values of ev callbacks */
enum {
    NN_EVCB_RET_RECV,
    NN_EVCB_RET_SEND,
    NN_EVCB_RET_CLOSE
};


#define NN_CTL_VERSION 0x1122

int bvr_controlplane_process(void);

#endif
