/**
**********************************************************************
*
* Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
* @file         $HeadURL: $
* @brief        bvrouter controlplane api
* @author       zhangyu(zhangyu09@baidu.com)
* @date         $Date:$
* @version      $Id: $
***********************************************************************
*/

#include <stdlib.h>
#include "bvrouter_config.h"
#include "bvr_ctl.h"
#include "bvr_cjson.h"
#include "bvr_namespace.h"
#include "bvr_netfilter.h"
#include "bvr_errno.h"
#include "bvr_arp.h"
#include "pal_l2_ctl.h"
#include "pal_list.h"
#include "pal_vxlan.h"
#include "pal_conf.h"
#include "pal_ip_cell.h"
#include "pal_vport.h"
#include "pal_route.h"
#include "pal_error.h"
#include "logger.h"
#define NN_CTL_LISTEN_PORT 12345
extern br_conf_t g_bvrouter_conf_info;
extern struct pal_hlist_head namespace_hash_table[];


const char *target_name[NF_TARGET_MAX] = {
    [NF_DROP]   = "DROP",
    [NF_ACCEPT] = "ACCEPT",
    [NF_SNAT]   = "SNAT",
    [NF_DNAT]   = "DNAT",
    [NF_DUMP]   = "DUMP",
};
const char *hook_name[NF_MAX_HOOKS] = {
    [NF_PREROUTING]     = "PREROUTING",
    [NF_FORWARDING]     = "FORWARDING",
    [NF_POSTROUTING]    = "POSTROUTING",
};


/*
* @brief set fd to nonblock mode.
*        better to use nonblock IO in libev
* @brief return -1 for failed, 0 for success
*/
static int set_nonblock(int fd)
{

    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

/*
* @brief set fd to block mode.
*        send msg on block mode
* @brief return -1 for failed, 0 for success
*/
static int set_block(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0)
        return -1;
    return 0;
}




/**
    * @brief converts a given depth value to its corresponding mask value.
    * @param[in] depth range 1-32.
    * @return corresponding mask value
*/

static inline u32 depth_to_mask(u8 depth)
{
    ASSERT ((depth <= 32));



    /* To calculate a mask start with a 1 on the left hand side and right
     * shift while populating the left hand side with 1's
     */
    return (int) 0x80000000 >> (depth - 1);
}


/**
    * @brief parse xx.xx.xx.xx/xx to ip and prefix.
    * @param string "xx.xx.xx.xx/xx".
    * @return 0 if success, -1 error
*/

static inline u32 get_ip_and_mask(char *src, u32 *ip, u32 *mask)
{
    char digits[] = "0123456789";
    int saw_digit, octets, ch;
    u8 mask_len = 0;
    unsigned char *tp;
    saw_digit = 0;
    octets = 0;

    *ip = 0;
    tp = (unsigned char *)ip;

    while ((ch = *src ++) != '\0') {
        const char *pch;
        if((pch = strchr(digits, ch)) != NULL) {
            int new = *tp * 10 + (pch - digits);
            if (saw_digit && *tp == 0)
                return -1;
            if (new > 255)
                return -1;
            *tp = new;
            if(!saw_digit) {
                if( ++octets > 5)
                    return -1;
                saw_digit = 1;
            }
        }else if (ch == '.' && saw_digit) {
            if (octets == 4)
                return -1;
            *++tp = 0;
            saw_digit = 0;
        }else if (ch == '/' && saw_digit) {
                if (octets != 4)
                    return -1;
                tp = (unsigned char *)&mask_len;
                saw_digit = 0;
        } else
            return -1;

    }
    if ( octets != 5 || *tp > 32 || *tp < 1)
        return -1;
 //   *mask = htonl(depth_to_mask(mask_len));
 //   *ip = (*ip) & (*mask);
    *mask = mask_len;

    return 0;
}

/*
* @brief: get port_start and port_end from "xx:xx"
*/

static inline u32 get_port_range(char *src, u16 *port_start, u16 *port_end)
{
    u32 port1, port2, octets, saw_digit = 0;
    u32 *tp = &port1;

    char digits[] = "0123456789";
    char ch;

    *tp = 0;
    octets = 0;

    while ((ch = *src++) != '\0') {
        char *pch;
        if ((pch = strchr(digits, ch)) != NULL) {
            int new = *tp * 10 + (pch - digits);
            if (saw_digit && *tp == 0)
                return -1;
            if (new > 65535)
                return -1;
            *tp = new;
            if (!saw_digit) {
                if( ++octets > 2)
                    return -1;
                saw_digit = 1;
            }
        }else if (ch == ':' && saw_digit) {
            if (octets == 2)
                return -1;
            tp = &port2;
            *tp = 0;
            saw_digit = 0;

        }else {
            return -1;
        }
    }
    *port_start = (port1 <= port2) ? port1 : port2;
    *port_end = (port1 > port2) ? port1 : port2;
    return 0;
}

/*
* @brief: get mac addr from "xx:xx:xx:xx:xx:xx"
*/

static inline u32 get_mac_addr(char *src, unsigned char *dst)
{
    int count = 0;
    char *tp = strsep(&src, ":");

    while(tp != NULL) {
        if(strlen(tp) != 2) {
            return -1;
        }

        if (((tp[0] >= '0' && tp[0] <= '9') || (tp[0] >= 'A' && tp[0] <= 'F') ||
            (tp[0] >= 'a' && tp[0] <= 'f')) && ((tp[1] >= '0' && tp[1] <= '9') ||
            (tp[1] >= 'A' && tp[1] <= 'F') || (tp[1] >= 'a' && tp[1] <= 'f')))
        {

            if (++count > 6) {
                return -1;
            }
            *dst = strtoul(tp, NULL, 16);
            //BVR_DEBUG("%02x str %s\n",(unsigned char)*dst , tp);
            dst ++;
            tp = strsep(&src, ":");
        } else {
            return -1;
        }

    }

    if (count != 6)
        return -1;

    return 0;
}


/*
* @brief: send data in block mode
*/

static int send_bytes(int fd, u8 *buf, unsigned len)
{
    int nsent;

    if (set_block(fd) < 0) {
        return -1;
    }

    while (len > 0) {
        nsent = send(fd, buf, len, 0);
        if (nsent < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                set_nonblock(fd);
                return -1;
            }
        }
        len -= nsent;
        buf += nsent;
    }
    set_nonblock(fd);
    return 0;
}


/*
 * @brief only for test
 * @json param:as your wish
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_test_handler(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_test_handler called\n");
    cJSON *root = cJSON_Parse(ev->buf);
    struct ipt_nat_entry entry;
    entry.orig_ip = cJSON_GetObjectItem(root, "orig_ip")->valueint;
    entry.nat_ip = cJSON_GetObjectItem(root, "nat_ip")->valueint;
    entry.nat_target = cJSON_GetObjectItem(root, "nat_target")->valueint;
    printf("name %s\n",cJSON_GetObjectItem(root, "name")->valuestring);
    cJSON_Delete(root);
    BVR_DEBUG("test handler,we get org ip %x,nat ip %x,nat target %d\n",
        entry.orig_ip,entry.nat_ip,entry.nat_target);


    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = 10;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0) {

        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;
}

/*
 * @brief create a bvrouter
 * @json param:"name"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_create_namespace_handler(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_create_namespace_handler called\n");
    int ret = 0;
    /*parse the json string, only one name param*/
    cJSON *root = cJSON_Parse(ev->buf);

    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (!name) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    ret = net_create(name->valuestring);

ret_state:
    /*release the json root*/
    cJSON_Delete(root);
    /*return the prefix to agent*/
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    /*send prefix back*/
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}



/*
 * @brief set a interval to update port polling status
 * @json param:"interval"
 * @return 0 on success,-1 return status error
 */
#define PORT_STAT_INTER_MIN 2
#define PORT_STAT_INTER_MAX 20
static u32 bvr_cmd_set_portstatus_interval_handler(struct conn_ev *ev)
{
    BVR_DEBUG("nn_bvr_cmd_set_portstatus_interval_handler called\n");
    int ret = 0;
    /*parse the json string, only one interval param*/
    cJSON *root = cJSON_Parse(ev->buf);

    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }

    cJSON *interval = cJSON_GetObjectItem(root, "interval");
    if (!interval) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    if (interval->valueint < PORT_STAT_INTER_MIN || interval->valueint > PORT_STAT_INTER_MAX)
    {
        ret = -NN_EOUTRANGE;
        goto ret_state;
    }
    g_bvrouter_conf_info.port_stat_itl = interval->valueint;

ret_state:
    /*release the json root*/
    cJSON_Delete(root);
    /*return the prefix to agent*/
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    /*send prefix back*/
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}

/*
 * @brief get the port polling status
 * @json param:"function:port_polling"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_get_port_update_handler(struct conn_ev *ev)
{
    BVR_DEBUG("bvr_cmd_get_port_update_handler called\n");
    /*need no param, but to trigger the handler,agent must
      send a param {function:port_polling}*/

    char *out = NULL;
    cJSON *root = NULL, *func = NULL;

    /*test if the function name is right*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        cJSON_Delete(root);
        goto ret_state;
    }

    func = cJSON_GetObjectItem(root, "function");
    if (!func) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;
        cJSON_Delete(root);
        goto ret_state;
    }

    if (strcmp(func->valuestring , "port_update")) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;

        cJSON_Delete(root);
        goto ret_state;
    }
    cJSON_Delete(root);

    /*create json string to return the result*/
    root = cJSON_CreateObject();
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;

        goto ret_state;
    }
    cJSON_AddNumberToObject(root, "port_update", g_bvrouter_conf_info.port_update);
    /*after get the port status, set it to 0 and keep on watching*/
    g_bvrouter_conf_info.port_update = 0;
    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);

    /*tell agent how many bytes to receive*/
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }
    else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }


ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;

}




/*
 * @brief delete a bvrouter
 * @json param:"name"
 * @return 0 on success,-1 return status error
 */

static u32 bvr_cmd_del_namespace_handler(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_del_namespace_handler called\n");
    int ret = 0;
    /*parse the json string, only one name param*/
    cJSON *root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (!name) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    ret = del_net(name->valuestring);
    BVR_DEBUG("del namespace %s\n",cJSON_GetObjectItem(root, "name")->valuestring);

ret_state:
    /*release the json root*/
    cJSON_Delete(root);
    /*return the prefix to agent*/
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    /*send prefix back*/
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}

/*
 * @brief list all bvrouters
 * @json param:"function:list"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_list_namespace_handler(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_list_namespace_handler called\n");
    /*list cmd need no param, but to trigger the handler,agent must
      send a param {function:show}*/
    u32 i;
    struct net *net = NULL;
    struct pal_hlist_node *node = NULL;
    char *out = NULL;
    cJSON *root = NULL, *bv_name = NULL, *func = NULL;

    /*test if the function name is right*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        cJSON_Delete(root);
        goto ret_state;
    }

    func = cJSON_GetObjectItem(root, "function");
    if (!func) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;
        cJSON_Delete(root);
        goto ret_state;
    }

    if (strcmp(func->valuestring , "show")) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;

        cJSON_Delete(root);
        goto ret_state;
    }
    cJSON_Delete(root);

    /*create json string to return the result*/
    root = cJSON_CreateArray();
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;

        goto ret_state;
    }
    for (i = 0; i < NAMESPACE_TABLE_SIZE; i++) {
        pal_hlist_for_each_entry(net, node, &namespace_hash_table[i], hlist)
        {
            /*return format vrouter_name:xxxx*/
            cJSON_AddItemToArray(root, bv_name = cJSON_CreateObject());
            cJSON_AddStringToObject(bv_name, "vrouter_name", net->name);
        }
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);

    /*tell agent how many bytes to receive*/
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }
    else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }


ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;

}

/*
 * @brief wrap net's information to json format
 * @json param: net
 * @return cJSON on success,return NULL error
 */

static struct cJSON *pack_net_entry(struct net *net)
{
    struct cJSON *root = NULL;
    u32 i;
    struct statistics sum;
    memset(&sum, 0, sizeof(sum));
    char tmp[64];
    root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }
    cJSON_AddStringToObject(root, "bvrname", net->name);
    for (i = 0; i < PAL_MAX_CPU; i++)
    {
        sum.arperror_pkts += net->stats[i].arperror_pkts;
        sum.arperror_bytes += net->stats[i].arperror_bytes;
        sum.hdrerror_bytes += net->stats[i].hdrerror_bytes;
        sum.hdrerror_pkts += net->stats[i].hdrerror_pkts;
        sum.input_bytes += net->stats[i].input_bytes;
        sum.input_pkts += net->stats[i].input_pkts;
        sum.output_bytes += net->stats[i].output_bytes;
        sum.output_pkts += net->stats[i].output_pkts;
        sum.rterror_bytes += net->stats[i].rterror_bytes;
        sum.rterror_pkts += net->stats[i].rterror_pkts;
    }
    /*use string for u64*/
    sprintf(tmp, "%lu", sum.arperror_bytes);
    cJSON_AddStringToObject(root, "arperror_bytes", tmp);
    sprintf(tmp, "%lu", sum.arperror_pkts);
    cJSON_AddStringToObject(root, "arperror_pkts", tmp);
    sprintf(tmp, "%lu", sum.hdrerror_bytes);
    cJSON_AddStringToObject(root, "hdrerror_bytes", tmp);
    sprintf(tmp, "%lu", sum.hdrerror_pkts);
    cJSON_AddStringToObject(root, "hdrerror_pkts", tmp);
    sprintf(tmp, "%lu", sum.input_bytes);
    cJSON_AddStringToObject(root, "input_bytes", tmp);
    sprintf(tmp, "%lu", sum.input_pkts);
    cJSON_AddStringToObject(root, "input_pkts", tmp);
    sprintf(tmp, "%lu", sum.output_bytes);
    cJSON_AddStringToObject(root, "output_bytes", tmp);

    sprintf(tmp, "%lu", sum.output_pkts);
    cJSON_AddStringToObject(root, "output_pkts", tmp);

    sprintf(tmp, "%lu", sum.rterror_bytes);
    cJSON_AddStringToObject(root, "rterror_bytes", tmp);
    sprintf(tmp, "%lu", sum.rterror_pkts);
    cJSON_AddStringToObject(root, "rterror_pkts", tmp);
    return root;

}


/*
 * @brief show status of a bvrouter
 * @json param:"name"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_show_namespace_handler(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_show_namespace_handler called\n");
    /*show cmd need param net's name*/
    struct net *net = NULL;
    char *out = NULL;
    cJSON *root = NULL, *name = NULL;

    /*test if the function name is right*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        cJSON_Delete(root);
        goto ret_state;
    }


    name = cJSON_GetObjectItem(root, "name");
    if (!name) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;
        cJSON_Delete(root);
        goto ret_state;
    }

    net = net_get(name->valuestring);
    if (!net) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENSNOTEXIST;
        cJSON_Delete(root);
        goto ret_state;
    }

    cJSON_Delete(root);


    /*create json string to return the result*/
    root = pack_net_entry(net);
    if (root == NULL) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        goto ret_state;
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);

    /*tell agent how many bytes to receive*/
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }
    else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }

ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;

error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;

}


/*
 * @brief parse a ipt_nat_entry struct from a json string
 * @json param: json root, hook number, ipt_nat_entry
 * @return 0 for success, return status for error
 */
static int parse_ip_nat_entry(cJSON *root, u32 *hook_num, struct ipt_nat_entry *entry)
{
    int ret = 0;
    /*all the elements are position params, so we can get them*/
    *hook_num = cJSON_GetObjectItem(root, "hook_num")->valueint;
    ret = inet_aton(cJSON_GetObjectItem(root, "orig_ip")->valuestring,
        (struct in_addr *)&entry->orig_ip);
    if (!ret) {
        BVR_WARNING("parse nat entry orig ip error.\n");
        return -NN_EPARSECMD;
    }
    ret = inet_aton(cJSON_GetObjectItem(root, "nat_ip")->valuestring,
        (struct in_addr *)&entry->nat_ip);

    if (!ret) {
        BVR_WARNING("parse nat entry nat ip error.\n");
        return -NN_EPARSECMD;
    }
    entry->nat_target = cJSON_GetObjectItem(root, "nat_target")->valueint;
    return 0;
}

/*filter priority from 1-10000, 1 is the highest,default 100*/
#define NF_FILTER_PRIO_MAX 10000
#define NF_FILTER_PRIO_MIN 1

/*
 * @brief parse a ipt_filter_entry struct from a json string
 * @json param: json root, hook number, ipt_filter_entry
 * @return 0 for success, return status for error
 */
static int parse_ip_filter_entry(cJSON *root, u32 *hook_num, struct ipt_filter_entry *entry)
{
    int ret = 0;
    u32 ip = 0, mask = 0;
    cJSON *tmp = NULL;
    /*parse position params first*/
    *hook_num = cJSON_GetObjectItem(root, "hook_num")->valueint;

    entry->filter_target = cJSON_GetObjectItem(root, "target")->valueint;
    /*parse optional params*/
    if ((tmp = cJSON_GetObjectItem(root, "priority")) == NULL) {
        /*default the lowwest priority*/
        entry->priority = NF_FILTER_PRIO_MAX;
    }else {
        if (tmp->valueint < NF_FILTER_PRIO_MIN || tmp->valueint > NF_FILTER_PRIO_MAX)
        {
            BVR_WARNING("priority out of range %d\n", tmp->valueint);
            return -NN_EOUTRANGE;
        } else {
            entry->priority = tmp->valueint;
        }
    }

    if ((tmp = cJSON_GetObjectItem(root, "dir")) == NULL) {
        /*default switch off directionary pkt filter*/
        entry->dir = 0;
        BVR_DEBUG("no dir %d\n", entry->dir);
    }else {
        if (tmp->valueint < 0 || tmp->valueint > 1)
        {
            BVR_WARNING("dir out of range %d\n", tmp->valueint);
            return -NN_EOUTRANGE;
        } else {
            entry->dir = tmp->valueint;
        }
        BVR_DEBUG("got entry dir %d\n", entry->dir);
    }


    if ((tmp = cJSON_GetObjectItem(root, "sip")) == NULL) {
        entry->key.sip = 0;
        entry->mask_value.sip = 0;
    }else {
        ret = get_ip_and_mask(tmp->valuestring, &ip, &mask);
        if (ret) {
            BVR_WARNING("parse filter entry sip/mask error\n");
            return -NN_EPARSECMD;
        }

        entry->mask_value.sip = htonl(depth_to_mask(mask));
        entry->key.sip = ip & entry->mask_value.sip;
    }

    if ((tmp = cJSON_GetObjectItem(root, "dip")) == NULL) {
        entry->key.dip = 0;
        entry->mask_value.dip = 0;
    }else {
        ret = get_ip_and_mask(tmp->valuestring, &ip, &mask);
        if (ret) {
            BVR_WARNING("parse filter entry dip/mask error\n");
            return -NN_EPARSECMD;
        }
        entry->mask_value.dip = htonl(depth_to_mask(mask));
        entry->key.dip = ip & entry->mask_value.dip;

    }

    if ((tmp = cJSON_GetObjectItem(root, "sport")) == NULL) {
        entry->key.sport[0]= 0;
        entry->key.sport[1]= 0;
        /*if sport not set, mark sport mask as 0*/
        entry->mask_value.sport = 0;
    }else {
        /*parse the port range in host byteorder, when filter the pkts, change pkt's port
          into host byteorder*/
        ret = get_port_range(tmp->valuestring, &entry->key.sport[0], &entry->key.sport[1]);
        if (ret) {
            BVR_WARNING("parse filter entry sport error\n");
            return -NN_EPARSECMD;
        }
        /*if sport has been set, mark sport mask as 1*/
        BVR_DEBUG("parse sport1 %d-%p, sport2 %d-%p\n", entry->key.sport[0],
        &entry->key.sport[0], entry->key.sport[1], &entry->key.sport[1]);
        entry->mask_value.sport = 1;
    }

    if ((tmp = cJSON_GetObjectItem(root, "dport")) == NULL) {
        entry->key.dport[0] = 0;
        entry->key.dport[1] = 0;
        /*if sport not set, mark sport mask as 0*/
        entry->mask_value.dport = 0;
    }else {
        ret = get_port_range(tmp->valuestring, &entry->key.dport[0], &entry->key.dport[1]);
        if (ret) {
            BVR_WARNING("parse filter entry dport error\n");
            return -NN_EPARSECMD;
        }
        /*if dport has been set, mark dport mask as 1*/
        entry->mask_value.dport = 1;
    }

    if ((tmp = cJSON_GetObjectItem(root, "proto")) == NULL) {
        entry->key.proto = 0;
        entry->mask_value.proto = 0;
    }else {
        /*here proto pass as protocol number*/
        entry->key.proto = tmp->valueint;
        entry->mask_value.proto = 1;
    }
    return 0;
}


/*
 * @brief add netfilter rule to bvrouter
 * @json param:"bvrouter" "table"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_add_netfilter_rule(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_add_netfilter_rule called\n");

    struct net *net = NULL;
    u32 hook_num = 0, ret = 0;


    /*parse the bvrouter name, if bvrouter not exist return error*/
    cJSON *root = cJSON_Parse(ev->buf);
    if (NULL == root) {
        ret = -NN_ENOMEM;
        BVR_WARNING("parse root error\n");
        goto ret_state;
    }
    cJSON_GetObjectItem(root, "bvrouter");

    cJSON *bvname = cJSON_GetObjectItem(root, "bvrouter");
    if (NULL == bvname) {
        ret = -NN_EPARSECMD;
        BVR_WARNING("parse bvrouter error\n");
        goto ret_state;
    }
    //BVR_DEBUG("test for json bvrouter string %s\n",bvname->valuestring);
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }

    cJSON *table = cJSON_GetObjectItem(root, "table");
    if (NULL == table) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }
    //BVR_DEBUG("test for json table string %s\n", table->valuestring);

    /*for nat table, parse struct ipt_nat_entry*/
    if (!strcmp(table->valuestring, NAT_TABLE))
    {
        struct ipt_nat_entry nat_entry;
        memset(&nat_entry, 0, sizeof(nat_entry));
        ret = parse_ip_nat_entry(root, &hook_num, &nat_entry);

        if (ret) {
            BVR_WARNING("parse ipt_nat_entry error.\n");
            goto ret_state;
        }

        /*in function insert ipt rule, lock the net_lock */
        ret = ipt_nat_insert_rule(net, hook_num, nat_entry);
    }

    /*for filter table, parse struct ipt_filter_entry*/
    else if (!strcmp(table->valuestring, FILTER_TABLE))
    {
        struct ipt_filter_entry filter_entry;
        memset(&filter_entry, 0, sizeof(filter_entry));
        ret = parse_ip_filter_entry(root, &hook_num, &filter_entry);

        if (ret) {
            BVR_WARNING("parse ipt_filter_entry error.\n");
            goto ret_state;
        }
        BVR_DEBUG("sport %d-%p \n",filter_entry.key.sport[1],&filter_entry.key.sport[1]);
        ret = ipt_filter_add_rule(net, hook_num, filter_entry);

    } else {
        BVR_WARNING("table is neither nat nor filter\n");
        ret = -NN_EINVAL;
    }

ret_state:

    cJSON_Delete(root);

    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}


/*
 * @brief delete netfilter rule from bvrouter
 * @json param:"bvrouter" "table"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_del_netfilter_rule(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_del_netfilter_rule called\n");

    struct net *net = NULL;
    u32 hook_num = 0, ret = 0;

    /*parse the bvrouter name, if bvrouter not exist return error*/
    cJSON *root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);
    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }

    cJSON *table = cJSON_GetObjectItem(root, "table");
    if (NULL == table) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    /*for nat table, parse struct ipt_nat_entry*/
    if (!strcmp(table->valuestring, "nat"))
    {
        struct ipt_nat_entry nat_entry;
        memset(&nat_entry, 0, sizeof(nat_entry));

        hook_num = cJSON_GetObjectItem(root, "hook_num")->valueint;
        ret = inet_aton(cJSON_GetObjectItem(root, "orig_ip")->valuestring,
            (struct in_addr *)&nat_entry.orig_ip);

        if (!ret) {
            BVR_WARNING("parse nat entry orig ip error.\n");
            ret =  -NN_EPARSECMD;
            goto ret_state;
        }


        /*before insert ipt rule,get the net rw lock for write first*/
        ret = ipt_nat_del_rule(net, hook_num, nat_entry);

    }else if(!strcmp(table->valuestring, "filter"))
    {
        /*for filter table, parse struct ipt_filter_entry*/
        struct ipt_filter_entry filter_entry;
        memset(&filter_entry, 0, sizeof(filter_entry));
        ret = parse_ip_filter_entry(root, &hook_num, &filter_entry);

        if (ret) {
            goto ret_state;
        }

        ret = ipt_filter_del_rule(net, hook_num, filter_entry);

    } else {
        BVR_WARNING("table is neither nat nor filter\n");
        ret = -NN_EINVAL;
    }
ret_state:
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}





static struct cJSON *pack_ipt_nat_rule(struct net *net)
{
    u32 i = 0 ,j = 0, k = 0;
    struct cJSON *root = NULL, *sub = NULL, *rule = NULL;
    char tmp[64];
    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }

    /*not necessary to readlock net lock. cause single thread in controlplane */
    struct xt_nat_table *nat_table = (struct xt_nat_table *)net->nat->private;

    for (i = 0; i < NF_MAX_HOOKS; i++) {
        //cJSON_AddItemTo(root, sub = cJSON_CreateObject());
        cJSON_AddItemToObject(root, hook_name[i], sub = cJSON_CreateArray());
        //cJSON_AddStringToObject(sub, "hook_num", hook_name[i]);
        for (j = 0; j < NAT_TABLE_SIZE; j++) {
            struct ipt_nat_entry *entry = NULL;
            struct pal_hlist_node *pos = NULL;

            struct nat_rule_table *table = &nat_table->table[i];
            struct pal_hlist_head *head = &table->nat_hmap[j];
            pal_hlist_for_each_entry(entry, pos, head, hlist) {
                u64 pcnt = 0, bcnt = 0;
                cJSON_AddItemToArray(sub, rule = cJSON_CreateObject());
                switch (entry->nat_target) {
                    case NF_SNAT:
                        cJSON_AddStringToObject(rule, "source-ip", trans_ip(entry->orig_ip, 0));
                        cJSON_AddStringToObject(rule, "to-ip", trans_ip(entry->nat_ip, 0));
                        cJSON_AddStringToObject(rule, "target", "SNAT");
                        for (k = 0; k < PAL_MAX_CPU; k++) {
                            pcnt += entry->counter.cnt[k].pcnt;
                            bcnt += entry->counter.cnt[k].bcnt;
                        }
                        sprintf(tmp, "%lu", pcnt);
                        cJSON_AddStringToObject(rule, "hit_pkts", tmp);
                        sprintf(tmp, "%lu", bcnt);
                        cJSON_AddStringToObject(rule, "hit_bytes", tmp);

                        break;
                    case NF_DNAT:
                        cJSON_AddStringToObject(rule, "destination-ip", trans_ip(entry->orig_ip, 0));
                        cJSON_AddStringToObject(rule, "to-ip", trans_ip(entry->nat_ip, 0));
                        cJSON_AddStringToObject(rule, "target", "DNAT");
                        for (k = 0; k < PAL_MAX_CPU; k++) {
                            pcnt += entry->counter.cnt[k].pcnt;
                            bcnt += entry->counter.cnt[k].bcnt;
                        }
                        sprintf(tmp, "%lu", pcnt);
                        cJSON_AddStringToObject(rule, "hit_pkts", tmp);
                        sprintf(tmp, "%lu", bcnt);
                        cJSON_AddStringToObject(rule, "hit_bytes", tmp);
                        break;
                    default:
                        break;
                }
            }
        }

    }

    return root;
}

static struct cJSON *pack_ipt_filter_rule(struct net *net)
{
    u32 i ,j, k;
    struct cJSON *root = NULL, *sub = NULL, *rule = NULL;
    char tmp[64];
    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }
    /*not necessary to readlock net lock. cause single thread in controlplane */
    struct xt_filter_table *filter_table = (struct xt_filter_table *)net->filter->private;

    for (i = 0; i < NF_MAX_HOOKS; i++) {
        cJSON_AddItemToObject(root, hook_name[i], sub = cJSON_CreateArray());
        //cJSON_AddStringToObject(sub, "hook_num", hook_name[i]);
        for (j = 0; j < FILTER_TABLE_SIZE; j++) {
            struct ipt_filter_entry *entry = NULL;
            struct pal_hlist_node *pos = NULL;
            struct pal_hlist_head *head = &filter_table->table[i].filter_hmap[j];
            pal_hlist_for_each_entry(entry, pos, head, hlist) {

                u64 bcnt = 0, pcnt = 0;
                cJSON_AddItemToArray(sub, rule = cJSON_CreateObject());

                cJSON_AddStringToObject(rule, "source-ip", trans_ip(entry->key.sip,
                    get_mask_count(entry->mask_value.sip)));
                BVR_DEBUG("mask %x",entry->mask_value.sip);
                cJSON_AddStringToObject(rule, "destination-ip", trans_ip(entry->key.dip,
                    get_mask_count(entry->mask_value.dip)));
                cJSON_AddNumberToObject(rule, "source-port-start", entry->key.sport[0]);
                cJSON_AddNumberToObject(rule, "source-port-end", entry->key.sport[1]);
                BVR_DEBUG("pack filter sport %d-%p, sport2 %d-%p\n", entry->key.sport[0], &entry->key.sport[0],
                    entry->key.sport[1],&entry->key.sport[1]);

                cJSON_AddNumberToObject(rule, "dest-port-start", entry->key.dport[0]);
                cJSON_AddNumberToObject(rule, "dest-port-end", entry->key.dport[1]);
                cJSON_AddNumberToObject(rule, "proto", entry->key.proto);
                cJSON_AddNumberToObject(rule, "priority", entry->priority);
                cJSON_AddNumberToObject(rule, "dir", entry->dir);

                cJSON_AddStringToObject(rule, "target", target_name[entry->filter_target]);
                for (k = 0; k < PAL_MAX_CPU; k++) {
                    pcnt += entry->counter.cnt[k].pcnt;
                    bcnt += entry->counter.cnt[k].bcnt;
                }

                sprintf(tmp, "%lu", pcnt);
                cJSON_AddStringToObject(rule, "hit_pkts", tmp);
                sprintf(tmp, "%lu", bcnt);
                cJSON_AddStringToObject(rule, "hit_bytes", tmp);
            }
        }
    }

    return root;
}


 /*
 * @brief show netfilter rule of bvrouter
 * @json param:"bvrouter" "table"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_show_netfilter_rule(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_add_netfilter_rule called\n");

    struct net *net = NULL;
    char table_name[32];
    char *out = NULL;

    /*parse the bvrouter name, if bvrouter not exist return error*/
    cJSON *root = NULL;
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        cJSON_Delete(root);
        goto ret_state;
    }

    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);
    if (!net) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENSNOTEXIST;
        cJSON_Delete(root);
        goto ret_state;
    }

    cJSON *table = cJSON_GetObjectItem(root, "table");
    if (NULL == table) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;
        cJSON_Delete(root);
        goto ret_state;
    }

    strcpy(table_name, table->valuestring);
    cJSON_Delete(root);

    if (!strcmp(table_name, NAT_TABLE)) {
        root = pack_ipt_nat_rule(net);
        if (root == NULL) {
            ev->msg_prefix.msg_len = 0;
            ev->msg_prefix.ret_state = -NN_ENOMEM;
            goto ret_state;
        }

    }else if (!strcmp(table_name, FILTER_TABLE)) {
        root = pack_ipt_filter_rule(net);
        if (root == NULL) {
            ev->msg_prefix.msg_len = 0;
            ev->msg_prefix.ret_state = -NN_ENOMEM;
            goto ret_state;
        }
    }else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EINVAL;
        goto ret_state;
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    } else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }


ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;
}


/*
 * @brief flush netfilter rule in bvrouter table
 * @json param:"bvrouter" "table"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_flush_netfilter_rule(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_flush_netfilter_rule called\n");

    struct net *net = NULL;
    u32 ret = 0;


    /*parse the bvrouter name, if bvrouter not exist return error*/
    cJSON *root = cJSON_Parse(ev->buf);
    if (NULL == root) {
        ret = -NN_ENOMEM;
        BVR_WARNING("parse root error\n");
        goto ret_state;
    }
    cJSON_GetObjectItem(root, "bvrouter");

    cJSON *bvname = cJSON_GetObjectItem(root, "bvrouter");
    if (NULL == bvname) {
        ret = -NN_EPARSECMD;
        BVR_WARNING("parse bvrouter error\n");
        goto ret_state;
    }
    //BVR_DEBUG("test for json bvrouter string %s\n",bvname->valuestring);
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }

    cJSON *table = cJSON_GetObjectItem(root, "table");
    if (NULL == table) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }
    //BVR_DEBUG("test for json table string %s\n", table->valuestring);

    /*for nat table, parse struct ipt_nat_entry*/
    if (!strcmp(table->valuestring, NAT_TABLE))
    {
        ipt_nf_nat_rules_flush(net);
    }

    /*for filter table, parse struct ipt_filter_entry*/
    else if (!strcmp(table->valuestring, FILTER_TABLE))
    {
        ipt_nf_filter_rules_flush(net);

    } else {
        BVR_WARNING("table is neither nat nor filter\n");
        ret = -NN_EINVAL;
    }

ret_state:

    cJSON_Delete(root);

    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}



/*
 * @brief add arp entry to bvrouter
 * @json param:"bvrouter" "ip" "mac"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_add_arp_table_entry(struct conn_ev *ev)
{

    BVR_DEBUG("nn_cmd_add_arp_entry called\n");
    //    struct net *net = NULL;
    struct cJSON *root = NULL;
    struct vxlan_arp_entry entry;
    int vni = -1;
    int ret = 0;

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }

    /*remove the bvrouter param,because this command called in l2-agent*/
    #if 0
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    #endif

    /*parse params*/
    vni = cJSON_GetObjectItem(root, "vni")->valueint;

    ret = inet_aton(cJSON_GetObjectItem(root, "ip")->valuestring, (struct in_addr *)&entry.ip);
    if (!ret) {
        BVR_WARNING("ip addr parse error %s\n",cJSON_GetObjectItem(root, "ip")->valuestring);
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    ret = get_mac_addr(cJSON_GetObjectItem(root, "mac")->valuestring, entry.mac_addr);
    if (ret) {
        BVR_WARNING("mac addr parse error\n");
        ret = -NN_EPARSECMD;
        goto ret_state;
    }
    BVR_DEBUG("arp entry add mac "MACPRINT_FMT, MACPRINT(entry.mac_addr));
    ret = vxlan_arp_add_ctl(vni, &entry);
    if (ret) {
        if (ret == -ENXIO || ret == -ESRCH) {
            ret = -NN_EIFNOTEXIST;
            goto ret_state;
        }else if (ret == -EEXIST) {
            ret = -NN_EARPEXIST;
            goto ret_state;
        }else if (ret == -ENOSPC) {
            ret = -NN_ENOSPACE;
            goto ret_state;
        }else if (ret == -ENOMEM) {
            ret = -NN_ENOMEM;
            goto ret_state;
        }else {
            BVR_WARNING("unknown error code when add arp entry return the orignal code %d", ret);
            goto ret_state;
        }
    }

ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}


/*
 * @brief delete arp entry from bvrouter
 * @json param:"bvrouter" "ip"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_del_arp_table_entry(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_del_arp_entry called\n");
    //  struct net *net = NULL;
    struct cJSON *root = NULL;
    int vni = -1;
    int ret = 0;
    struct vxlan_arp_entry entry;
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }
    /*remove the bvrouter param,because this command called in l2-agent*/
    #if 0
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    #endif
    /*parse params*/
    vni = cJSON_GetObjectItem(root, "vni")->valueint;

    ret = inet_aton(cJSON_GetObjectItem(root, "ip")->valuestring, (struct in_addr *)&entry.ip);
    if (!ret) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    ret = vxlan_arp_delete_ctl(vni, &entry);

    if (ret) {
        if (ret == -ENXIO || ret == -ESRCH) {
            ret = -NN_EIFNOTEXIST;
            goto ret_state;
        }else if (ret == -ENOENT) {
            ret = -NN_EARPNOTEXIST;
            goto ret_state;
        }else {
            BVR_WARNING("unknown error code when del arp entry return the orignal code %d", ret);
            goto ret_state;
        }
    }

ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}


__unused static struct cJSON *pack_arp_table_entries(struct net *net)
{
    struct cJSON *root = NULL, *sub = NULL;
    struct pal_hlist_head *head = NULL;
    u32 i;
    struct arp_entry *entry = NULL;
    struct pal_hlist_node *pos = NULL;

    root = cJSON_CreateArray();
    if (root == NULL) {
        return NULL;
    }
    /*we are in control plane ,no lock*/
    head = net->arp_table;
    for(i = 0; i < ARP_TABLE_SIZE; i++)
    {
        pal_hlist_for_each_entry(entry, pos, &head[i], hlist)
        {
            cJSON_AddItemToArray(root, sub = cJSON_CreateObject());
            cJSON_AddStringToObject(sub, "ip", trans_ip(entry->ip, 0));

            cJSON_AddStringToObject(sub, "mac", trans_mac(entry->mac_addr));
        }

    }

    return root;
}

/*TODO*/
static struct cJSON *pack_arp_entries(struct vxlan_dev *vport)
{
    u32 i = 0;
    struct cJSON *root = NULL, *sub = NULL;
    struct vxlan_arp_entry *entry = NULL;
    struct pal_hlist_node *pos = NULL;

    root = cJSON_CreateArray();
    if (root == NULL) {
        return NULL;
    }
    for (i = 0; i < ARP_HASH_SIZE; i++)
    {
        pal_hlist_for_each_entry(entry, pos, vxlan_arp_head_index(vport, i), hlist)
        {
            cJSON_AddItemToArray(root, sub = cJSON_CreateObject());
            cJSON_AddStringToObject(sub, "ip", trans_ip(entry->ip, 0));
            cJSON_AddStringToObject(sub, "mac", trans_mac(entry->mac_addr));

        }
    }
    return root;
}



/*
 * @brief show arp entries of bvrouter
 * @json param:"bvrouter"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_show_arp_table_entries(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_show_fdb_table_entries called\n");
    //    struct net *net = NULL;
    char *out = NULL;
    cJSON *root = NULL;

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        goto ret_state;
    }
    /*remove the bvrouter param,because this command called in l2-agent*/
    #if 0
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);
    if (!net) {
    BVR_WARNING("no bvrouter found\n");
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = -NN_ENSNOTEXIST;
    cJSON_Delete(root);
    goto ret_state;
    }
    #endif
    /*get interface name*/
    int vni = cJSON_GetObjectItem(root, "vni")->valueint;
    struct vxlan_dev *vxlan_dev = get_vxlan_dev(vni);
    if (!vxlan_dev) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EIFNOTEXIST;
        cJSON_Delete(root);
        goto ret_state;
    }
    cJSON_Delete(root);

    /*pack interface information in cjson*/
    root = pack_arp_entries(vxlan_dev);
    if (root == NULL) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        goto ret_state;
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }
ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;
}




static int parse_int_vport_entry(cJSON *root, struct int_vport_entry *entry)
{
    int ret = 0;
    char *mac = NULL;
    entry->vport_name = cJSON_GetObjectItem(root, "ifname")->valuestring;
    entry->uuid = cJSON_GetObjectItem(root, "uuid")->valuestring;
    mac = cJSON_GetObjectItem(root, "mac")->valuestring;
    ret = get_mac_addr(mac, (unsigned char *)entry->int_gw_mac);

    if (ret) {
        return -1;
    }

    ret = get_ip_and_mask(cJSON_GetObjectItem(root, "ip")->valuestring,
        &entry->int_gw_ip, &entry->prefix_len);
    if (ret) {
        return -1;
    }

    entry->vni = cJSON_GetObjectItem(root, "vni")->valueint;
    return 0;
}


/*
 * @brief add a internal interface to a bvrouter
 * @json param:"bvrouter" "interface" "ip/prefix" "mac" "vni"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_add_internal_interface(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_add_internal_interface called\n");
    struct net *net = NULL;
    struct cJSON *root = NULL;
    int ret = 0;
    struct int_vport_entry entry;
    /*internal port add or remove should update port_polling*/
    g_bvrouter_conf_info.port_update = 1;
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }
    /*parse json cmd to find the bvrouter*/
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    /*parse params*/
    ret = parse_int_vport_entry(root, &entry);
    if (ret) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }


    ret = int_vport_add_ctl(&entry, net);
    BVR_DEBUG("int port add name :%s\n ", entry.vport_name);
    if (ret) {
        if (ret == -EEXIST) {
            ret = -NN_EIFEXIST;
            goto ret_state;
        }else if (ret == -ENOMEM) {
            ret = -NN_ENOMEM;
            BVR_DEBUG("out of mem when add if\n");
            goto ret_state;
        }else if (ret == -ENXIO) {
            ret = -NN_EINVAL;
            goto ret_state;
        }else if (ret == -ENOSPC) {
            ret = -NN_ENOSPACE;
            goto ret_state;
        }else if (ret == -ERANGE) {
            ret = -NN_EOUTRANGE;
            goto ret_state;
        }else {
            BVR_WARNING("unknown error code when add internal interface return the orignal code %d", ret);
            goto ret_state;
        }
    }
ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}



static int parse_ext_vport_entry(cJSON *root, struct phy_vport_entry *entry)
{
    int ret = 0;
    entry->vport_name = cJSON_GetObjectItem(root, "ifname")->valuestring;
    entry->uuid =  cJSON_GetObjectItem(root, "uuid")->valuestring;

    ret = get_ip_and_mask(cJSON_GetObjectItem(root, "ip")->valuestring,
        &entry->ext_gw_ip, &entry->prefix_len);
    if (ret) {
        return -1;
    }
    return 0;
}


/*
 * @brief add a external interface to a bvrouter
 * @json param:"bvrouter" "interface" "ip/prefix"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_add_external_interface(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_add_external_interface called\n");
    struct net *net = NULL;
    struct cJSON *root = NULL;
    int ret = 0;
    struct phy_vport_entry entry;
    /*parse json cmd to find the bvrouter*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    /*parse params*/
    ret = parse_ext_vport_entry(root, &entry);
    BVR_DEBUG("external port add name %s \n",entry.vport_name);
    if (ret) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    ret = phy_vport_add_ctl(&entry, net);

    if (ret) {
        if (ret == -EEXIST) {
            ret = -NN_EIFEXIST;
            goto ret_state;
        }else if (ret == -EPERM) {
            ret = -NN_EIPEXIST;
            goto ret_state;
        }else if (ret == -ENOMEM) {
            ret = -NN_ENOMEM;
            goto ret_state;
        }else if (ret == -ENXIO) {
            ret = -NN_EINVAL;
            goto ret_state;
        }else if (ret == -ENOSPC) {
            ret = -NN_ENOSPACE;
            goto ret_state;
        }else {
            BVR_WARNING("unknown error code when add external interface return the orignal code %d", ret);
            goto ret_state;
        }
    }

ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}


/*
 * @brief delete a internal or external interface from a bvrouter
 * @json param:"bvrouter" "interface"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_del_interface(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_delete_interface called\n");
    struct net *net = NULL;
    struct cJSON *root = NULL;
    char *ifname = NULL;
    int ret = 0;
    /*internal port add or remove should update port_polling*/
    g_bvrouter_conf_info.port_update = 1;
    /*parse json cmd to find the bvrouter*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }

    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    /*parse params*/
    ifname = cJSON_GetObjectItem(root, "ifname")->valuestring;
    ret = vport_delete_ctl(ifname);
    if (ret) {
        if (ret == -EIO || ret == -ENXIO) {
            ret = -NN_EIFNOTEXIST;
            goto ret_state;
        }else {
            BVR_WARNING("unknown error code when delete interface return the orignal code %d", ret);
            goto ret_state;
        }
    }
ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}

/*TODO:vport delete interface should return a json string*/
static struct cJSON *pack_interfaces_entries(struct net *net)
{
    struct vport *pos = NULL;
    struct cJSON *root = NULL, *sub = NULL;
    char tmp[64];
    u32 i = 0;
    root = cJSON_CreateArray();
    if (root == NULL) {
        return NULL;
    }

    pal_list_for_each_entry(pos, &net->dev_base_head, list_nd)
    {
        cJSON_AddItemToArray(root, sub = cJSON_CreateObject());
        cJSON_AddStringToObject(sub, "ifname", pos->vport_name);
        cJSON_AddStringToObject(sub, "inet addr", trans_ip(pos->vport_ip, pos->prefix_len));
        cJSON_AddStringToObject(sub, "hwaddr", trans_mac(pos->vport_eth_addr));
        /*for phy vport pack floating ip and status*/
        if (pos->vport_type == PHY_VPORT) {
            struct phy_vport *phy_vport = (struct phy_vport *)pos;
            struct ip_cell *fip = NULL;
            struct cJSON *sub_sub = NULL, *ip_info = NULL;
            cJSON_AddItemToObject(sub, "floating IPs", sub_sub = cJSON_CreateArray());

            pal_list_for_each_entry(fip, &phy_vport->floating_list, list)
            {
                cJSON_AddItemToArray(sub_sub, ip_info = cJSON_CreateObject());
                cJSON_AddStringToObject(ip_info, "inet addr", trans_ip(fip->ip, 0));
            }
            /*pack the statistics*/
            struct vport_stats stats;
            memset(&stats, 0, sizeof(stats));

            for (i = 0; i < PAL_MAX_CPU; i++) {
                stats.rx_packets += phy_vport->stats[i].rx_packets;
                stats.rx_errors += phy_vport->stats[i].rx_errors;
                stats.rx_dropped += phy_vport->stats[i].rx_dropped;
                stats.tx_packets += phy_vport->stats[i].tx_packets;
                stats.tx_errors += phy_vport->stats[i].tx_errors;
                stats.tx_dropped += phy_vport->stats[i].tx_dropped;
            }
            sprintf(tmp, "%lu", stats.rx_packets);
            cJSON_AddStringToObject(sub, "rx_pkts", tmp);
            sprintf(tmp, "%lu", stats.rx_dropped);
            cJSON_AddStringToObject(sub, "rx_dropped", tmp);
            sprintf(tmp, "%lu", stats.rx_errors);
            cJSON_AddStringToObject(sub, "rx_errors", tmp);
            sprintf(tmp, "%lu", stats.tx_packets);
            cJSON_AddStringToObject(sub, "tx_pkts", tmp);
            sprintf(tmp, "%lu", stats.tx_dropped);
            cJSON_AddStringToObject(sub, "tx_dropped", tmp);
            sprintf(tmp, "%lu", stats.tx_errors);
            cJSON_AddStringToObject(sub, "tx_errors", tmp);

        }
        if (pos->vport_type == VXLAN_VPORT) {
            /*pack vxlan statistics*/
            struct int_vport *vxlan_vport = (struct int_vport *)pos;

            struct vport_stats stats;
            memset(&stats, 0, sizeof(stats));

            for (i = 0; i < PAL_MAX_CPU; i++) {
                stats.rx_packets += vxlan_vport->stats[i].rx_packets;
                stats.rx_errors += vxlan_vport->stats[i].rx_errors;
                stats.rx_dropped += vxlan_vport->stats[i].rx_dropped;
                stats.tx_packets += vxlan_vport->stats[i].tx_packets;
                stats.tx_errors += vxlan_vport->stats[i].tx_errors;
                stats.tx_dropped += vxlan_vport->stats[i].tx_dropped;
            }
            sprintf(tmp, "%lu", stats.rx_packets);
            cJSON_AddStringToObject(sub, "rx_pkts", tmp);
            sprintf(tmp, "%lu", stats.rx_dropped);
            cJSON_AddStringToObject(sub, "rx_dropped", tmp);
            sprintf(tmp, "%lu", stats.rx_errors);
            cJSON_AddStringToObject(sub, "rx_errors", tmp);
            sprintf(tmp, "%lu", stats.tx_packets);
            cJSON_AddStringToObject(sub, "tx_pkts", tmp);
            sprintf(tmp, "%lu", stats.tx_dropped);
            cJSON_AddStringToObject(sub, "tx_dropped", tmp);
            sprintf(tmp, "%lu", stats.tx_errors);
            cJSON_AddStringToObject(sub, "tx_errors", tmp);
            sprintf(tmp, "%u", vxlan_vport->vdev->vni);
            cJSON_AddStringToObject(sub, "vni", tmp);

        }
        /*TODO:pack floating ip into interface infomation*/
    }

    return root;
}

/*
 * @brief show all interfaces of a bvrouter
 * @json param:"bvrouter"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_show_interfaces(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_show_arp_table_entries called\n");
    struct net *net = NULL;
    char *out = NULL;
    cJSON *root = NULL;
    /*parse the bvrouter name, if bvrouter not exist return error*/

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        goto ret_state;
    }
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);
    if (!net) {
        BVR_WARNING("no bvrouter found\n");
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENSNOTEXIST;
        cJSON_Delete(root);
        goto ret_state;
    }
    cJSON_Delete(root);

    /*pack interface information in cjson*/
    root = pack_interfaces_entries(net);
    if (root == NULL) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        goto ret_state;
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }

ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
         }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;

}


static struct cJSON *pack_route_table_entries(struct net *net)
{
    struct route_entry_table reb;
    memset(&reb, 0, sizeof(reb));
    struct cJSON *root = NULL, *sub = NULL;
    int i = 0;
    root = cJSON_CreateArray();
    if (root == NULL) {
        return NULL;
    }

    pal_trie_traverse(net->route_table, &reb);

    for (i = 0; i < reb.len; i++) {
        u32 mask;
        if (reb.r_table[i].prefixlen && reb.r_table[i].prefixlen <= 32)
        {
            mask = depth_to_mask(reb.r_table[i].prefixlen);
        }else {
            mask = 0;
        }

        cJSON_AddItemToArray(root, sub = cJSON_CreateObject());
        cJSON_AddStringToObject(sub, "destination", trans_ip(reb.r_table[i].prefix, 0));
        cJSON_AddStringToObject(sub, "gateway", trans_ip(reb.r_table[i].next_hop, 0));
        cJSON_AddStringToObject(sub, "mask", trans_ip(htonl(mask), 0));
        cJSON_AddStringToObject(sub, "interface", reb.r_table[i].dev->vport_name);
    }
    return root;
}

/*
 * @brief show route table of a bvrouter
 * @json param:"bvrouter"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_show_route_table(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_show_route_table_entries called\n");
    struct net *net = NULL;
    char *out = NULL;
    cJSON *root = NULL;
    /*parse the bvrouter name, if bvrouter not exist return error*/

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        goto ret_state;
    }
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);
    if (!net) {
        BVR_WARNING("no bvrouter found\n");
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENSNOTEXIST;
        cJSON_Delete(root);
        goto ret_state;
    }
    cJSON_Delete(root);

    /*pack route information in cjson*/
    root = pack_route_table_entries(net);
    if (root == NULL) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        goto ret_state;
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }

ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
         }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;

}



/**
 * Add a route item to a vrouter
 * @param json params - "bvrouter" "network/prefix" "interface" "nexthop"
 * @return 0 on success, otherwise status error
 */
static u32 bvr_cmd_add_route(struct conn_ev *ev) {
    BVR_DEBUG("nn_cmd_add_route called\n");
    uint32_t prefix = 0;
    uint32_t prefixlen = 0;
    uint32_t nexthop_nl = 0;
    int ret = 0;
    struct net *net = NULL;
    char *to_vport = NULL;
    cJSON *nexthop = NULL;
    cJSON *root = NULL;
    cJSON *cidr = NULL;

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    /*parse params*/
    to_vport = cJSON_GetObjectItem(root, "ifname")->valuestring;
    cidr = cJSON_GetObjectItem(root, "cidr");
    nexthop = cJSON_GetObjectItem(root, "nexthop");
    if (!cidr || (to_vport == NULL && nexthop == NULL)) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }
    if (nexthop) {
        get_ip_and_mask(nexthop->valuestring, &nexthop_nl, &prefixlen);
    }
    get_ip_and_mask(cidr->valuestring, &prefix, &prefixlen);
    if (prefix == 0 || prefixlen == 0) {
        BVR_ERROR("prefix = %d, prefixlen = %d", prefix, prefixlen);
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    ret = pal_route_add_to_net(net, prefix, prefixlen, nexthop_nl, to_vport);
    if (ret) {
        if (ret == -EROUTE_IF_NOT_EXIST) {
            ret = -NN_ERTIFNEXIST;
            goto ret_state;
        } else if (ret == -EROUTE_WRONG_PREFIX) {
            ret = -NN_ERINVALPREFIX;
            goto ret_state;
        } else if (ret == -EROUTE_WRONG_NETMASK) {
            ret = -NN_ERINVALMASK;
            goto ret_state;
        } else if (ret == -EROUTE_MISS_DST) {
            ret = -NN_ERNODST;
            goto ret_state;
        } else if (ret == -EROUTE_CIDR_EXIST) {
            ret = -NN_ERCIDREXIST;
            goto ret_state;
        } else if (ret == -EROUTE_GW_UNREACHABLE) {
            ret = -NN_ERGWUNREACHABLE;
            goto ret_state;
        } else if (ret == -EROUTE_GW_UNABLE_PHYPORT) {
            ret = -NN_ERGWONPHYPORT;
            goto ret_state;
        } else if (ret == -EROUTE_ERROR) {
            ret = -NN_EEXCERR;
            goto ret_state;
        } else {
            BVR_ERROR("unknown error code when add external interface return the orignal code %d", ret);
            ret = -NN_EEXCERR;
            goto ret_state;
        }
    }
ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;
}



/**
 * Delete a route item from a vrouter
 * @param  json params - "bvrouter" "network/prefix"
 * @return    0 on success, otherwise status error
 */
static u32 bvr_cmd_del_route(struct conn_ev *ev) {
    BVR_DEBUG("nn_cmd_del_route called\n");
    uint32_t prefix = 0;
    uint32_t prefixlen = 0;
    int ret = 0;
    struct net *net = NULL;
    char *cidr = NULL;
    cJSON *root = NULL;

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }

    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);
    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }

    /*parse params*/
    cidr = cJSON_GetObjectItem(root, "cidr")->valuestring;
    if (!cidr) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }
    get_ip_and_mask(cJSON_GetObjectItem(root, "cidr")->valuestring, &prefix, &prefixlen);
    if (prefix == 0 || prefixlen == 0) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    ret = pal_route_del_from_net(net, prefix, prefixlen);
    if (ret) {
        if (ret == -EROUTE_WRONG_NETMASK) {
            ret = -NN_ERINVALMASK;
            goto ret_state;
        } else if (ret == -EROUTE_CIDR_NOT_EXIST) {
            ret = -NN_ERCIDRNEXIST;
            goto ret_state;
        } else {
            BVR_ERROR("unknown error code when add external interface return the orignal code %d", ret);
            ret = -NN_EEXCERR;
            goto ret_state;
        }
    }

ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;
}


/*
 * @brief add a floating ip to a external interface
 * @json param:"bvrouter" "interface" "ip"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_add_floating_ip(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_add_floating_ip called\n");
    struct net *net = NULL;
    struct cJSON *root = NULL;
    char *ifname = NULL;
    u32 ip = 0;
    int ret = 0;

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }
    /*parse json cmd to find the bvrouter*/
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    /*parse params*/
    ifname = cJSON_GetObjectItem(root, "ifname")->valuestring;

    ret = inet_aton(cJSON_GetObjectItem(root, "ip")->valuestring, (struct in_addr *)&ip);
    if (!ret) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }
    /* if floating ip has been add, delete it first*/
    ret = floating_ip_add_ctl(ip, ifname);

    if (ret) {
        if (ret == -ENXIO 

|| ret == -ESRCH) {
            ret = -NN_EIFNOTEXIST;
            goto ret_state;
        }else if (ret == -EEXIST) {
            ret = -NN_EIPEXIST;
            goto ret_state;
        }else if (ret == -ENOSPC) {
            ret = -NN_ENOSPACE;
            goto ret_state;
        } else {
            BVR_WARNING("unknown error code when add floating ip return the orignal code %d", ret);
            goto ret_state;
        }
    }

ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}


/*
 * @brief delete a floating ip from a external interface
 * @json param:"bvrouter" "interface" "interface" "ip"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_del_floating_ip(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_del_floating_ip called\n");
    struct net *net = NULL;
    struct cJSON *root = NULL;

    u32 ip = 0;
    int ret = 0;

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }
    /*parse json cmd to find the bvrouter*/
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    /*parse params*/
    /*del floating ip don't need a vport????*/
    //ifname = cJSON_GetObjectItem(root, 'ifname')
    ret = inet_aton(cJSON_GetObjectItem(root, "ip")->valuestring,
        (struct in_addr *)&ip);
    if (!ret) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    ret = floating_ip_delete_ctl(ip);
    if (ret) {
        if (ret == -ENOENT || ret == -EIO) {
            ret = -NN_EIPNOTEXIST;
            goto ret_state;
        }else {
            BVR_WARNING("unknown error code when delete floating ip return the orignal code %d", ret);
            goto ret_state;
        }
    }

ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;
}



static int parse_fdb_entry(cJSON *root, struct fdb_entry *entry)
{
    int ret = 0;
    char *mac = cJSON_GetObjectItem(root, "mac")->valuestring;
    ret = get_mac_addr(mac, (unsigned char *)entry->mac);
    if (ret) {
        return -1;
    }
    /*return 0 means input string format error*/
    ret = inet_aton(cJSON_GetObjectItem(root, "remote_ip")->valuestring,
        (struct in_addr *)&entry->remote_ip);
    if (!ret) {
        return -1;
    }

    entry->remote_port = htons(cJSON_GetObjectItem(root, "remote_port")->valueint);
    return 0;
}


/*
 * @brief add a fdb entry to a bvrouter
 * @json param:"bvrouter" "interface"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_add_fdb_entry(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_add_fdb called\n");
//    struct net *net = NULL;
    struct cJSON *root = NULL;
    struct fdb_entry entry;
    int vni = -1;
    int ret = 0;

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }

    /*remove the bvrouter param,because this command called in l2-agent*/
    #if 0
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    #endif
    /*parse params*/
    vni = cJSON_GetObjectItem(root, "vni")->valueint;

    ret = parse_fdb_entry(root, &entry);

    if (ret) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }
    BVR_DEBUG("add fdb entry mac "MACPRINT_FMT, MACPRINT(entry.mac));
    ret = vxlan_fdb_add_ctl(vni, &entry);
    if (ret) {
        if (ret == -ENXIO || ret == -ESRCH) {
            ret = -NN_EIFNOTEXIST;
            goto ret_state;
        }else if (ret == -EEXIST) {
            ret = -NN_EFDBEXIST;
            goto ret_state;
        }else if (ret == -ENOSPC) {
            ret = -NN_ENOSPACE;
            goto ret_state;
        }else if (ret == -ENOMEM) {
            ret = -NN_ENOMEM;
            goto ret_state;
        }else {
            BVR_WARNING("unknown error code when add fdb entry return the orignal code %d", ret);
            goto ret_state;
        }
    }


ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}



/*
 * @brief delete a fdb entry from a bvrouter
 * @json param:"bvrouter" "interface" "mac"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_del_fdb_entry(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_add_internal_interface called\n");
  //  struct net *net = NULL;
    struct cJSON *root = NULL;
    int vni = -1;
    unsigned char mac[6];
    int ret = 0;

    root = cJSON_Parse(ev->buf);
    if (!root) {
        ret = -NN_ENOMEM;
        goto ret_state;
    }
    /*remove the bvrouter param,because this command called in l2-agent*/
    #if 0
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);

    if (!net) {
        ret = -NN_ENSNOTEXIST;
        goto ret_state;
    }
    #endif
    /*parse params*/
    vni = cJSON_GetObjectItem(root, "vni")->valueint;

    ret = get_mac_addr(cJSON_GetObjectItem(root, "mac")->valuestring, mac);
    if (ret) {
        ret = -NN_EPARSECMD;
        goto ret_state;
    }

    ret = vxlan_fdb_delete_ctl(vni, (uint8_t *)mac);
    if (ret) {
        if (ret == -ENXIO || ret == -ESRCH) {
            ret = -NN_EIFNOTEXIST;
            goto ret_state;
        }else if (ret == -ENOENT) {
            ret = -NN_EFDBNOTEXIST;
            goto ret_state;
        }else {
            BVR_WARNING("unknown error code when delete fdb entry return the orignal code %d", ret);
            goto ret_state;
        }
    }

ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;
}


/*TODO*/
static struct cJSON *pack_fdb_entries(struct vxlan_dev *vport)
{
    u32 i = 0;
    struct cJSON *root = NULL, *sub = NULL;
    struct vxlan_fdb *fdb = NULL;
    struct pal_hlist_node *pos = NULL;

    root = cJSON_CreateArray();
    if (root == NULL) {
        return NULL;
    }
    for (i = 0; i < FDB_HASH_SIZE; i++)
    {
        pal_hlist_for_each_entry(fdb, pos, vxlan_fdb_head_index(vport, i), hlist)
        {
            cJSON_AddItemToArray(root, sub = cJSON_CreateObject());
            cJSON_AddStringToObject(sub, "mac", trans_mac(fdb->eth_addr));
            cJSON_AddStringToObject(sub, "ip", trans_ip(fdb->remote.remote_ip, 0));
            cJSON_AddNumberToObject(sub, "port", ntohs(fdb->remote.remote_port));
            cJSON_AddNumberToObject(sub, "vni", fdb->remote.remote_vni);
        }
    }
    return root;
}

/*
 * @brief show all fdb entries of a bvrouter
 * @json param:"bvrouter" "interface"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_show_fdb_entries(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_show_fdb_table_entries called\n");
//    struct net *net = NULL;
    char *out = NULL;

    cJSON *root = NULL;
    /*parse the bvrouter name, if bvrouter not exist return error*/

    root = cJSON_Parse(ev->buf);
    if (!root) {
         ev->msg_prefix.msg_len = 0;
         ev->msg_prefix.ret_state = -NN_ENOMEM;
          goto ret_state;
     }
    /*remove the bvrouter param,because this command called in l2-agent*/
    #if 0
    net = net_get(cJSON_GetObjectItem(root, "bvrouter")->valuestring);
    if (!net) {
        BVR_WARNING("no bvrouter found\n");
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENSNOTEXIST;
        cJSON_Delete(root);
        goto ret_state;
    }
    #endif
    /*get interface name*/
    int vni = cJSON_GetObjectItem(root, "vni")->valueint;
    struct vxlan_dev *vxlan_dev = get_vxlan_dev(vni);
    if (!vxlan_dev) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EIFNOTEXIST;
        cJSON_Delete(root);
        goto ret_state;
    }
    cJSON_Delete(root);

    /*pack interface information in cjson*/
    root = pack_fdb_entries(vxlan_dev);
    if (root == NULL) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        goto ret_state;
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }

ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;
}

/*
 * @brief list all interfaces
 * @json param:"function:list"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_list_all_ifs(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_list_all ifs called\n");
    /*list cmd need no param, but to trigger the handler,agent must
      send a param {function:show}*/
    u32 i;
    struct vport *vport = NULL;
    struct pal_hlist_node *node = NULL;
    char *out = NULL;
    cJSON *root = NULL, *if_name = NULL, *func = NULL;

    /*test if the function name is right*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        cJSON_Delete(root);
        goto ret_state;
    }

    func = cJSON_GetObjectItem(root, "function");
    if (!func) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;
        cJSON_Delete(root);
        goto ret_state;
    }

    if (strcmp(func->valuestring , "show")) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;

        cJSON_Delete(root);
        goto ret_state;
    }
    cJSON_Delete(root);

    /*create json string to return the result*/
    root = cJSON_CreateArray();
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;

        goto ret_state;
    }
    for (i = 0; i < VPORT_HASH_SIZE; i++) {
        pal_hlist_for_each_entry(vport, node, &vport_nets.vport_list[i], hlist)
        {
            /*return format interface_name:xxxx*/
            cJSON_AddItemToArray(root, if_name = cJSON_CreateObject());
            cJSON_AddStringToObject(if_name, "interface_name", vport->vport_name);
            cJSON_AddStringToObject(if_name, "uuid", vport->uuid);
            cJSON_AddStringToObject(if_name, "type", vport->vport_type == VXLAN_VPORT ?
                                    "internal" : "external");

        }
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);

    /*tell agent how many bytes to receive*/
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }
    else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }


ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;

}

/*
 * @brief list all interfaces
 * @json param:"function:list"
 * @return 0 on success,-1 return status error
 */

static u32 bvr_cmd_show_ifs_stat(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_show_ifs_stat called\n");
    /*list cmd need no param, but to trigger the handler,agent must
    send a param {function:show}*/
    char *out = NULL;
    char tmp[64];
    struct rte_eth_stats stats;
    cJSON *root = NULL, *if_stat = NULL, *func = NULL;

    /*test if the function name is right*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        cJSON_Delete(root);
        goto ret_state;
    }

    func = cJSON_GetObjectItem(root, "function");
    if (!func) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;
        cJSON_Delete(root);
        goto ret_state;
    }

    if (strcmp(func->valuestring , "show")) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;

        cJSON_Delete(root);
        goto ret_state;
    }
    cJSON_Delete(root);

    /*create json string to return the result*/
    root = cJSON_CreateArray();
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;

        goto ret_state;
    }

    bound_interface_t *bi = NULL;
    list_for_each_entry(bi, &g_bvrouter_conf_info.bound_interfaces, l)
    {
        if (bi->port_id >= rte_eth_dev_count())
            break;
        cJSON_AddItemToArray(root, if_stat = cJSON_CreateObject());
        rte_eth_stats_get(bi->port_id, &stats);
        cJSON_AddNumberToObject(if_stat, "port_id", bi->port_id);
        sprintf(tmp, "%lu", stats.ipackets);
        cJSON_AddStringToObject(if_stat, "rxpkts", tmp);
        sprintf(tmp, "%lu", stats.ibytes);
        cJSON_AddStringToObject(if_stat, "rxbytes", tmp);
        sprintf(tmp, "%lu", stats.imissed);
        cJSON_AddStringToObject(if_stat, "rxmissed", tmp);
        sprintf(tmp, "%lu", stats.ibadcrc);
        cJSON_AddStringToObject(if_stat, "rxbadcrc", tmp);
        sprintf(tmp, "%lu", stats.ibadlen);
        cJSON_AddStringToObject(if_stat, "rxbadlen", tmp);
        sprintf(tmp, "%lu", stats.ierrors);
        cJSON_AddStringToObject(if_stat, "rxerrors", tmp);
        sprintf(tmp, "%lu", stats.opackets);
        cJSON_AddStringToObject(if_stat, "txpkts", tmp);
        sprintf(tmp, "%lu", stats.obytes);
        cJSON_AddStringToObject(if_stat, "txbytes", tmp);
        sprintf(tmp, "%lu", stats.oerrors);
        cJSON_AddStringToObject(if_stat, "txerrors", tmp);
    }
    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);

    /*tell agent how many bytes to receive*/
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }
    else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }

ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;
}

/*
 * @brief show all interface link status (including slave interface)
 * @json param:"function:show"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_show_ifs_link_status(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_show_ifs_link_status called\n");
    /*list cmd need no param, but to trigger the handler,agent must
    send a param {function:show}*/
    char *out = NULL;
    cJSON *root = NULL, *func = NULL, *link_stat = NULL;
    int i = 0;

    /*test if the function name is right*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        cJSON_Delete(root);
        goto ret_state;
    }


    func = cJSON_GetObjectItem(root, "function");
    if (!func) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;
        cJSON_Delete(root);
        goto ret_state;
    }

    if (strcmp(func->valuestring , "show")) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;

        cJSON_Delete(root);
        goto ret_state;
    }

    cJSON_Delete(root);

    /*create json string to return the result*/
    root = cJSON_CreateArray();
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;

        goto ret_state;
    }

    for (i = 0; i < rte_eth_dev_count(); i++)
    {
        struct rte_eth_link eth_link;
        memset(&eth_link, 0, sizeof(eth_link));
        rte_eth_link_get_nowait(i, &eth_link);
        cJSON_AddItemToArray(root, link_stat = cJSON_CreateObject());
        cJSON_AddNumberToObject(link_stat, "port_id", i);
        cJSON_AddNumberToObject(link_stat, "link_status", eth_link.link_status);
        cJSON_AddNumberToObject(link_stat, "link_speed", eth_link.link_speed);
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);

    /*tell agent how many bytes to receive*/
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }

ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;
}

/*
 * @brief set one interface link status (including slave interface)
 * @json param:"port_id , link status:0 for down, 1 for up"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_set_ifs_link_status(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_set_ifs_link_status called\n");

    int port_id = 0, link_status = 0, ret = 0;

    cJSON *root = NULL;

    /*test if the function name is right*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        cJSON_Delete(root);
        goto ret_state;
    }
    port_id = cJSON_GetObjectItem(root, "portid")->valueint;
    link_status = cJSON_GetObjectItem(root, "status")->valueint;

    if (port_id < 0 || port_id >= rte_eth_dev_count() || link_status < 0 ||
        link_status > 1)
    {
        ret = -NN_EOUTRANGE;
        goto ret_state;
    }

    if (link_status) {

        ret = rte_eth_dev_set_link_up(port_id);
    }else {

        ret = rte_eth_dev_set_link_down(port_id);
    }

    if (ret) {
        ret = -NN_EEXCERR;
    }

ret_state:
    /*return the exe status*/
    cJSON_Delete(root);
    ev->msg_prefix.msg_len = 0;
    ev->msg_prefix.ret_state = ret;
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        return -1;
    }
    return 0;

}



/*
 * @brief show cpu usage of pal
 * @json param:"function:list"
 * @return 0 on success,-1 return status error
 */
static u32 bvr_cmd_show_cpu_usage(struct conn_ev *ev)
{
    BVR_DEBUG("nn_cmd_show_cpu_usage called\n");
    /*list cmd need no param, but to trigger the handler,agent must
    send a param {function:show}*/
    char *out = NULL;
    cJSON *root = NULL, *cpu = NULL, *func = NULL;

    /*test if the function name is right*/
    root = cJSON_Parse(ev->buf);
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
        cJSON_Delete(root);
        goto ret_state;
    }

    func = cJSON_GetObjectItem(root, "function");
    if (!func) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;
        cJSON_Delete(root);
        goto ret_state;
    }

    if (strcmp(func->valuestring , "show")) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_EPARSECMD;

        cJSON_Delete(root);
        goto ret_state;
    }
    cJSON_Delete(root);

    /*create json string to return the result*/
    root = cJSON_CreateArray();
    if (!root) {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;

        goto ret_state;
    }
    u32 i = 0;
    struct pal_cpu_stats cpu_stats;
    memset(&cpu_stats, 0, sizeof(cpu_stats));

    pal_get_cpu_usage(&cpu_stats);

    PAL_FOR_EACH_RECEIVER(i) {
        cJSON_AddItemToArray(root, cpu = cJSON_CreateObject());
        cJSON_AddNumberToObject(cpu, "datapath_core", cpu_stats.cpu_usage[i]);
    }

    out = cJSON_Print(root);
    cJSON_Delete(root);
    BVR_DEBUG("%s\n",out);

    /*tell agent how many bytes to receive*/
    if (NULL != out) {
        ev->msg_prefix.msg_len = strlen(out);
        ev->msg_prefix.ret_state = 0;
    }
    else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = -NN_ENOMEM;
    }

ret_state:
    if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0)
    {
        BVR_ERROR("send ret message failed\n");
        goto error;
    }
    if (ev->msg_prefix.msg_len) {
        if (send_bytes(ev->ev.fd, (u8 *)out, ev->msg_prefix.msg_len) < 0)
        {
            BVR_ERROR("send ret message failed\n");
            goto error;
        }
        free(out);
    }
    return 0;
error:
    if (ev->msg_prefix.msg_len) {
        free(out);
    }
    return -1;
}



nn_msg_handler_info_t g_msg_handler_tbl_pr[NN_CMD_ID_MAX_CMD] =
{
    [NN_CMD_ID_TEST]                = {bvr_cmd_test_handler,"test handler"},
    [NN_CMD_ID_ADD_NAMESPACE]       = {bvr_cmd_create_namespace_handler, "create namespace handler"},
    [NN_CMD_ID_DEL_NAMESPACE]       = {bvr_cmd_del_namespace_handler, "del namespace handler"},
    [NN_CMD_ID_LIST_NAMESPACE]      = {bvr_cmd_list_namespace_handler, "list all namespace handler"},
    [NN_CMD_ID_SHOW_NAMESPACE]      = {bvr_cmd_show_namespace_handler, "show namespace handler"},
    [NN_CMD_ID_ADD_NF_RULE]         = {bvr_cmd_add_netfilter_rule, "add netfilter rule"},
    [NN_CMD_ID_DEL_NF_RULE]         = {bvr_cmd_del_netfilter_rule, "del netfilter rule"},
    [NN_CMD_ID_SHOW_NF_RULE]        = {bvr_cmd_show_netfilter_rule, "show netfilter rule"},
    [NN_CMD_ID_FLUSH_NF_RULE]       = {bvr_cmd_flush_netfilter_rule, "flush netfilter rules in bvrouter table"},

    [NN_CMD_ID_ADD_ARP_ENTRY]       = {bvr_cmd_add_arp_table_entry, "add arp entry"},
    [NN_CMD_ID_DEL_ARP_ENTRY]       = {bvr_cmd_del_arp_table_entry, "del arp entry"},
    [NN_CMD_ID_SHOW_ARP_ENTRIES]    = {bvr_cmd_show_arp_table_entries, "show arp entries"},

    [NN_CMD_ID_ADD_INT_IF]          = {bvr_cmd_add_internal_interface, "add a internal interface to router"},
    [NN_CMD_ID_ADD_EXT_IF]          = {bvr_cmd_add_external_interface, "add a external interface to router"},
    [NN_CMD_ID_DEL_IF]              = {bvr_cmd_del_interface, "delete a inter"},
    [NN_CMD_ID_SHOW_IFS]            = {bvr_cmd_show_interfaces, "show interfaces of router"},
    [NN_CMD_ID_ADD_IP]              = {bvr_cmd_add_floating_ip, "add floating ip on interface"},
    [NN_CMD_ID_DEL_IP]              = {bvr_cmd_del_floating_ip, "delete floating ip on interface"},
    [NN_CMD_ID_ADD_FDB_ENTRY]       = {bvr_cmd_add_fdb_entry, "add fdb entry on vxlan interface"},
    [NN_CMD_ID_DEL_FDB_ENTRY]       = {bvr_cmd_del_fdb_entry, "delete fdb entry on vxlan interface"},
    [NN_CMD_ID_SHOW_FDB_ENTRIES]    = {bvr_cmd_show_fdb_entries, "show fdb entries of a vxlan interface"},
    [NN_CMD_ID_LIST_ALL_IFS]        = {bvr_cmd_list_all_ifs, "show all interface name(used by l2 agent)"},
    [NN_CMD_ID_SHOW_IFS_STAT]       = {bvr_cmd_show_ifs_stat, "show phy interfaces status"},
    [NN_CMD_ID_SHOW_CPU_USAGE]      = {bvr_cmd_show_cpu_usage, "show pal cpu usage"},
    [NN_CMD_ID_SHOW_ROUTE_TABLE]    = {bvr_cmd_show_route_table, "show bvrouter's route table"},
    [NN_CMD_ID_GET_PORT_POLLING]    = {bvr_cmd_get_port_update_handler, "get port polling status"},
    [NN_CMD_ID_SET_PORT_STAT_INT]   = {bvr_cmd_set_portstatus_interval_handler, "set port polling status interval"},
    [NN_CMD_ID_SHOW_PORT_LINK_STATUS]  = {bvr_cmd_show_ifs_link_status, "show port link up or down"},
    [NN_CMD_ID_SET_PORT_LINK_STATUS]   = {bvr_cmd_set_ifs_link_status, "set port link up or down"},
    [NN_CMD_ID_ADD_ROUTE]           = {bvr_cmd_add_route, "add route item"},
    [NN_CMD_ID_DEL_ROUTE]           = {bvr_cmd_del_route, "delete route item"},
};



/* create a tcp listen socket on specified port, bound to INADDR_ANY
 * returns the fd created, or -1 on failure */
static int tcp_server_create(u16 port)
{
    int fd;
    int reuseaddr = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        BVR_PANIC("Create listen socket failed: %s\n", strerror(errno));
    }

    if (fcntl(fd, F_SETFL, fcntl(fd,F_GETFL) | O_NONBLOCK) < 0) {
        BVR_PANIC("Set listen socket to nonblock failed: %s\n", strerror(errno));
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) < 0) {
        BVR_PANIC("Set listen socket reuse addr failed: %s\n", strerror(errno));
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        BVR_PANIC("Bind listen socket failed: %s\n", strerror(errno));
    }

    if (listen(fd, 1024) < 0) {
        BVR_PANIC("Listen socket failed: %s\n", strerror(errno));
    }
    BVR_DEBUG("listen on 0.0.0.0:port %d\n",port);
    return fd;

}



/*
 * @brief Read n bytes from a conn_ev. if error occurs or peer closed the connection
 *      before all data are read, the connection is closed.
 */
static inline void recv_until(struct conn_ev *ev, void *buf, u32 len, int needfree,
                int (* cb)(struct conn_ev *ev))
{
    ev->buf = buf;
    ev->toread = len;
    ev->rcvd = 0;
    ev->cb = cb;
    ev->needfree = needfree;
}


static void bvr_ctl_do_recv(struct ev_loop *loop, ev_io *ev, int events)
{
    int rcvd;
    u32 tot_rcvd;
    u32 left;
    struct conn_ev *conn_ev = (struct conn_ev *)ev;

    if (events & EV_ERROR) {
        goto recv_error;
    }

    if ((events & EV_READ) == 0)
        return;

    tot_rcvd = conn_ev->rcvd;
    left = conn_ev->toread;
    while (left > 0) {
        rcvd = recv(ev->fd, (char *)conn_ev->buf + tot_rcvd, left, 0);
        if (rcvd < 0) {
            if(errno == EAGAIN) {
                break;
            } else {
                BVR_ERROR("recv error: %s\n", strerror(errno));
                goto recv_error;
            }
        } else if (rcvd > 0) {
            left -= rcvd;
            tot_rcvd += rcvd;
        } else {
            BVR_ERROR("Connection closed by client.\n");
            goto recv_error;
        }
    }

    if (left == 0) {
        switch(conn_ev->cb(conn_ev)) {
            case NN_EVCB_RET_CLOSE:
                goto recv_error;
            case NN_EVCB_RET_RECV:
                    break;
            /* TODO: currently, this return value is not used.*/
            /* case BGW_EVCB_RET_SEND:
                ev_io_stop(loop, ev);
                ev_io_set(ev, ev->fd, EV_WRITE);
                ev_io_start(loop, ev);
                break; */
            default:
                BVR_ERROR("cb returned a invalid value\n");
                goto recv_error;
        }
    } else {
        conn_ev->toread = left;
        conn_ev->rcvd = tot_rcvd;
    }

    return;

recv_error:
    ev_io_stop(loop, ev);

    close(ev->fd);
    if (conn_ev->needfree) {
        free(conn_ev->buf);
    }

    conn_ev->listen_ev->n_conn--;
    BVR_DEBUG("close connection, now %u connections\n", conn_ev->listen_ev->n_conn);
    free(ev);


    return;
}



/*
 * event callback. handles the entire message body, including all the commands
 */
static int handle_msg(struct conn_ev *ev)
{
    int cmd_id;

    cmd_id = ev->msg_prefix.cmd_id;

    if (g_msg_handler_tbl_pr[cmd_id].handler) {
        g_msg_handler_tbl_pr[cmd_id].handler(ev);
    } else {
        ev->msg_prefix.msg_len = 0;
        ev->msg_prefix.ret_state = NN_CMD_ID_NO_CMD;
        BVR_WARNING("no cmd find,cmd id %d\n",ev->msg_prefix.cmd_id);
        if (send_bytes(ev->ev.fd, (u8 *)&ev->msg_prefix, sizeof(ev->msg_prefix)) < 0) {
            BVR_ERROR("send ret message failed\n");
        }
    }
    return NN_EVCB_RET_CLOSE;

}


/*
 * event callback. handles message prefix
 */
static int handle_prefix(struct conn_ev *ev)
{
    nn_msg_prefix_t *prefix = &ev->msg_prefix;

    if (prefix->magic_num != NN_MSG_MAGIC_NUM) {
        BVR_WARNING("Messsage magic number incorrect, %d\n",prefix->magic_num );
        return NN_EVCB_RET_CLOSE;
    }

    if (prefix->msg_len == 0 || prefix->msg_len > NN_CTL_MAX_MSG_LENGTH) {
        BVR_WARNING("Message len too small or too large: %u\n", prefix->msg_len);
        return NN_EVCB_RET_CLOSE;
    }

    if (prefix->version != NN_CTL_VERSION) {
        BVR_WARNING("Message version unrecognised: %u\n", prefix->version);
        return NN_EVCB_RET_CLOSE;
    }

    if (prefix->cmd_id == NN_CMD_ID_NO_CMD || prefix->cmd_id >= NN_CMD_ID_MAX_CMD) {
        BVR_WARNING("Message cmd id unrecognised: %u\n", prefix->cmd_id);
        return NN_EVCB_RET_CLOSE;
    }


    ev->buf = malloc(prefix->msg_len);
    if(ev->buf == NULL) {
        BVR_ERROR("Malloc buf for receiving message failed\n");
        return NN_EVCB_RET_CLOSE;
    }

    recv_until(ev, ev->buf, prefix->msg_len, 1, handle_msg);

    return NN_EVCB_RET_RECV;
}



/*accept a connection from listen fd, put the conn fd into ev_loop
 and register the recieve function*/
static void bvr_ctl_do_accept(struct ev_loop *loop, ev_io *ev, int events)
{
    struct conn_ev *new_ev;
    struct listen_ev *listen_ev = (struct listen_ev *)ev;
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(addr);
    int conn;
    struct timeval rcvto = {5, 0};
    struct timeval sndto = {5, 0};

    if (events & EV_ERROR) {
        BVR_ERROR("listen fd error\n");
        /* serious problem, sleep 1 second to see whether we can recover */
        sleep(1);
        return;
    }
    /*not a read event, ignore it*/
    if ((events & EV_READ) == 0)
        return;

    conn = accept(ev->fd, (struct sockaddr *)&addr, &addr_size);
    if (conn < 0) {
        BVR_ERROR("accept failed\n");
        return;
    }

    if (set_nonblock(conn) < 0) {
        BVR_ERROR("set nonblock failed\n");
        close(conn);
        return;
    }

    if (setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, (char *)&rcvto,
        sizeof(rcvto)) < 0) {
        BVR_ERROR("set receive timeout failed\n");
        close(conn);
        return;
    }

    if (setsockopt(conn, SOL_SOCKET, SO_SNDTIMEO, (char *)&sndto,
        sizeof(sndto)) < 0) {
        BVR_ERROR("set send timeout failed\n");
        close(conn);
        return;
    }

    new_ev = (struct conn_ev *)malloc(sizeof(*new_ev));
    if (new_ev == NULL) {
        close(conn);
        return;
    }
    new_ev->listen_ev = listen_ev;
    recv_until(new_ev, &new_ev->msg_prefix, sizeof(new_ev->msg_prefix), 0, handle_prefix);
    ev_io_init(&new_ev->ev, bvr_ctl_do_recv, conn, EV_READ);
    ev_io_start(loop, &new_ev->ev);

    listen_ev->n_conn++;
    BVR_DEBUG("new connection, now %u connections\n", listen_ev->n_conn);
    /* TODO: if we stop it here, we must restart it when a connection is closed */
    /* if (listen_ev->n_conn == CTL_MAX_CONNECTION) {
        ev_io_stop(loop, ev);
    } */

    return;
}



int bvr_controlplane_process(void)
{
    int listenfd;
    struct ev_loop *loop;
    struct listen_ev listen_ev;

    listenfd =  tcp_server_create(NN_CTL_LISTEN_PORT);
    if (listenfd < 0) {
        return -1;
    }
    loop = ev_loop_new(EVFLAG_AUTO);
    if (loop == NULL) {
        return -1;
    }

    listen_ev.n_conn = 0;
    ev_io_init(&listen_ev.ev, bvr_ctl_do_accept, listenfd, EV_READ);
    ev_io_start(loop, &listen_ev.ev);
    while (1) {
        ev_run(loop, 0);
        BVR_WARNING("ev_run returned!\n");
        sleep(1);
    }
    return 0;
}

//#define TEST
#if 0
extern struct pernet_operation nf_net_ops;
extern struct pernet_operation arp_net_ops;

int main()
{
    int i;
    for (i = 0; i < NAMESPACE_TABLE_SIZE; i++) {
        INIT_HLIST_HEAD(&namespace_hash_table[i]);
    }

    register_pernet_operations(&nf_net_ops);
    register_pernet_operations(&arp_net_ops);
    bvr_controlplane_process();
    return 0;

}

#endif

