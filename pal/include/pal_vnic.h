#ifndef _PAL_VNIC_H_
#define _PAL_VNIC_H_
#include "pal_skb.h"

/*
 * @brief Dump a packet by send it to dump vnic. The packet is copied in
 *        this function.
 * @prarm skb Packet to be dumped
 * @return 0 on success, -1 otherwise. in either case, skb is not freed
 */
int pal_dump_pkt(const struct sk_buff *skb, uint16_t size);


#endif
