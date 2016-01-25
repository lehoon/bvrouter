#ifndef _PALI_VNIC_H_
#define _PALI_VNIC_H_
#include "utils.h"
#include "pal_vnic.h"

/*
 * @brief main function of vnic thread
 */
int vnic_loop(__unused void *data);

/*
 * @brief test whether vnic function is enabled. When enabled, 
 *        applications can create vnic on physical ports.
 * @return 1 if enabled, 0 otherwise
 */
int vnic_enabled(void);

void pal_enable_vnic(int tid);

/*
 * @brief send a packet to virtual nic
 * @return 0 on success, -1 on failure
 */
int pal_send_to_vnic(unsigned vnic_id, struct sk_buff *skb);

/*
 * @brief bring up a virtual network interface
 */
void pal_bring_up_nic(const char *name);

/*
 * @brief Create a vnic interface for a specified physical port
 * @param port_id Id of the physical port
 * @param core_id Id of core on which kni kernel thread runs. Note this is
 *        not the VNIC thread, which is a user-space thread
 */
int pal_vnic_create(int port_id, unsigned core_id);

/*
 * @brief Create a vnic to dump packets
 */
int pal_dump_vnic_create(void);


#endif
