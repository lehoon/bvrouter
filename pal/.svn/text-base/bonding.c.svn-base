/**
 **********************************************************************
 *
 * Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
 * @file			$HeadURL$
 * @brief		bonding interface init methods definition
 * @author		jorenwu(wujiaoren@baidu.com)
 * @date			$Date$
 * @version		$Revision$ by $Author$
 ***********************************************************************
 */

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_eth_bond.h>

#include "bonding.h"
#include "pal_utils.h"

/**
 * @brief creat a bonding interface
 * @param bi the configuration of the bonding interface
 * @return -1=failed, >0 success
 */
int
create_bonded_device (char *name, uint8_t mode, uint8_t socket_id)
{
  int bonded_port_id;

  bonded_port_id = rte_eth_bond_create (name, mode, socket_id);
  if (bonded_port_id < 0)
    {
      PAL_PANIC("create_bonded_device: cannot creat bond interface");
      return -1;
    }

  PAL_LOG("creat a new bonded device %s : %d.\n", name, bonded_port_id);

  return bonded_port_id;
}

/**
 * @brief add the slave ports into this bonding eth device
 * @param port_id the id of this bonding eth device
 * @param slaves the port_id of slave ports
 * @param slaves_nb the number of slave ports
 * @return -1=failed, 0=success
 */
int
add_slaves_to_bonded_device (int port_id, uint8_t *slaves, uint8_t slaves_nb)
{
  int idx;

  for (idx = 0; idx < slaves_nb; idx++)
    {
      if (rte_eth_bond_slave_add (port_id, slaves[idx]) != 0)
	{
	  PAL_LOG(
	      "add_slave_to_bonded_device: cannot add port-%d " "into bondinterface-%d",
	      port_id, slaves[idx]);
	  return -1;
	}
    }

  return 0;
}

/**
 * @brief remove the slave port from this bonding eth device
 * @param port_id the id of this bonding eth device
 * @param slave_portid the port_id of the slave port
 * @return -1=failed, 0=success
 */
static int
remove_slave_from_bonded_device (int port_id, uint8_t slave_portid)
{
  if (rte_eth_bond_slave_remove (port_id, slave_portid) != 0)
    {
      PAL_LOG(
	  "remove_slave_from_bonded_device: cannot remove port-%d " "into bondinterface-%d",
	  port_id, slave_portid);
      return -1;
    }

  return 0;
}

/**
 * @brief remove the slave ports from this bonding eth device
 * @param port_id the id of this bonding eth device
 * @param slaves the port_id of slave ports
 * @param slaves_nb the number of slave ports
 * @return -1=failed, 0=success
 */
int
remove_slaves_from_bonded_device (int port_id, uint8_t *slaves,
				  uint8_t slaves_nb)
{
  int idx;

  for (idx = 1; idx < slaves_nb; idx++)
    {
      if (remove_slave_from_bonded_device (port_id, slaves[idx]) < 0)
	{
	  return -1;
	}
    }

  return 0;
}
