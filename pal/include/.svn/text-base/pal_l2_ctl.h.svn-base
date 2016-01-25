#ifndef _PAL_L2_CTL_H
#define _PAL_L2_CTL_H

#include <string.h>
#include <stdint.h>

#include "pal_phy_vport.h"
#include "pal_vxlan.h"
#include "pal_route.h"

struct int_vport_entry{
	char *vport_name;
    char *uuid;
	uint8_t int_gw_mac[6];
	__be32 int_gw_ip;
	uint32_t prefix_len;
	uint32_t vni;
};

struct phy_vport_entry{
    char *vport_name;	
    char *uuid;
	uint8_t ext_gw_mac[6];
	__be32 ext_gw_ip;	
	uint32_t prefix_len;
};

struct fdb_entry{
	uint8_t mac[6]; 
	__be32 remote_ip;
	__be16 remote_port;
};

extern int int_vport_add_ctl(struct int_vport_entry *entry,void *private);
extern int phy_vport_add_ctl(struct phy_vport_entry * entry,void *private);
extern int vport_delete_ctl(char *vport_name);
extern int floating_ip_add_ctl(__be32 floating_ip, 
				  char *vport_name);
extern int floating_ip_delete_ctl(__be32 floating_ip);
extern int floating_ip_show_ctl(char *vport_name);
extern int vxlan_fdb_add_ctl(uint32_t vni,struct fdb_entry *entry);
extern int vxlan_fdb_delete_ctl(uint32_t vni,uint8_t *mac);
extern int vxlan_fdb_show_ctl(uint32_t vni);
extern void nd_delete_vport(void *nd);
extern struct vxlan_dev * get_vxlan_dev(uint32_t vni);
extern int vxlan_arp_add_ctl(uint32_t vni,struct vxlan_arp_entry *entry);
extern int vxlan_arp_delete_ctl(uint32_t vni,struct vxlan_arp_entry *entry);
extern int route_entry_table_show_ctl(struct route_table *rt ,struct route_entry_table *reb);

#endif
