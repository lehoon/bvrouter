#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#include <unistd.h>

#include <arpa/inet.h>
#include "pal_phy_vport.h"
#include "pal_ip_cell.h"
#include "../vtep.h"
#include "pal_error.h"
#include "pal_l2_ctl.h"
#include "pal_utils.h"

static char uuid[] = "uuid";

static char int_vport_name1[] = "int_vport_1";
static char int_vport_name2[] = "int_vport_2";
static char int_vport_name3[] = "int_vport_3";
static char int_vport_name4[] = "int_vport_3"; /*error*/
static char int_vport_name5[] = "int_vport_5";
static char int_vport_name6[] = "int_vport_6";
static char int_vport_name7[] = "int_vport_7";
static char int_vport_name8[] = "int_vport_7";

static int int_vport_vni1 = 1;
static int int_vport_vni2 = 2;
static int int_vport_vni3 = 3;
static int int_vport_vni4 = 4;
static int int_vport_vni5 = 2; 	 /*error*/
static int int_vport_vni6 = -1; 	 /*error*/
static int int_vport_vni7 = 7;
static int int_vport_vni8 = 8;

static uint8_t int_gw_mac[6]={0x00,0x00,0xEF,0x12,0x2F,0x00};
static uint8_t int_gw_mac2[6]={0x00,0x00,0xEF,0x12,0x2F,0x10};
static uint8_t int_gw_mac3[6]={0x00,0x00,0xEF,0x12,0x2F,0x11};
static uint8_t int_gw_mac4[6]={0x00,0x00,0xEF,0x11,0x2F,0x11};
static uint8_t invalid_gw_mac[6]={0xff,0xff,0xff,0xff,0xff,0xff};

static void vxlan_dev_creat_delete_test(void)
{
	uint32_t int_gw_ip;
	struct vxlan_dev *vdev;
	struct int_vport_entry entry;

	entry.uuid = uuid;

 	vdev = get_vxlan_dev(int_vport_vni1);
	assert(vdev == NULL);
	
	/*int_vport 1*/
	inet_pton(AF_INET, "10.64.2.1", &int_gw_ip);
	entry.vport_name = int_vport_name1;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni1;
	assert(int_vport_add_ctl(&entry,NULL) == 0);
	/*repeat create*/
	assert(int_vport_add_ctl(&entry,NULL) < 0);
	
   	/*int_vport 2*/
	inet_pton(AF_INET, "10.64.2.2", &int_gw_ip);
	entry.vport_name = int_vport_name2;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni1;
	/*repeat mac*/
	assert(int_vport_add_ctl(&entry,NULL) < 0);	
	memcpy(entry.int_gw_mac,int_gw_mac2,6);	
	assert(int_vport_add_ctl(&entry,NULL) == 0);	
	/*repeat create*/
	assert(int_vport_add_ctl(&entry,NULL) < 0);

	/*int_vport 3*/
	inet_pton(AF_INET, "10.64.2.3", &int_gw_ip);
	entry.vport_name = int_vport_name3;
	memcpy(entry.int_gw_mac,int_gw_mac3,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni1;
	assert(int_vport_add_ctl(&entry,NULL) == 0);
	/*repeat create*/
	assert(int_vport_add_ctl(&entry,NULL) < 0);

	/*int_vport 4*/
	inet_pton(AF_INET, "10.64.2.3", &int_gw_ip);
	entry.vport_name = int_vport_name5;
	memcpy(entry.int_gw_mac,int_gw_mac4,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni1;
	assert(int_vport_add_ctl(&entry,NULL) == 0);

 	vdev = get_vxlan_dev(int_vport_vni1);
	assert(vdev != NULL);

	assert(vport_delete_ctl(int_vport_name1) == 0);
	assert(vport_delete_ctl(int_vport_name2) == 0);

	vdev = get_vxlan_dev(int_vport_vni1);
	assert(vdev != NULL);
	
	assert(vport_delete_ctl(int_vport_name3) == 0);
	assert(vport_delete_ctl(int_vport_name4) < 0);	
	vdev = get_vxlan_dev(int_vport_vni1);
	assert(vdev != NULL);
	
	assert(vport_delete_ctl(int_vport_name5) == 0);

	vdev = get_vxlan_dev(int_vport_vni1);
	assert(vdev == NULL);

	assert(vport_delete_ctl(int_vport_name1) < 0);
	assert(vport_delete_ctl(int_vport_name3) < 0);
}

static void int_vport_creat_delete_test(void)
{
	uint32_t int_gw_ip;
	struct int_vport *vp;
	struct int_vport_entry entry;

	entry.uuid = uuid;

	/*int_vport 1*/
	inet_pton(AF_INET, "10.64.2.1", &int_gw_ip);
	entry.vport_name = int_vport_name1;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni1;
	assert(int_vport_add_ctl(&entry,NULL) == 0);
	/*repeat create*/
	assert(int_vport_add_ctl(&entry,NULL) < 0);
	
   	/*int_vport 2*/
	inet_pton(AF_INET, "10.64.2.2", &int_gw_ip);
	entry.vport_name = int_vport_name2;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni2;
	assert(int_vport_add_ctl(&entry,NULL) == 0);

	/*int_vport 3*/
	inet_pton(AF_INET, "10.64.2.3", &int_gw_ip);
	entry.vport_name = int_vport_name3;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni3;
	assert(int_vport_add_ctl(&entry,NULL) == 0);

	/*int_vport 4*/
	inet_pton(AF_INET, "10.64.2.4", &int_gw_ip);
	entry.vport_name = int_vport_name4;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni4;
	assert(int_vport_add_ctl(&entry,NULL) < 0);

	/*int_vport 5*/
	inet_pton(AF_INET, "10.64.2.5", &int_gw_ip);
	entry.vport_name = int_vport_name5;
	memcpy(entry.int_gw_mac,int_gw_mac2,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni5;
	assert(int_vport_add_ctl(&entry,NULL) == 0);

	/*int_vport 6*/
	inet_pton(AF_INET, "10.64.2.6", &int_gw_ip);
	entry.vport_name = int_vport_name6;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni6;
	assert(int_vport_add_ctl(&entry,NULL) < 0);

	 /*int_vport 7*/
	inet_pton(AF_INET, "10.64.2.7", &int_gw_ip);
	entry.vport_name = int_vport_name7;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni7;
	assert(int_vport_add_ctl(&entry,NULL) == 0);

	/*int_vport 8*/
	inet_pton(AF_INET, "10.64.2.8", &int_gw_ip);
	entry.vport_name = int_vport_name8;
	memcpy(entry.int_gw_mac,invalid_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni8;
	assert(int_vport_add_ctl(&entry,NULL) < 0);

	assert(vport_delete_ctl(int_vport_name1) == 0);
	assert(vport_delete_ctl(int_vport_name2) == 0);
	assert(vport_delete_ctl(int_vport_name3) == 0);
	assert(vport_delete_ctl(int_vport_name4) < 0);	
	assert(vport_delete_ctl(int_vport_name5) == 0);
	assert(vport_delete_ctl(int_vport_name6) < 0);	
	assert(vport_delete_ctl(int_vport_name7) == 0);
	assert(vport_delete_ctl(int_vport_name2) < 0);	
	assert(vport_delete_ctl(int_vport_name8) < 0);

	vxlan_dev_creat_delete_test();

}

static uint8_t vm11_mac[6]={0x00,0x00,0xEF,0x12,0x2F,0xee};
static uint8_t vm12_mac[6]={0x00,0x00,0xEF,0x12,0x2F,0xef};
static uint8_t vm13_mac[6]={0x00,0x00,0xEF,0x12,0x2F,0xee}; /*err*/
static uint8_t vm14_mac[6]={0x00,0x00,0xEF,0x12,0x2F,0x33};
static uint8_t vm15_mac[6]={0x00,0x00,0xEF,0x12,0x2F,0x34};
static uint8_t vm16_mac[6]={0x00,0x00,0xEF,0x12,0x2F,0x44};

static uint8_t vm21_mac[6]={0x00,0x00,0xEF,0x12,0x2F,0xee};
static uint8_t vm22_mac[6]={0x00,0x00,0xEF,0x12,0x2F,0xef};
static uint8_t broadcast_mac[6]={0xff,0xff,0xff,0xff,0xff,0xff};

static void broadcast_fdb_entry_test(void)
{	
	uint32_t int_gw_ip,vtep1_ip,vtep2_ip,vtep3_ip,vtep4_ip,vtep5_ip;
	uint16_t port1,port2,port3,port4,port5;
	struct int_vport_entry entry;
	struct fdb_entry fdbentry;

	entry.uuid = uuid;

	/*int_vport 2*/
	inet_pton(AF_INET, "10.64.3.1", &int_gw_ip);
	entry.vport_name = int_vport_name2;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni2;
	assert(int_vport_add_ctl(&entry,NULL) == 0);

	port1=0;
	port2=0;
	port3=0;
	port4=1024;
	port5=0;
	
	inet_pton(AF_INET, "10.31.55.1", &vtep1_ip);
	inet_pton(AF_INET, "10.32.55.1", &vtep2_ip);	
	inet_pton(AF_INET, "10.31.55.1", &vtep3_ip); /*error vtep*/
	inet_pton(AF_INET, "10.31.55.1", &vtep4_ip);	
	inet_pton(AF_INET, "10.35.55.1", &vtep5_ip);

	/*create non-braodcast fdb21*/
	memcpy(fdbentry.mac,vm21_mac,6);
	fdbentry.remote_ip = vtep1_ip;
	fdbentry.remote_port = 0;
	assert(vxlan_fdb_add_ctl(int_vport_vni2,&fdbentry) == 0);

	/*create non-braodcast fdb22*/
	memcpy(fdbentry.mac,vm22_mac,6);
	fdbentry.remote_ip = vtep1_ip;
	fdbentry.remote_port = 0;
	assert(vxlan_fdb_add_ctl(int_vport_vni2,&fdbentry) == 0);

	/*create braodcast fdb1*/
	memcpy(fdbentry.mac,broadcast_mac,6);
	fdbentry.remote_ip = vtep1_ip;
	fdbentry.remote_port = port1;
	assert(vxlan_fdb_add_ctl(int_vport_vni2,&fdbentry) == 0);

	/*create braodcast fdb2*/
	memcpy(fdbentry.mac,broadcast_mac,6);
	fdbentry.remote_ip = vtep2_ip;
	fdbentry.remote_port = port2;
	assert(vxlan_fdb_add_ctl(int_vport_vni2,&fdbentry) == 0);

	/*create braodcast fdb3*/
	memcpy(fdbentry.mac,broadcast_mac,6);
	fdbentry.remote_ip = vtep3_ip;
	fdbentry.remote_port = port3;
	assert(vxlan_fdb_add_ctl(int_vport_vni2,&fdbentry) == 0);

	/*create braodcast fdb4*/
	memcpy(fdbentry.mac,broadcast_mac,6);
	fdbentry.remote_ip = vtep4_ip;
	fdbentry.remote_port = port4;
	assert(vxlan_fdb_add_ctl(int_vport_vni2,&fdbentry) == 0);

	/*create braodcast fdb5*/
	memcpy(fdbentry.mac,broadcast_mac,6);
	fdbentry.remote_ip = vtep5_ip;
	fdbentry.remote_port = port5;
	assert(vxlan_fdb_add_ctl(int_vport_vni2,&fdbentry) == 0);

	/*delete fdb 21*/
	assert(vxlan_fdb_delete_ctl(int_vport_vni2,vm21_mac) == 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vni2,vm21_mac) < 0);

	/*delete int_vport 2*/
	assert(vport_delete_ctl(int_vport_name2) == 0);

	assert(vxlan_fdb_delete_ctl(int_vport_vni2,vm21_mac) < 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vni2,broadcast_mac) < 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vni2,vm22_mac) < 0);
}

static void fdb_create_delete_test(void)
{
	uint32_t int_gw_ip,vtep_ip;
	struct int_vport_entry entry;
	struct fdb_entry fdbentry;

	entry.uuid = uuid;

	inet_pton(AF_INET, "10.24.2.2", &vtep_ip);

	/*err fdb add*/
	memcpy(fdbentry.mac,vm11_mac,6);
	fdbentry.remote_ip = vtep_ip;
	fdbentry.remote_port = 0;
	assert(vxlan_fdb_add_ctl(int_vport_vni1,&fdbentry) < 0);
	
	/*int_vport 1*/
	inet_pton(AF_INET, "10.64.2.1", &int_gw_ip);
	entry.vport_name = int_vport_name1;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni1;
	assert(int_vport_add_ctl(&entry,NULL) == 0);
		
	/*create fdb11*/
	memcpy(fdbentry.mac,vm11_mac,6);
	fdbentry.remote_ip = vtep_ip;
	fdbentry.remote_port = 0;
	assert(vxlan_fdb_add_ctl(int_vport_vni1,&fdbentry) == 0);

	/*create fdb12*/
	memcpy(fdbentry.mac,vm12_mac,6);
	assert(vxlan_fdb_add_ctl(int_vport_vni1,&fdbentry) == 0);
	
	/*create fdb13*/
	memcpy(fdbentry.mac,vm13_mac,6);
	assert(vxlan_fdb_add_ctl(int_vport_vni1,&fdbentry) < 0);

	/*create fdb14*/
	memcpy(fdbentry.mac,vm14_mac,6);
	assert(vxlan_fdb_add_ctl(int_vport_vni1,&fdbentry) == 0);

	/*create fdb15*/
	memcpy(fdbentry.mac,vm15_mac,6);
	assert(vxlan_fdb_add_ctl(int_vport_vni1,&fdbentry) == 0);

	/*create fdb16*/
	memcpy(fdbentry.mac,vm16_mac,6);
	assert(vxlan_fdb_add_ctl(int_vport_vni1,&fdbentry) == 0);

	/*err delete*/
	assert(vxlan_fdb_delete_ctl(int_vport_vni2,vm11_mac) < 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vni3,vm11_mac) < 0);	
	
	assert(vxlan_fdb_delete_ctl(int_vport_vni1,vm11_mac) == 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vni1,vm11_mac) < 0);	
	assert(vxlan_fdb_delete_ctl(int_vport_vni1,vm12_mac) == 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vni1,vm13_mac) < 0);

	/*delete int_vport 1*/
	assert(vport_delete_ctl(int_vport_name1) == 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vni1,vm14_mac) < 0);	
	assert(vxlan_fdb_delete_ctl(int_vport_vni1,vm15_mac) < 0);	
	assert(vxlan_fdb_delete_ctl(int_vport_vni1,vm16_mac) < 0);
	
	broadcast_fdb_entry_test();
}

static char int_vport_namex[] = "int_vport_x";
static int int_vport_vnix = 150;

static uint8_t vmx1_mac[6]={0x00,0x00,0xff,0xff,0xff,0x01};
static uint8_t vmx2_mac[6]={0x00,0x00,0xff,0xff,0xff,0x02};
static uint8_t vmx3_mac[6]={0x00,0x00,0xff,0xff,0xff,0x03};
static uint8_t vmx4_mac[6]={0x00,0x00,0xff,0xff,0xff,0x04};
static uint8_t vmx5_mac[6]={0x00,0x00,0xff,0xff,0xff,0x05};

static void int_vport_data_plane_test(void)
{
	uint32_t int_gw_ip,vtep_ip;
	struct int_vport_entry entry;
	struct fdb_entry fdbentry;

	entry.uuid = uuid;

	inet_pton(AF_INET, "192.168.200.1", &vtep_ip);

	/*create int_vport x*/
	inet_pton(AF_INET, "10.107.64.1", &int_gw_ip);
	entry.vport_name = int_vport_namex;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vnix;
	assert(int_vport_add_ctl(&entry,NULL) == 0);

	/*create fdb1*/
	memcpy(fdbentry.mac,vmx1_mac,6);
	fdbentry.remote_ip = vtep_ip;
	fdbentry.remote_port = 0;
	assert(vxlan_fdb_add_ctl(int_vport_vnix,&fdbentry) ==0);

	/*create fdb2*/
	memcpy(fdbentry.mac,vmx2_mac,6);
	assert(vxlan_fdb_add_ctl(int_vport_vnix,&fdbentry) == 0);

	/*create fdb3*/
	memcpy(fdbentry.mac,vmx3_mac,6);
	assert(vxlan_fdb_add_ctl(int_vport_vnix,&fdbentry) == 0);

	/*create fdb4*/
	memcpy(fdbentry.mac,vmx4_mac,6);
	assert(vxlan_fdb_add_ctl(int_vport_vnix,&fdbentry) == 0);

	/*create fdb5*/
	memcpy(fdbentry.mac,vmx5_mac,6);
	assert(vxlan_fdb_add_ctl(int_vport_vnix,&fdbentry) == 0);

	sleep(4);

	/*delete fdbx2 fdbx3*/
	assert(vxlan_fdb_delete_ctl(int_vport_vnix,vmx2_mac) == 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vnix,vmx3_mac) == 0);
	sleep(1);
	
	/*delete int_vport x*/
	assert(vport_delete_ctl(int_vport_namex) == 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vnix,vmx1_mac) < 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vnix,vmx4_mac) < 0);
	assert(vxlan_fdb_delete_ctl(int_vport_vnix,vmx5_mac) < 0);
	sleep(3);

	/*create int_vport x*/
	assert(int_vport_add_ctl(&entry,NULL) == 0);
	
	/*create braodcast fdb*/
	memcpy(fdbentry.mac,broadcast_mac,6);
	fdbentry.remote_ip = vtep_ip;
	fdbentry.remote_port = 0;
	assert(vxlan_fdb_add_ctl(int_vport_vnix,&fdbentry) ==0);

	memcpy(fdbentry.mac,broadcast_mac,6);
	fdbentry.remote_ip = vtep_ip;
	fdbentry.remote_port = 1024;
	assert(vxlan_fdb_add_ctl(int_vport_vnix,&fdbentry) ==0);

	memcpy(fdbentry.mac,broadcast_mac,6);
	fdbentry.remote_ip = vtep_ip;
	fdbentry.remote_port = 16;
	assert(vxlan_fdb_add_ctl(int_vport_vnix,&fdbentry) ==0);

	sleep(3);
	
	/*delete int_vport x*/
	assert(vport_delete_ctl(int_vport_namex) == 0);	
}

static void arp_create_delete_test(void)
{
	uint32_t int_gw_ip,ip1,ip2,ip3,ip4;
	struct vxlan_dev *vdev;
	struct int_vport_entry entry;	
	entry.uuid = uuid;
	struct vxlan_arp_entry arp_entry;
	struct vxlan_arp_entry *arp_e;

	inet_pton(AF_INET, "10.24.2.1", &ip1);
	inet_pton(AF_INET, "10.24.2.2", &ip2);
	inet_pton(AF_INET, "10.24.2.3", &ip3);
	inet_pton(AF_INET, "10.24.2.4", &ip4); 

	/*err arp add*/
	memcpy(arp_entry.mac_addr,vm11_mac,6);
	arp_entry.ip = ip1;
	assert(vxlan_arp_add_ctl(int_vport_vni1,&arp_entry) < 0);

	/*int_vport 1*/
	inet_pton(AF_INET, "10.64.2.1", &int_gw_ip);
	entry.vport_name = int_vport_name1;
	memcpy(entry.int_gw_mac,int_gw_mac,6);
	entry.int_gw_ip = int_gw_ip;
	entry.vni = int_vport_vni1;
	assert( int_vport_add_ctl(&entry,NULL) == 0);
	vdev = get_vxlan_dev(int_vport_vni1);
	assert(vdev != NULL);
	
	/*create arp1*/
	memcpy(arp_entry.mac_addr,vm11_mac,6);
	arp_entry.ip = ip1;
	assert(vxlan_arp_add_ctl(int_vport_vni1,&arp_entry) == 0);

	/*create arp2*/
	memcpy(arp_entry.mac_addr,vm12_mac,6);
	arp_entry.ip = ip2;
	assert(vxlan_arp_add_ctl(int_vport_vni1,&arp_entry) == 0);
	/*repeate create*/
	assert(vxlan_arp_add_ctl(int_vport_vni1,&arp_entry) == 0);

	/*create arp3*/
	memcpy(arp_entry.mac_addr,vm13_mac,6);
	arp_entry.ip = ip3;
	assert(vxlan_arp_add_ctl(int_vport_vni1,&arp_entry) == 0);
	
	/*create arp4*/
	memcpy(arp_entry.mac_addr,vm12_mac,6);
	arp_entry.ip = ip4;
	assert(vxlan_arp_add_ctl(int_vport_vni1,&arp_entry) == 0);

	arp_e = find_vxlan_arp_entry(vdev, ip1);
	assert(arp_e != NULL);
	arp_e = find_vxlan_arp_entry(vdev, ip2);
	assert(arp_e != NULL);
	arp_e = find_vxlan_arp_entry(vdev, ip3);
	assert(arp_e != NULL);
	arp_e = find_vxlan_arp_entry(vdev, ip4);
	assert(arp_e != NULL);

	/*delete arp2*/
	arp_entry.ip = ip2;
	assert(vxlan_arp_delete_ctl(int_vport_vni1,&arp_entry) == 0);
	assert(vxlan_arp_delete_ctl(int_vport_vni1,&arp_entry) < 0);
	arp_e = find_vxlan_arp_entry(vdev, ip2);
	assert(arp_e == NULL);
	arp_e = find_vxlan_arp_entry(vdev, ip3);
	assert(arp_e != NULL);
	
	/*delete arp3*/
	arp_entry.ip = ip3;
	assert(vxlan_arp_delete_ctl(int_vport_vni1,&arp_entry) == 0);
	assert(vxlan_arp_delete_ctl(int_vport_vni1,&arp_entry) < 0);
	arp_e = find_vxlan_arp_entry(vdev, ip3);
	assert(arp_e == NULL);
	arp_e = find_vxlan_arp_entry(vdev, ip1);
	assert(arp_e != NULL);

	/*delete int_vport 1*/
	assert(vport_delete_ctl(int_vport_name1) == 0);
	/*delete arp4*/
	arp_entry.ip = ip4;
	assert(vxlan_arp_delete_ctl(int_vport_vni1,&arp_entry) < 0);
	arp_e = find_vxlan_arp_entry(vdev, ip1);
	assert(arp_e == NULL);
		
	arp_entry.ip = ip1;
	assert(vxlan_arp_delete_ctl(int_vport_vni1,&arp_entry) < 0);
	arp_entry.ip = ip3;
	assert(vxlan_arp_delete_ctl(int_vport_vni1,&arp_entry) < 0);
}

extern 	void int_vport_test(void);
void int_vport_test(void)
{	
	int_vport_creat_delete_test();
	fdb_create_delete_test();
	arp_create_delete_test();
	int_vport_data_plane_test();
	
	printf("int_vport_test ok!\n");
}
