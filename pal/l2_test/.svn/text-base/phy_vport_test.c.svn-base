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

static char phy_vport_name1[] = "phy_vport_1";
static char phy_vport_name2[] = "phy_vport_2";
static char phy_vport_name3[] = "phy_vport_3";
static char phy_vport_name4[] = "phy_vport_4";
static char phy_vport_name5[] = "phy_vport_2";  /*error*/
static char phy_vport_name6[] = "phy_vport_6";
static char phy_vport_name7[] = "111212312312312312312312312311113323233333333345123451234567890012121212121212121212121212121212";
static char phy_vport_name8[] = "phy_vport_8";

static uint8_t ext_gw_mac[6] = {0x25,0x90,0xEF,0x36,0x2F,0x00};
static uint8_t invalid_gw_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

/*
   create phy_vport 1236 succes 45 fail
   delete 1236 succes
*/
static void phy_vport_creat_delete_test(void){
	uint32_t ext_gw1_ip,ext_gw2_ip,ext_gw3_ip,
		ext_gw4_ip,ext_gw5_ip,ext_gw6_ip,ext_gw7_ip,ext_gw8_ip;
	struct phy_vport_entry entry;

	entry.uuid = uuid;

	inet_pton(AF_INET, "192.168.2.1", &ext_gw1_ip);
	inet_pton(AF_INET, "192.168.2.2", &ext_gw2_ip);
	inet_pton(AF_INET, "192.168.2.3", &ext_gw3_ip);
	inet_pton(AF_INET, "192.168.2.2", &ext_gw4_ip); /*error*/
	inet_pton(AF_INET, "192.168.2.5", &ext_gw5_ip);	
	inet_pton(AF_INET, "192.168.2.6", &ext_gw6_ip);	
	inet_pton(AF_INET, "192.168.2.7", &ext_gw7_ip);
	inet_pton(AF_INET, "192.168.2.8", &ext_gw8_ip);

	/*create phy_vport 1*/
	entry.vport_name = phy_vport_name1;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw1_ip;
	assert(phy_vport_add_ctl(&entry,NULL)==0);

	/*create phy_vport 2*/
	entry.vport_name = phy_vport_name2;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw2_ip;
	assert(phy_vport_add_ctl(&entry,NULL)==0);

	/*create phy_vport 3*/
	entry.vport_name = phy_vport_name3;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw3_ip;
	assert(phy_vport_add_ctl(&entry,NULL)==0);

	/*create phy_vport 4*/
	entry.vport_name = phy_vport_name4;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw4_ip;
	assert(phy_vport_add_ctl(&entry,NULL) < 0);

	/*create phy_vport 5*/
	entry.vport_name = phy_vport_name5;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw5_ip;
	assert(phy_vport_add_ctl(&entry,NULL)<=0);


	/*create phy_vport 6*/
	entry.vport_name = phy_vport_name6;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw6_ip;
	assert(phy_vport_add_ctl(&entry,NULL)==0);
	assert(phy_vport_add_ctl(&entry,NULL) < 0);

	/*create phy_vport 7*/
	entry.vport_name = phy_vport_name7; /*too long name*/
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw7_ip;
	assert(phy_vport_add_ctl(&entry,NULL) < 0);

	/*create phy_vport 8*/
	entry.vport_name = phy_vport_name8; 
	memcpy(entry.ext_gw_mac,invalid_gw_mac,6);
	entry.ext_gw_ip = ext_gw8_ip;
	assert(phy_vport_add_ctl(&entry,NULL) == 0);

	assert(vport_delete_ctl(phy_vport_name1)==0);
	assert(vport_delete_ctl(phy_vport_name2)==0);
	assert(vport_delete_ctl(phy_vport_name3)==0);
	assert(vport_delete_ctl(phy_vport_name4) < 0);
	assert(vport_delete_ctl(phy_vport_name5) < 0);
	assert(vport_delete_ctl(phy_vport_name6)== 0);	
	assert(vport_delete_ctl(phy_vport_name7) < 0);
	assert(vport_delete_ctl(phy_vport_name8)== 0);
	/*repeat delete*/
	assert(vport_delete_ctl(phy_vport_name1) < 0);

}

static void floating_ip_create_delete_test(void)
{
	uint32_t ext_gw1_ip,ext_gw2_ip,floating_ip;
	struct phy_vport_entry entry;
	entry.uuid = uuid;

	inet_pton(AF_INET, "192.168.2.1", &ext_gw1_ip);
	inet_pton(AF_INET, "192.168.3.1", &ext_gw2_ip);

	entry.vport_name = phy_vport_name1;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw1_ip;
	/*create phy_vport 1*/
	assert(phy_vport_add_ctl(&entry,NULL)==0);

	entry.vport_name = phy_vport_name2;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw2_ip;
	/*create phy_vport 2*/
	assert(phy_vport_add_ctl(&entry,NULL)==0);
	
	/*create floating_ip 2.2 */
	inet_pton(AF_INET, "192.168.2.2", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name1) == 0);
	
	/*create floating_ip 2.3 */
	inet_pton(AF_INET, "192.168.2.3", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name1) == 0);
	
	/*create floating_ip 2.4 */
	inet_pton(AF_INET, "192.168.2.4", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name1) == 0);
	
	/*create floating_ip 3.2 */
	inet_pton(AF_INET, "192.168.3.2", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name2) == 0);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name2) < 0);
	
	/*create floating_ip 3.3 */
	inet_pton(AF_INET, "192.168.3.3", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name2) == 0);
	
	/*create floating_ip 3.4 */
	inet_pton(AF_INET, "192.168.3.4", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name2) == 0);

	/*add error floating_ip*/
	inet_pton(AF_INET, "192.168.2.1", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name1) < 0);
	inet_pton(AF_INET, "192.168.2.1", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name2) < 0);
	inet_pton(AF_INET, "192.168.3.1", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name1) < 0);
	inet_pton(AF_INET, "192.168.3.1", &floating_ip);	
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name2) < 0);

    /*create phy_vport 3*/
	entry.vport_name = phy_vport_name3;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);	
	inet_pton(AF_INET, "192.168.2.2", &floating_ip); /*error*/
	entry.ext_gw_ip = floating_ip;
	assert(phy_vport_add_ctl(&entry,NULL) < 0);

	/*delete floating_ip 2.2 */
	inet_pton(AF_INET, "192.168.2.2", &floating_ip);
	assert(floating_ip_delete_ctl(floating_ip) == 0);
	assert(floating_ip_delete_ctl(floating_ip) < 0);

	/*create floating_ip 2.2 */
	inet_pton(AF_INET, "192.168.2.2", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name1) == 0);	
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name2) < 0);

	/*delete floating_ip 2.3 */
	inet_pton(AF_INET, "192.168.2.3", &floating_ip);
	assert(floating_ip_delete_ctl(floating_ip) == 0);

	/*delete phy_vport 1*/
	assert(vport_delete_ctl(phy_vport_name1)==0);

	/*delete floating_ip 2.4 */
	inet_pton(AF_INET, "192.168.2.4", &floating_ip);
	assert(floating_ip_delete_ctl(floating_ip) < 0);
	
	/*delete floating_ip 2.2 */
	inet_pton(AF_INET, "192.168.2.2", &floating_ip);
	assert(floating_ip_delete_ctl(floating_ip) < 0);

	/*delete floating_ip 3.2 */
	inet_pton(AF_INET, "192.168.3.2", &floating_ip);
	assert(floating_ip_delete_ctl(floating_ip) == 0);

	/*delete error floating_ip */
	inet_pton(AF_INET, "192.168.3.1", &floating_ip);
	assert(floating_ip_delete_ctl(floating_ip) < 0);

	/*delete phy_vport 2*/
	assert(vport_delete_ctl(phy_vport_name2)==0);

	/*delete floating_ip 3.3 */
	inet_pton(AF_INET, "192.168.3.3", &floating_ip);
	assert(floating_ip_delete_ctl(floating_ip) < 0);

	/*delete floating_ip 3.4 */
	inet_pton(AF_INET, "192.168.3.4", &floating_ip);
	assert(floating_ip_delete_ctl(floating_ip) < 0);

	/*add null phy_vport */
	inet_pton(AF_INET, "192.168.2.2", &floating_ip);
	assert(floating_ip_add_ctl(floating_ip,phy_vport_name1) < 0);
	
}

static char phy_vport_namex[] = "phy_vport_x";

/*need 20 secend to complete test*/
static void phy_vport_data_plane_test(void)
{
	uint32_t ext_gw_ip,floating_ip1,floating_ip2,floating_ip3,floating_ip4,floating_ip5;
	struct phy_vport_entry entry;
	entry.uuid = uuid;

	inet_pton(AF_INET, "192.168.10.1", &ext_gw_ip);

	inet_pton(AF_INET, "192.168.10.2", &floating_ip1);
	inet_pton(AF_INET, "192.168.10.3", &floating_ip2);
	inet_pton(AF_INET, "192.168.10.4", &floating_ip3);
	inet_pton(AF_INET, "192.168.10.5", &floating_ip4);
	inet_pton(AF_INET, "192.168.10.6", &floating_ip5);

	/*create phy_vport x*/
	entry.vport_name = phy_vport_namex;
	memcpy(entry.ext_gw_mac,ext_gw_mac,6);
	entry.ext_gw_ip = ext_gw_ip;
	assert(phy_vport_add_ctl(&entry,NULL)==0);

	/*sleep2*/
	sleep(1);

	/*create floating_ip1 */
	assert(floating_ip_add_ctl(floating_ip1,phy_vport_namex) == 0);	
	/*sleep2*/
	sleep(1);

	/*create floating_ip2 */
	assert(floating_ip_add_ctl(floating_ip2,phy_vport_namex) == 0);	
	/*create floating_ip3 */
	assert(floating_ip_add_ctl(floating_ip3,phy_vport_namex) == 0);	
	/*sleep2*/
	sleep(1);

	/*create floating_ip4 */
	assert(floating_ip_add_ctl(floating_ip4,phy_vport_namex) == 0);
     /*sleep2*/
	sleep(1);
	
	/*create floating_ip5 */
	assert(floating_ip_add_ctl(floating_ip5,phy_vport_namex) == 0);
     /*sleep2*/
	sleep(4);

	assert(floating_ip_delete_ctl(floating_ip1) == 0);	
	assert(floating_ip_delete_ctl(floating_ip5) == 0);
	sleep(1);
	assert(floating_ip_delete_ctl(floating_ip4) == 0);
		
	assert(vport_delete_ctl(phy_vport_namex)==0);
	assert(floating_ip_delete_ctl(floating_ip2) < 0);	
	assert(floating_ip_delete_ctl(floating_ip3) < 0);

	sleep(1);

}

extern 	void phy_vport_test(void);
void phy_vport_test(void)
{	
	phy_vport_creat_delete_test();
	floating_ip_create_delete_test();
	phy_vport_data_plane_test();
	printf("phy_vport_test ok!\n");
}

