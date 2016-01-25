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
#include "../route.h"

static void normal_case_test(void){
	uint32_t ip;
	struct fib_result res;
	struct route_table *rt;
	
	printf("---------------------Test case 0--------------------------\n");
	rt = pal_rtable_new();		
	assert(rt != NULL);

	/*create local route*/
	assert(route_add_local(rt,inet_addr("192.168.30.2"),NULL)==0);		
	assert(route_add_local(rt,inet_addr("192.168.30.2"),NULL) < 0);

	/*create connect route*/
	assert(route_add_connected(rt,inet_addr("192.168.30.0"),24,inet_addr("192.168.30.2"),NULL)==0);	

	/*create common route*/
	assert(pal_route_add(rt,inet_addr("10.23.13.0"),24,inet_addr("192.168.30.7"))==0);	
	assert(pal_route_add(rt,inet_addr("17.42.22.0"),24,inet_addr("192.168.30.8"))==0);	
	assert(pal_route_add(rt,inet_addr("17.42.22.0"),24,inet_addr("192.168.30.9"))== 0);	

	/*repeate create*/
	assert(pal_route_add(rt,inet_addr("17.42.22.0"),24,inet_addr("192.168.30.8"))< 0);
	/*network unreachable*/
	assert(pal_route_add(rt,inet_addr("10.42.12.0"),24,inet_addr("192.168.20.2"))< 0);

	pal_trie_dump(rt);

	/*lookup local route*/
	ip = inet_addr("192.168.30.2");
    assert(pal_route_lookup(rt, ip, &res)==0);
	assert((res.route_type == PAL_ROUTE_LOCAL) && (res.sip = inet_addr("192.168.30.2")));

	/*lookup connect route*/
	ip = inet_addr("192.168.30.7");
    assert(pal_route_lookup(rt, ip, &res)==0);
	assert((res.route_type == PAL_ROUTE_CONNECTED) && (res.sip = inet_addr("192.168.30.2")));

	/*lookup common route*/
	ip = inet_addr("10.23.13.3");
    assert(pal_route_lookup(rt, ip, &res)==0);
	assert((res.route_type == PAL_ROUTE_COMMON) && (res.next_hop= inet_addr("192.168.30.7")));

	/*lookup empty route*/
	ip = inet_addr("10.77.13.3");
    assert(pal_route_lookup(rt, ip, &res) < 0);

	/*lookup common route*/
	ip = inet_addr("192.168.30.0");
    assert(pal_route_lookup(rt, ip, &res) == 0);
	assert((res.route_type == PAL_ROUTE_CONNECTED));
	
	/*delete local route*/
	assert(pal_route_del_local(rt,inet_addr("192.168.30.2"))== 0);	
	assert(pal_route_del_local(rt,inet_addr("192.168.30.2"))< 0);
	
	/*delete common route*/
	assert(pal_route_del(rt,inet_addr("10.23.13.0"),24)== 0);	
	assert(pal_route_del(rt,inet_addr("10.23.13.0"),24)< 0);

	/*lookup common route*/
	ip = inet_addr("10.23.13.3");
    assert(pal_route_lookup(rt, ip, &res) < 0);
	
	/*delete connect route*/
	assert(pal_route_del_connect(rt,inet_addr("192.168.30.0"),24,inet_addr("192.168.30.2"))== 0);	
	assert(pal_route_del(rt,inet_addr("17.42.22.0"),24)< 0);

	/*lookup common route*/
	ip = inet_addr("17.42.22.3");
    assert(pal_route_lookup(rt, ip, &res) < 0);

	assert(rt->route_entry_count == 0);
	
	pal_trie_dump(rt);

	pal_rtable_destroy(rt);
}

/* if vport xx host_id is zero, eg 192.168.30.0, but network scope is the same ip..
*/
static void case_1_test(void)
{	
	uint32_t ip;
	struct fib_result res;
	struct route_table *rt;
	
	printf("---------------------Test case 1--------------------------\n");
	rt = pal_rtable_new();		
	assert(rt != NULL);
	
	/*create local route*/
	assert(route_add_local(rt,inet_addr("192.168.30.0"),NULL)==0);		
	/*create connect route*/
	assert(route_add_connected(rt,inet_addr("192.168.30.0"),24,inet_addr("192.168.30.0"),NULL)==0);	
	/*create common route*/
	assert(pal_route_add(rt,inet_addr("10.23.13.0"),24,inet_addr("192.168.30.7"))==0);	

	/*lookup common route*/
	ip = inet_addr("192.168.30.1");
    assert(pal_route_lookup(rt, ip, &res) == 0);	
	assert((res.route_type == PAL_ROUTE_CONNECTED));

	ip = inet_addr("192.168.30.0");
    assert(pal_route_lookup(rt, ip, &res) == 0);	
	assert((res.route_type == PAL_ROUTE_LOCAL));

	ip = inet_addr("10.23.13.22");
    assert(pal_route_lookup(rt, ip, &res) == 0);	
	assert((res.route_type == PAL_ROUTE_COMMON)&&(res.next_hop= inet_addr("192.168.30.7")));
	
	pal_trie_dump(rt);
	
	/*delete local route*/
	assert(pal_route_del_local(rt,inet_addr("192.168.30.0"))== 0);	
	/*delete connect route*/
	assert(pal_route_del_connect(rt,inet_addr("192.168.30.0"),24,inet_addr("192.168.30.0"))== 0);

	assert(rt->route_entry_count == 0);
	pal_rtable_destroy(rt);	
}

/* first add 10.0.0.0/8  connect_route
*  then  add 10.0.0.0/24 common_route
*  now, if we add nexthop is 10.0.0.2, I want to test the sysytem can work well or not.
*/
static void case_2_test(void)
{	
	uint32_t ip;
	struct fib_result res;
	struct route_table *rt;
	
	printf("---------------------Test case 2--------------------------\n");
	rt = pal_rtable_new();		
	assert(rt != NULL);
	
	/*create local route*/
	assert(route_add_local(rt,inet_addr("10.0.0.2"),NULL)==0);		
	/*create connect route*/
	assert(route_add_connected(rt,inet_addr("10.0.0.0"),8,inet_addr("10.0.0.2"),NULL)==0);	
	/*create common route*/
	assert(pal_route_add(rt,inet_addr("10.0.0.0"),24,inet_addr("10.0.0.7"))==0);

	/*create common route*/
	assert(pal_route_add(rt,inet_addr("192.168.2.0"),24,inet_addr("10.0.0.5"))==0);

	/*lookup common route*/
	ip = inet_addr("192.168.2.3");
    assert(pal_route_lookup(rt, ip, &res) == 0);	
	assert((res.route_type == PAL_ROUTE_COMMON)&&(res.next_hop= inet_addr("10.0.0.5")));
	
	pal_trie_dump(rt);
	
	/*delete local route*/
	assert(pal_route_del_local(rt,inet_addr("10.0.0.2"))== 0);	
	/*delete connect route*/
	assert(pal_route_del_connect(rt,inet_addr("10.0.0.0"),24,inet_addr("10.0.0.7")) < 0);	
	assert(pal_route_del_connect(rt,inet_addr("10.0.0.0"),8,inet_addr("10.0.0.2")) == 0);

	/*lookup common route*/
	ip = inet_addr("192.168.2.3");
    assert(pal_route_lookup(rt, ip, &res) < 0);	

	assert(rt->route_entry_count == 0);
	pal_rtable_destroy(rt);	
}

static void show_route_entry(struct route_entry_table *reb)
{
	int i;
	printf("Destination     Gateway         Genmask         Flags  Iface\n");

	for(i=0; i < reb->len ;i++){
		printf(""NIPQUAD_FMT"    ",NIPQUAD(reb->r_table[i].prefix));
		printf("   "NIPQUAD_FMT"    ",NIPQUAD(reb->r_table[i].next_hop));		
		printf("      %d     ",reb->r_table[i].prefixlen);
		printf("        %d  ",reb->r_table[i].route_type);
		printf("\n");
	}
}

/* first add 10.0.0.0/8  connect_route
*  then  add 10.0.0.0/24 conncet_route
*  now, if we add 192.168.2.0 - nexthop is 10.0.0.2, then will attach 10.0.0.0/24,I'll check it
*  after a while ,we delete connect_route 10.0.0.0/24 , we will test 192.168.2.0 is unreachable. 
*  I want to test the sysytem can work well or not.
*/
static void case_3_test(void)
{	
	uint32_t ip;
	struct fib_result res;
	struct route_table *rt;
	struct route_entry_table reb;
	
	printf("---------------------Test case 3--------------------------\n");
	rt = pal_rtable_new();		
	assert(rt != NULL);
	
	/*create local route*/
	assert(route_add_local(rt,inet_addr("10.0.0.8"),NULL)==0);		
	/*create connect route*/
	assert(route_add_connected(rt,inet_addr("10.0.0.0"),8,inet_addr("10.0.0.8"),NULL)==0);	

	/*create local route*/
	assert(route_add_local(rt,inet_addr("10.0.0.24"),NULL)==0);		
	/*create connect route*/
	assert(route_add_connected(rt,inet_addr("10.0.0.0"),24,inet_addr("10.0.0.24"),NULL)==0);	

	/*create common route*/
	assert(pal_route_add(rt,inet_addr("192.168.2.0"),24,inet_addr("10.0.0.5"))==0);

	/*lookup common route*/
	ip = inet_addr("192.168.2.3");
    assert(pal_route_lookup(rt, ip, &res) == 0);	
	assert((res.route_type == PAL_ROUTE_COMMON)&&(res.next_hop= inet_addr("10.0.0.5")));
	
	pal_trie_dump(rt);

	route_entry_table_show_ctl(rt,&reb);
	show_route_entry(&reb);
	
	/*delete local route*/
	assert(pal_route_del_local(rt,inet_addr("10.0.0.24"))== 0);	
	/*delete connect route*/
	assert(pal_route_del_connect(rt,inet_addr("10.0.0.0"),24,inet_addr("10.0.0.24")) == 0);

	/*lookup common route*/
	ip = inet_addr("192.168.2.3");
    assert(pal_route_lookup(rt, ip, &res) == 0);	
	assert((res.route_type == PAL_ROUTE_COMMON)&&(res.next_hop= inet_addr("10.0.0.5")));

	/*delete local route*/
	assert(pal_route_del_local(rt,inet_addr("10.0.0.8"))== 0);	
	/*delete connect route*/
	assert(pal_route_del_connect(rt,inet_addr("10.0.0.0"),8,inet_addr("10.0.0.8")) == 0);

	assert(rt->route_entry_count == 0);
	pal_rtable_destroy(rt);	
}
	
extern int route_test(void);
int route_test(void)
{	
	normal_case_test();
	case_1_test();
	case_2_test();
	case_3_test();
	return 0;
}

