#include <stdio.h>
#include <sys/prctl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <rte_common.h> // for rte_pause

#include "pal_cpu.h"
#include "pal_conf.h"
#include "pal_thread.h"
#include "pal_skb.h"

#include "pal_pktdef.h"
#include "pal_utils.h"
#include "pal_ipgroup.h"
#include "pal_netif.h"
#include "pal_slab.h"
#include "pal_malloc.h"
#include "pal_timer.h"
#include "pal_jiffies.h"
#include "pal_vnic.h"

extern int pal_start(void);

static PAL_DEFINE_PER_THREAD(struct pal_slab *, _skb_slab);

struct pal_ipgroup *g_ipg;

/* show a u32 type ip in str mode */
static inline char *trans_ip(__unused uint32_t ip)
{
	static uint8_t i = 0;
	static char g_print_ip_buf[5][20];

	i = (i + 1) % 5;
	memset(g_print_ip_buf[i], 0, 20);
	sprintf(g_print_ip_buf[i], NIPQUAD_FMT, NIPQUAD(ip));

	return g_print_ip_buf[i];
}

static inline void BGW_DEBUG_SKB(struct sk_buff *skb)
{
	struct ip_hdr *iph;
	struct tcp_hdr *th;
	struct udp_hdr *uh;
	struct icmp_hdr *icmph;
	iph = skb_ip_header(skb);
	char flags[10];
	int32_t pos = 0;

	switch (iph->protocol) {
	case PAL_IPPROTO_TCP:

		th = skb_tcp_header(skb);
		if (th->syn)
			pos = sprintf(flags, "%c", 'S');
		if (th->rst)
			pos += sprintf(flags + pos, "%c", 'R');
		if (th->fin)
			pos += sprintf(flags + pos, "%c", 'F');
		if (th->psh)
			pos += sprintf(flags + pos, "%c", 'P');
		if (th->ack)
			pos += sprintf(flags + pos, "%c", '.');
		flags[pos] = '\0';

		PAL_DEBUG("TCP %s.%d > %s.%d, ipid %d: Flags [%s], seq %u, ack %u\n", 
			trans_ip(iph->saddr), pal_ntohs(th->source), trans_ip(iph->daddr), pal_ntohs(th->dest),
			pal_ntohs(iph->id), flags, pal_ntohl(th->seq), pal_ntohl(th->ack_seq));
		break;
	case PAL_IPPROTO_UDP:
		uh = skb_udp_header(skb);
		PAL_DEBUG("UDP %s.%d > %s.%d, ipid %d\n", 
			trans_ip(iph->saddr), pal_ntohs(uh->source), trans_ip(iph->daddr), pal_ntohs(uh->dest),
			pal_ntohs(iph->id));
		break;
	case PAL_IPPROTO_ICMP:
		icmph = skb_icmp_header(skb);
		PAL_DEBUG("ICMP %s > %s, ipid %d, type %d\n", 
			trans_ip(iph->saddr), trans_ip(iph->daddr), pal_ntohs(iph->id), icmph->type);
		break;
	default:
		PAL_DEBUG("PROTO[%d] %s > %s, ipid %d\n", 
			iph->protocol, trans_ip(iph->saddr), trans_ip(iph->daddr), pal_ntohs(iph->id));
		break;
	}

}

static uint64_t get_ms(void)
{
	struct timeval tv;

	if(gettimeofday(&tv, NULL) < 0) {
		PAL_DEBUG("gettimeofday error\n");
		return 0;
	}

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* main function of control process */
static int __unused custom1(__unused void *data)
{
	int i;
	//uint32_t ip = inet_addr("123.123.163.4");

	while (1) {
		//PAL_LOG("in custom 1\n");
		run_timer(100);
		rte_pause();
		sleep(1);
		//pal_ipg_del_ip(ip, 1);
		//pal_ipg_add_ip(g_ipg, ip, 0, 0);
		for (i = 0; i < 300; i++) {
			rte_pause();
		}
	}

	return 0;
}

/* mon thread main cycle */
static int __unused custom2(__unused void *data)
{
	while (1) {
		//PAL_LOG("in custom 1\n");
		run_timer(100);
		rte_pause();
		sleep(1);
	}

	return 0;
}

static void __unused test_pkt_handler(struct sk_buff *skb)
{
	struct ip_hdr *iph = skb_ip_header(skb);
	//unsigned hdrlen = iph->ihl * 4 + sizeof(struct eth_hdr);

	iph = skb_ip_header(skb);
	//skb_push(skb, hdrlen);
	//pal_dump_pkt(skb);
	//skb_push(skb, hdrlen);

	/* dump receive pkt */
	pal_skb_free(skb);

	PAL_DEBUG("worker %d received a packet\n", pal_thread_id());
}

static void __unused ipg_single_test(void)
{
	struct pal_ipgroup    *ipg;
	int workers[PAL_MAX_THREAD];

	workers[0] = 0; 
	ipg = pal_ipg_create("single", test_pkt_handler, 
		                  IPG_DIST_PPL_SINGLE, workers, 
		                  1, 0, 0);
	if (ipg == NULL) {
		PAL_PANIC("ipg create failed\n");
	}
	if (pal_ipg_add_ip(ipg, inet_addr("192.168.124.31"), 0, 0) < 0)
		PAL_PANIC("ipg add ip failed\n");


	workers[0] = 0; 
	ipg = pal_ipg_create("single2", test_pkt_handler, 
		                  IPG_DIST_PPL_SINGLE, workers, 
		                  1, 0, PAL_IPG_F_HANDLEICMP);
	if (ipg == NULL) {
		PAL_PANIC("ipg create failed\n");
	}
	if (pal_ipg_add_ip(ipg, inet_addr("192.168.124.32"), 0, 0) < 0)
		PAL_PANIC("ipg add ip failed\n");
}

static void __unused ipg_l4hash_test(void)
{
	//struct pal_ipgroup    *ipg;
	int workers[PAL_MAX_THREAD];

	workers[0] = 0; 
	workers[1] = 1; 
	workers[2] = 2; 
	g_ipg = pal_ipg_create("l4hash", test_pkt_handler, 
		                  IPG_DIST_PPL_4TUPHASH, workers, 
		                  3, 0, 0);
	if (g_ipg == NULL) {
		PAL_PANIC("ipg create failed\n");
	}
	if (pal_ipg_add_ip(g_ipg, inet_addr("192.168.124.41"), 0, 0) < 0)
		PAL_PANIC("ipg add ip failed\n");

	g_ipg = pal_ipg_create("l4hash2", test_pkt_handler, 
		                  IPG_DIST_PPL_4TUPHASH, workers, 
		                  3, 0, PAL_IPG_F_HANDLEICMP | PAL_IPG_F_HANDLEUNKNOWIPPROTO);
	if (g_ipg == NULL) {
		PAL_PANIC("ipg create failed\n");
	}
	if (pal_ipg_add_ip(g_ipg, inet_addr("192.168.124.42"), 0, 0) < 0)
		PAL_PANIC("ipg add ip failed\n");
}

static void __unused ipg_rtc_rss_test(void)
{
	struct pal_ipgroup    *ipg;
	//int workers[PAL_MAX_THREAD];

	ipg = pal_ipg_create("rtc_rss", test_pkt_handler, 
		                  IPG_DIST_RTC, NULL, 
		                  0, 0, 0);
	if (ipg == NULL) {
		PAL_PANIC("ipg create failed\n");
	}
	if (pal_ipg_add_ip(ipg, inet_addr("192.168.124.5"), 0, 0) < 0)
		PAL_PANIC("ipg add ip failed\n");
}

static void __unused ipg_rtc_fdir_test(void)
{
	struct pal_ipgroup    *ipg;
	int workers[PAL_MAX_THREAD];

	workers[0] = 3;
	ipg = pal_ipg_create("rtc_fdir", test_pkt_handler, 
		                  IPG_DIST_RTC, workers, 
		                  1, 0, 0);
	if (ipg == NULL) {
		PAL_PANIC("ipg create failed\n");
	}

	if (pal_ipg_add_ip(ipg, inet_addr("192.168.124.6"), 0, 0) < 0)
		PAL_PANIC("ipg add ip failed\n");

	workers[0] = 4;
	ipg = pal_ipg_create("rtc_fdir", test_pkt_handler, 
		                  IPG_DIST_RTC, workers, 
		                  1, 0, 0);
	if (ipg == NULL) {
		PAL_PANIC("ipg create failed\n");
	}

	if (pal_ipg_add_ip(ipg, inet_addr("192.168.124.7"), 0, 0) < 0)
		PAL_PANIC("ipg add ip failed\n");
}

static void __unused slab_test(void)
{
	const int cnt = 1024;
	const int size = 1024 * 8;
	int i, j;
	struct pal_slab *slab;
	void *elem[cnt];

	slab = pal_slab_create("test slab", cnt, size, 1, 0);
	if (slab == NULL) {
		PAL_PANIC("slab create failed\n");
	}

	elem[0] = pal_slab_alloc(slab);
	if (elem[0] == NULL)
		PAL_PANIC("alloc one elem failed\n");
	memset(elem[0], 0, size);
	pal_slab_free(elem[0]);

	for (j = 0; j < 10; j++) {
		PAL_LOG("alloced %d times\n", j);
		if (pal_slab_alloc_bulk(slab, elem, cnt) < 0)
			PAL_PANIC("alloc bulk failed\n");
		for (i = 0; i < cnt; i++) {
			memset(elem[i], 0, size);
			pal_slab_free(elem[i]);
		}
	}

	PAL_PANIC("slab test passed\n");
}

static int multi_thread_malloc_test(__unused void *arg)
{
	const int size = 8 * 1024;
	int i;
	void *mem;

	for (i = 0; i < 1000; i++) {
		PAL_LOG("thread %d running %d pass\n", pal_thread_id(), i);
		mem = pal_malloc(size);
		if (mem == NULL)
			PAL_PANIC("alloc failed\n");
		memset(mem, 0, size);
		pal_free(mem);
	}

	return 0;
}

static void __unused heap_test(void)
{
	const int size = 8 * 1024;
	int tid;
	void *mem;

	mem = pal_malloc(size);
	if (mem == NULL)
		PAL_PANIC("alloc failed\n");
	memset(mem, 0, size);
	pal_free(mem);

	PAL_FOR_EACH_THREAD(tid) {
		pal_remote_launch(multi_thread_malloc_test, NULL, tid);
	}
	pal_wait_all_threads();

	PAL_PANIC("heap test passed\n");
}

static void timer_test_func(unsigned long data)
{
	struct timer_list *timer = (struct timer_list *)data;

	PAL_LOG("timer in thread %d, timer %lu\n", pal_thread_id(), get_ms());
	mod_timer(timer, jiffies + HZ * 123 / 1000);
}

static int timer_test_init(__unused void *arg)
{
	static PAL_DEFINE_PER_THREAD(struct timer_list, _timer);

	init_timer(&PAL_PER_THREAD(_timer));
	PAL_PER_THREAD(_timer).function = timer_test_func;
	PAL_PER_THREAD(_timer).expires = jiffies + HZ * 3;
	PAL_PER_THREAD(_timer).data = (unsigned long)&PAL_PER_THREAD(_timer);

	PAL_LOG("timer test init in thread %d, timer %lu\n", pal_thread_id(), get_ms());

	add_timer(&PAL_PER_THREAD(_timer));
	//add_timer(&timer);

	return 0;
}

static void __unused timer_test(void)
{
	int tid;

	PAL_FOR_EACH_THREAD(tid) {
		pal_remote_launch(timer_test_init, NULL, tid);
	}
	pal_wait_all_threads();
}

static int thread_test_func(__unused void *data)
{
	PAL_LOG("from thread %d\n", pal_thread_id());
	sleep(pal_thread_id() + 1);
	PAL_LOG("end from thread %d\n", pal_thread_id());

	return 0;
}

static void __unused thread_test(void)
{
	int tid;

	PAL_FOR_EACH_THREAD(tid) {
		pal_remote_launch(thread_test_func, NULL, tid);
	}
	pal_wait_all_threads();

	PAL_LOG("all thread stopped\n");
	
}

static void build_tcp_header(struct sk_buff *skb)
{
	struct tcp_hdr *th;

	th = skb_tcp_header(skb);
	memset(th, 0, sizeof(*th));
	th->ack = pal_htonl(12345678);
	th->seq = pal_htonl(87654321);
	th->source = pal_htons(12345);
	th->dest = pal_htons(54321);
	th->doff = 5;
	th->ack = 1;
	th->window = pal_htons(2468);
}

static void build_ip_header(struct sk_buff *skb, uint8_t proto)
{
	struct ip_hdr *ip;

	ip = skb_ip_header(skb);
	memset(ip, 0, sizeof(*ip));
	ip->version = 4;
	ip->ihl = 5;
	ip->tot_len = pal_htons(skb_len(skb));
	ip->id = pal_htons(pal_thread_id());
	ip->ttl = 64;
	ip->protocol = proto;
	ip->saddr = inet_addr("192.168.124.3");
	ip->daddr = inet_addr("192.168.123.3");
}

static void __unused build_and_send_tcp(void)
{
	static PAL_DEFINE_PER_THREAD(int, count) = 0;
	struct sk_buff *skb;
	struct pal_slab *slab = PAL_PER_THREAD(_skb_slab);

	PAL_PER_THREAD(count)++;
	skb = pal_skb_alloc(slab);
	if (skb == NULL) {
		PAL_LOG("alloc tcp %d skb failed\n", PAL_PER_THREAD(count));
	}

	skb_append(skb, 200);
	memset(skb_data(skb), 'a', 50);
	memset((uint8_t *)skb_data(skb) + 50, 'b', 50);
	memset((uint8_t *)skb_data(skb) + 100, 'c', 50);
	memset((uint8_t *)skb_data(skb) + 150, 'd', 50);

	skb_push(skb, sizeof(struct tcp_hdr));
	skb_reset_l4_header(skb);
	build_tcp_header(skb);

	skb_push(skb, sizeof(struct ip_hdr));
	skb_reset_network_header(skb);
	build_ip_header(skb, PAL_IPPROTO_TCP);

	skb_iptcp_csum_offload(skb, skb_ip_header(skb)->saddr, 
		skb_ip_header(skb)->daddr, 200 + sizeof(struct tcp_hdr), 20);

	skb_set_dump(skb);

	if (pal_send_pkt(skb, 0) < 0) {
		PAL_PANIC("send failed in thread %d\n", pal_thread_id());
	}

	if (PAL_PER_THREAD(count) % 100000 == 0)
		PAL_LOG("sent %d packets\n", PAL_PER_THREAD(count));
}

static void build_udp_header(struct sk_buff *skb)
{
	struct udp_hdr *uh;

	uh = skb_udp_header(skb);
	memset(uh, 0, sizeof(*uh));
	uh->source = pal_htons(12345);
	uh->dest = pal_htons(54321);
	uh->len = pal_htons(200 + sizeof(*uh));
}

static void __unused build_and_send_udp(void)
{
	static PAL_DEFINE_PER_THREAD(int, count) = 0;
	struct sk_buff *skb;
	struct pal_slab *slab = PAL_PER_THREAD(_skb_slab);

	PAL_PER_THREAD(count)++;
	skb = pal_skb_alloc(slab);
	if (skb == NULL) {
		PAL_LOG("alloc udp %d skb failed\n", PAL_PER_THREAD(count));
	}

	skb_append(skb, 200);
	memset(skb_data(skb), 'a', 50);
	memset((uint8_t *)skb_data(skb) + 50, 'b', 50);
	memset((uint8_t *)skb_data(skb) + 100, 'c', 50);
	memset((uint8_t *)skb_data(skb) + 150, 'd', 50);

	skb_push(skb, sizeof(struct udp_hdr));
	skb_reset_l4_header(skb);
	build_udp_header(skb);

	skb_push(skb, sizeof(struct ip_hdr));
	skb_reset_network_header(skb);
	build_ip_header(skb, PAL_IPPROTO_UDP);

	skb_ipudp_csum_offload(skb, skb_ip_header(skb)->saddr, 
		skb_ip_header(skb)->daddr, 200 + sizeof(struct udp_hdr), 20);

	if (pal_send_pkt(skb, 0) < 0) {
		PAL_PANIC("send failed in thread %d\n", pal_thread_id());
	}

	if (PAL_PER_THREAD(count) % 100000 == 0)
		PAL_LOG("sent %d packets\n", PAL_PER_THREAD(count));
}

static void __unused tcpudp_test_timer(unsigned long data)
{
	int i;
	struct timer_list *timer = (struct timer_list *)data;

	for (i = 0; i < 1; i++) {
		build_and_send_tcp();
		//build_and_send_udp();
	}
	mod_timer(timer, jiffies + 100);
}

static int tcp_timer_init(__unused void *arg)
{
	char name[32];
	static PAL_DEFINE_PER_THREAD(struct timer_list, _timer);

	if (pal_thread_id() != 0)
		return 0;

	sprintf(name, "skb_slab_%d", pal_thread_id());
	PAL_PER_THREAD(_skb_slab) = pal_skb_slab_create(name, 1100);
	if (PAL_PER_THREAD(_skb_slab) == NULL) {
		PAL_PANIC("create skb slab for thread %d failed\n", pal_thread_id());
	}

	init_timer(&PAL_PER_THREAD(_timer));
	PAL_PER_THREAD(_timer).function = tcpudp_test_timer;
	PAL_PER_THREAD(_timer).expires = jiffies + HZ * 3;
	PAL_PER_THREAD(_timer).data = (unsigned long)&PAL_PER_THREAD(_timer);
	PAL_LOG("thread %d ready to send packets!!!!!!!!!!\n", pal_thread_id());

	add_timer(&PAL_PER_THREAD(_timer));

	return 0;
}

static void __unused tcp_send_test(void)
{
	int tid;

	PAL_FOR_EACH_THREAD (tid) {
		pal_remote_launch(tcp_timer_init, NULL, tid);
	}
	pal_wait_all_threads();
}


#if 1
int main(__unused int argc, __unused char * argv[])
{
	struct pal_config     palconf;
	const int custom_cpu = 5;

	/* pal config memory init */
	pal_conf_init(&palconf);

	palconf.mem_channel = 4;

	/* TODO, worker core assignment should be read from bgw.conf */

	/*
	 *  numa0: 0-4 worker, 5 reveiver
	 *  numa1: 6-9 worker, 10 receiver, 11 custom
	 */

	/* worker and receiver */
	palconf.thread[0].mode = PAL_THREAD_WORKER;
	palconf.thread[0].cpu = 0;
	sprintf(palconf.thread[0].name, "worker@0");

	palconf.thread[1].mode = PAL_THREAD_WORKER;
	palconf.thread[1].cpu = 1;
	sprintf(palconf.thread[1].name, "worker@1");

	palconf.thread[2].mode = PAL_THREAD_WORKER;
	palconf.thread[2].cpu = 2;
	sprintf(palconf.thread[2].name, "worker@2");

	palconf.thread[3].mode = PAL_THREAD_RECEIVER;
	palconf.thread[3].cpu = 3;
	palconf.thread[4].mode = PAL_THREAD_RECEIVER;
	palconf.thread[4].cpu = 4;

	/* ctl thread */
	palconf.thread[5].mode = PAL_THREAD_CUSTOM;
	palconf.thread[5].func = custom1;
	palconf.thread[5].arg = NULL;
	palconf.thread[5].cpu = custom_cpu;
	//strcpy(palconf.thread[5].name, "pal_ctl");

	/* mon thread */
	palconf.thread[6].mode = PAL_THREAD_CUSTOM;
	palconf.thread[6].func = custom2;
	palconf.thread[6].arg = NULL;
	palconf.thread[6].cpu = custom_cpu;
	//strcpy(palconf.thread[6].name, "pal_mon_13");

	/* arp thread */
	palconf.thread[7].mode = PAL_THREAD_ARP;
	palconf.thread[7].cpu = custom_cpu;

	/* vnic thread */
	palconf.thread[8].mode = PAL_THREAD_VNIC;
	palconf.thread[8].cpu = custom_cpu;

	/* port conf set, port0 is ul port, port1 is dl port */
	palconf.port[0].ip = inet_addr("192.168.124.2");
	palconf.port[0].gw_ip = inet_addr("192.168.124.1");
	palconf.port[0].netmask = inet_addr("255.255.255.0");
	//palconf.port[1].ip = inet_addr("192.168.234.2");
	//palconf.port[1].gw_ip = inet_addr("192.168.234.1");
	//palconf.port[1].netmask = inet_addr("255.255.255.0");

	pal_init(&palconf);

	PAL_LOG("totlly %u ports\n", pal_phys_port_count());

	/* kpd ipgroup set */
	ipg_single_test();
	ipg_l4hash_test();
	ipg_rtc_rss_test();
	ipg_rtc_fdir_test();

	/* heap/slab test */
	//slab_test();
	//heap_test();
	//timer_test();
	//thread_test();
	//tcp_send_test();

	pal_ipg_dump();

	/* threads start*/
	pal_start();

	return 0;
}

#else

#include <pal_route.h>
int route_add_connected(struct route_table *t, uint32_t prefix, uint32_t prefixlen, 
				uint32_t sip);
int main(void)
{
	uint32_t ip;
	struct route_table *rt;
	struct fib_result res;

	rt = pal_rtable_new();
	if (rt == NULL)
		PAL_PANIC("rtable failed\n");

	if (route_add_connected(rt, inet_addr("192.168.1.0"), 24, inet_addr("192.168.1.2")) < 0) {
		PAL_PANIC("add route failed\n");
	}

	if (pal_route_add(rt, inet_addr("10.0.0.0"), 8, inet_addr("192.168.1.1")) < 0)
		PAL_PANIC("add route failed\n");

	if (pal_route_add(rt, inet_addr("10.0.0.0"), 24, inet_addr("192.168.1.3")) < 0)
		PAL_PANIC("add route failed\n");

	if (pal_route_add(rt, inet_addr("10.0.1.0"), 24, inet_addr("192.168.1.4")) < 0)
		PAL_PANIC("add route failed\n");

	if (pal_route_add(rt, inet_addr("0.0.0.0"), 0, inet_addr("192.168.1.88")) < 0)
		PAL_PANIC("add route failed\n");

	pal_trie_dump(rt);


	ip = inet_addr("1.2.3.10");
	if (pal_route_lookup(rt, ip, &res) < 0) {
		PAL_PANIC("lookup route failed\n");
	}
	printf("nexthop to addr "NIPQUAD_FMT" is "NIPQUAD_FMT"\n", 
			NIPQUAD(ip), NIPQUAD(res.next_hop));


	ip = inet_addr("192.168.1.56");
	if (pal_route_lookup(rt, ip, &res) < 0) {
		PAL_PANIC("lookup route failed\n");
	}
	printf("nexthop to addr "NIPQUAD_FMT" is "NIPQUAD_FMT"\n", 
			NIPQUAD(ip), NIPQUAD(res.next_hop));

	return 0;
}
#endif
