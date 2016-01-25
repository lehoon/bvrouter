#ifndef _PAL_PKTDEF_H_
#define _PAL_PKTDEF_H_
#include <stdint.h>

#include "pal_byteorder.h"

#define PAL_ETH_IP	(0x0800)  /* ip protocol type */
#define PAL_ETH_ARP	(0x0806)  /* arp protocol type */

#define PAL_IPPROTO_ICMP	1
#define PAL_IPPROTO_TCP		6
#define PAL_IPPROTO_UDP		17

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		/* Octets in the FCS*/

/* Ethernet header, without 802.1q headr. */
struct eth_hdr {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
} __attribute__((__packed__));

struct ip_hdr {
#ifdef PAL_CONFIG_LITTLE_ENDIAN
	uint8_t		ihl:4,
		version:4;
#elif defined PAL_CONFIG_BIG_ENDIAN
	uint8_t		version:4,
  			ihl:4;
#else
#error	"Please define PAL_CONFIG_LITTLE_ENDIAN or PAL_CONFIG_BIG_ENDIAN" \
        "in pal_conf.h"
#endif
	uint8_t		tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
	/*The options start here. */
}__attribute__((__packed__));

#define PAL_ARPOP_REQUEST	(0x0001)	/* ARP request */
#define PAL_ARPOP_REPLY		(0x0002)	/* ARP reply */

/*
 * @brief struct of arp header
 */
struct arp_hdr {
	uint16_t  ar_hrd;	/* format of hardware address */
	uint16_t  ar_pro;	/* format of protocol address */
	uint8_t   ar_hln;	/* length of hardware address */
	uint8_t   ar_pln;	/* length of protocol address */

	uint16_t  ar_op;	/* ARP opcode (command) */

	uint8_t   src_mac[6];	/* mac address of sender */
	uint32_t  src_ip;	/* ip address of sender */
	uint8_t   dst_mac[6];	/* mac address of receiver */
	uint32_t  dst_ip;	/* ip address of receiver */
}__attribute__((__packed__));

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

static inline int ip_is_fragment(const struct ip_hdr *iph)
{
	return (iph->frag_off & pal_htons(IP_MF | IP_OFFSET)) != 0;
}

static inline void ip_select_ident(struct ip_hdr *iph)
{
	iph->id = pal_htons(pal_ntohs(iph->id) + 1);
}

struct tcp_hdr {
	uint16_t	source;
	uint16_t	dest;
	uint32_t	seq;
	uint32_t	ack_seq;
#if defined(PAL_CONFIG_LITTLE_ENDIAN)
	uint16_t	res1:4,
			doff:4,
			fin:1,
			syn:1,
			rst:1,
			psh:1,
			ack:1,
			urg:1,
			ece:1,
			cwr:1;
#elif defined(PAL_CONFIG_BIG_ENDIAN)
	uint16_t	doff:4,
			res1:4,
			cwr:1,
			ece:1,
			urg:1,
			ack:1,
			psh:1,
			rst:1,
			syn:1,
			fin:1;
#else
#error	"Please define PAL_CONFIG_LITTLE_ENDIAN or PAL_CONFIG_BIG_ENDIAN" \
        "in pal_conf.h"
#endif	

	uint16_t	window;
	uint16_t	check;
	uint16_t	urg_ptr;
}__attribute__((__packed__));

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcp_hdr	hdr;
	uint32_t 	words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = pal_htonl_constant(0x00800000),
	TCP_FLAG_ECE = pal_htonl_constant(0x00400000),
	TCP_FLAG_URG = pal_htonl_constant(0x00200000),
	TCP_FLAG_ACK = pal_htonl_constant(0x00100000),
	TCP_FLAG_PSH = pal_htonl_constant(0x00080000),
	TCP_FLAG_RST = pal_htonl_constant(0x00040000),
	TCP_FLAG_SYN = pal_htonl_constant(0x00020000),
	TCP_FLAG_FIN = pal_htonl_constant(0x00010000),
	TCP_RESERVED_BITS = pal_htonl_constant(0x0F000000),
	TCP_DATA_OFFSET = pal_htonl_constant(0xF0000000)
};

#define TCP_APRSF_MASK	(TCP_FLAG_ACK | TCP_FLAG_PSH | TCP_FLAG_RST | \
	                 TCP_FLAG_SYN | TCP_FLAG_FIN)
#define TCP_ARSF_MASK	(TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_SYN | TCP_FLAG_FIN)
#define TCP_UAPRSF_MASK	(TCP_FLAG_URG | TCP_FLAG_ACK | TCP_FLAG_PSH | \
                         TCP_FLAG_RST | TCP_FLAG_SYN | TCP_FLAG_FIN)


/*
 *	TCP option
 */
 
#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_MD5SIG         18

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED		12
#define TCPOLEN_WSCALE_ALIGNED		4
#define TCPOLEN_SACKPERM_ALIGNED	4
#define TCPOLEN_SACK_BASE		2
#define TCPOLEN_SACK_BASE_ALIGNED	4
#define TCPOLEN_SACK_PERBLOCK		8
#define TCPOLEN_MD5SIG_ALIGNED		20
#define TCPOLEN_MSS_ALIGNED		4


/*
 * TCP general constants
 */
#define TCP_MSS_DEFAULT		 536U	/* IPv4 (RFC1122, RFC2581) */
#define TCP_MSS_DESIRED		1220U	/* IPv6 (tunneled), EDNS0 (RFC3226) */


struct udp_hdr {
	uint16_t	source;
	uint16_t	dest;
	uint16_t	len;
	uint16_t	check;
}__attribute__((__packed__));


struct icmp_hdr {
	uint8_t		type;
	uint8_t		code;
	uint16_t	checksum;
	union {
		struct {
			uint16_t	id;
			uint16_t	sequence;
		} echo;
		uint32_t	gateway;
		struct {
			uint16_t	__notused;
			uint16_t	mtu;
		} frag;
	} un;

}__attribute__((__packed__));

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

/*
 *@brief This is a version of ip_compute_csum() optimized for IP headers,
 *       which always checksum on 4 octet boundaries.
 *@param iph Ip header pointer.
 *@param ihl Ip header length.
 *@return checksum
 */
static inline uint16_t ip_fast_csum(uint16_t *iph, uint32_t ihl)
{
	uint32_t opt_bytes_num = ihl - sizeof(struct ip_hdr);
	uint16_t *p = iph;
	uint32_t csum = *p++;/* version header tos */
	csum += *p++; /* total length */
	csum += *p++; /* id */
	csum += *p++; /* fragment */
	csum += *p++; /* ttl protocol */
	p++;		  /* check sum */
	csum += *p++; /* source addr high  */
	csum += *p++; /* sourcr addr low */
	csum += *p++; /* destnation addr high */
	csum += *p++; /* destnation addr low */

	while (opt_bytes_num>1){
		csum += *p++;
		opt_bytes_num -= 2;
	}

	if(opt_bytes_num){
		csum += (*(uint8_t *)p); /*set the remain bytes to zero*/
	}

	csum = (csum & (uint32_t)0x0000ffffUL) + (csum>>16);
	csum = (csum & (uint32_t)0x0000ffffUL) + (csum>>16);

	return ~((uint16_t)csum);
}

/*
 * @brief A even fatser version of ip_fast_csum.
 *        This functions differs from ip_fast_csum in the way that it
 *        ignores the option fields. So use this function only when
 *        your ip header does not contain options.
 */
static inline uint16_t ip_fast_fast_csum(uint16_t *iph)
{
	uint16_t *p = iph;
	uint32_t csum = *p++;/* version header tos */

	csum += *p++; /* total length */
	csum += *p++; /* id */
	csum += *p++; /* fragment */
	csum += *p++; /* ttl protocol */
	p++;          /* check sum */
	csum += *p++; /* source addr high  */
	csum += *p++; /* sourcr addr low */
	csum += *p++; /* destnation addr high */
	csum += *p++; /* destnation addr low */

	csum = (csum & (uint32_t)0x0000ffffUL) + (csum>>16);
	csum = (csum & (uint32_t)0x0000ffffUL) + (csum>>16);
	return ~((uint16_t)csum);
}

/*
 * @brief Checks the csum of icmp packets
 * @param start_of_icmp Pointer to the payload of icmp packet
 * @param len Total length of the icmp packet
 * @return 1 if the csum is correct. 0 otherwise.
 */
static inline int icmp_check_sum_correct(uint16_t *start_of_icmp, int len)
{
	uint32_t sum = 0;
	int i;
	int u16_num = len >> 1;
	int last_byte = len & 1;

	for(i = 0; i < u16_num; i++)
	        sum += start_of_icmp[i];

	if(last_byte)
	        sum += *(uint8_t *)(start_of_icmp + i);

	sum = (sum & 0x0000ffff) + (sum >> 16);
	sum += (sum >> 16);
	return ((uint16_t)sum == 0xffff);
}

/*
 * @brief Update the checksum after some fields are changed.
 * @param oldvalinv Inverted old value of the changed field
 * @param newval New value of the changed field.
 * @param oldcheck Old value of checksum
 * @return New value of checksum
 */
static inline uint16_t ip_nat_check(uint32_t oldvalinv, 
                                    uint32_t newval, uint16_t oldcheck)
{
	uint32_t csum = oldcheck ^ 0xFFFF;

	csum += oldvalinv >> 16;
	csum += oldvalinv & 0xFFFF;
	csum += newval >> 16;
	csum += newval & 0xFFFF;

	csum = (csum & 0xFFFFUL) + (csum >> 16);
	csum = (csum & 0xFFFFUL) + (csum >> 16);

	return ~((uint16_t)csum);
}

static inline unsigned pal_compare_ether_addr(const uint8_t *addr1, const uint8_t *addr2)
{
	const uint16_t *a = (const uint16_t *) addr1;
	const uint16_t *b = (const uint16_t *) addr2;

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}

static inline int pal_is_multicast_ether_addr(const uint8_t *addr)
{
	return 0x01 & addr[0];
}

static inline int pal_is_unicast_ether_addr(const uint8_t *addr)
{
	return !pal_is_multicast_ether_addr(addr);
}

static inline int pal_is_broadcast_ether_addr(const uint8_t *addr)
{
	return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}

/**
 * is_zero_ether_addr - Determine if give Ethernet address is all zeros.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is all zeroes.
 */
static inline int pal_is_zero_ether_addr(const uint8_t *addr)
{
	return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}

/**
 * is_valid_ether_addr - Determine if the given Ethernet address is valid
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Check that the Ethernet address (MAC) is not 00:00:00:00:00:00, is not
 * a multicast address, and is not FF:FF:FF:FF:FF:FF.
 *
 * Return true if the address is valid.
 */
static inline int pal_is_valid_ether_addr(const uint8_t *addr)
{
	/* FF:FF:FF:FF:FF:FF is a multicast address so we don't need to
	 * explicitly check for it here. */
	return !pal_is_multicast_ether_addr(addr) && !pal_is_zero_ether_addr(addr);
}

#endif
