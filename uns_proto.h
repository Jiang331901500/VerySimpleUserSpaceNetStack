/* definition about protocol headers and API functions*/

#ifndef __UNS_PROTO_H__
#define __UNS_PROTO_H__

#include <arpa/inet.h>
#include "uns_common.h"
#define NETMAP_WITH_LIBS    // 使用netmap必须加上
#include <net/netmap_user.h> 
#include "uns_cb.h"

/* ---------------------- ETH ---------------------- */
#define ETH_LEN 6
#define PROTO_IP	0x0800
#define PROTO_ARP	0x0806
struct eth_header
{
    _u8 dst_mac[ETH_LEN];
    _u8 src_mac[ETH_LEN];
    _u16 proto;
} __attribute__ ((packed));
/* ---------------------- ETH END ---------------------- */

/* ---------------------- ARP ---------------------- */
#define IP_LEN 4
enum arp_op {
	arp_op_request = 1,
	arp_op_reply = 2,
};
struct arp_header
{
    _u16 hw_type;
    _u16 proto_type;
    _u8 hw_addr_len;
    _u8 proto_addr_len;
    _u16 op;
    _u8 src_mac[ETH_LEN];
    _u32 src_ip;
    _u8 dst_mac[ETH_LEN];
    _u32 dst_ip;
} __attribute__ ((packed));

struct arp_packet
{
    struct eth_header eth;
    struct arp_header arp;
} __attribute__ ((packed));

int arp_process(struct nm_desc *nmr, _u8* stream, _u8* localmac, _u32 localip);
/* ---------------------- ARP END ---------------------- */

/* ---------------------- IP ---------------------- */
struct ip_header
{
    _u8 header_len : 4, // 在大端字节序下，首部长度是低4位，版本是高4位
        version : 4;
    _u8 tos;
    _u16 total_len;
    _u16 id;
    _u16 flag_off;
    _u8 ttl;
    _u8 proto;
    _u16 header_check;
    _u32 src_ip;
    _u32 dst_ip;
} __attribute__ ((packed));

#define IP_FLAG_NOT_FRAGMENT    (1<<14) // flag_off 指示数据包不分片：1 - 不分片
#define IP_FLAG_MORE_FRAGMENT   (1<<13) // flag_off 指示是否有更多分片：1 - 有更多分片

struct ip_packet
{
    struct eth_header eth;
    struct ip_header ip;
} __attribute__ ((packed));

int ip_process(struct nm_desc *nmr, _u8* stream);
int ip_enpack_header(struct ip_header* ip, _u16 id, _u8 proto, _u16 send_len, _u32 src_ip, _u32 dst_ip);
/* ---------------------- IP END ---------------------- */

/* ---------------------- UDP ---------------------- */
struct udp_header
{
    _u16 src_port;
    _u16 dst_port;
    _u16 length;
    _u16 check;
} __attribute__ ((packed));

struct udp_packet
{
    struct eth_header eth;
    struct ip_header ip;
    struct udp_header udp;
    _u8 payload[0]; // 柔性数组
} __attribute__ ((packed));

int udp_process(struct nm_desc *nmr, _u8* stream);
int udp_handle_recv(struct nm_desc *nmr, struct udp_packet* udp);
int udp_handle_send(struct nm_desc *nmr, struct ucb* ucb, struct eth_header* eth, _u8* sendbuf, _u16 datalen);
/* ---------------------- UDP END ---------------------- */

/* ---------------------- ICMP ---------------------- */
struct icmp_header
{
    _u8 type;
    _u8 code;
    _u16 checkSum;
} __attribute__ ((packed));

struct icmp_packet
{
    struct eth_header eth;
    struct ip_header ip; 
    struct icmp_header icmp;
} __attribute__ ((packed));

struct icmp_ping_header
{
    struct icmp_header icmp;
    _u16 identifier;
    _u16 seq;
    _u8 data[0];
} __attribute__ ((packed));

struct icmp_ping_packet
{
    struct eth_header eth;
    struct ip_header ip; 
    struct icmp_ping_header icmp_ping;
} __attribute__ ((packed));

int icmp_process(struct nm_desc *nmr, _u8* stream);
/* ---------------------- ICMP END ---------------------- */

/* ---------------------- TCP ---------------------- */
struct tcp_header
{
    _u16 src_port;
    _u16 dst_port;
    _u32 seq_num;
    _u32 ack_num;
    _u16 res1 : 4,
         header_len : 4,
         fin : 1,
         syn : 1,
         rst : 1,
         psh : 1,
         ack : 1,
         urg : 1,
         res2 : 2;
    _u16 win_size;
    _u16 check;
    _u16 urg_ptr;
} __attribute__ ((packed));

struct tcp_flags
{
    _u8 fin : 1,
    syn : 1,
    rst : 1,
    psh : 1,
    ack : 1,
    urg : 1,
    res2 : 2;
};

enum _tcp_status
{
	TCP_STATUS_CLOSED,
	TCP_STATUS_LISTEN,
	TCP_STATUS_SYN_REVD,
	TCP_STATUS_SYN_SENT,
	TCP_STATUS_ESTABLISHED,
	TCP_STATUS_FIN_WAIT_1,
	TCP_STATUS_FIN_WAIT_2,
	TCP_STATUS_CLOSING,
	TCP_STATUS_TIME_WAIT,
	TCP_STATUS_CLOSE_WAIT,
	TCP_STATUS_LAST_ACK,
};

struct tcp_packet
{
    struct eth_header eth;
    struct ip_header ip;
    struct tcp_header tcp;
    _u8 payload[0];
} __attribute__ ((packed));

int tcp_process(struct nm_desc *nmr, _u8* stream);
int tcp_handle_estb_recv(struct nm_desc *nmr, struct tcp_packet* tcp, struct tcb* tcb);
int tcp_handle_estb_send(struct nm_desc *nmr, struct tcb* tcb, struct tcp_flags* flags, struct eth_header* eth, 
                                _u8* sendbuf, _u16 tcp_datalen);
/* ---------------------- TCP END ---------------------- */

void print_mac(_u8* mac);
void print_ip(_u32 ip);
int str2mac(_u8* mac, char* macstr);
_u16 ip_header_calculate_checksum(_u16 *addr, int len);
_u16 tcp_udp_calculate_checksum(_u16 *buf, _u16 len, _u32 saddr, _u32 daddr, _u8 proto);


#endif