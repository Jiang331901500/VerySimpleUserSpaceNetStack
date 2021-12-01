/* definition about control-block */

#ifndef __UNS_CB_H__
#define __UNS_CB_H__
#include "uns_common.h"

struct tcb  // tcp 控制块
{
    struct tcb* next;
    _u32 remote_ip;
    _u32 local_ip;
    _u16 remote_port;
    _u16 local_port;

    int status;
    _u8* recv_buf;
    _u8* send_buf;

    _u32 seq_num;   // 本次发送时的 seq，等于上次发送的 seq + 本次发送的 data length (SYN、RST、FIN 占 1)（没有数据则等于本次接受到的 ack）
    _u32 ack_num;   // 本次发送时的 ack，等于本次接收到的 seq + 本次接收的 data length (SYN、RST、FIN 占 1)
    _u32 ack_recv_next;  // 下一次接收时应该收到的正确 ack，等于本次发送时的 seq + 本次发送的 data length (SYN、RST、FIN 占 1)
    _u16 win_size;
    _u16 ip_id;     // ip数据报id
};

struct tcb_queue
{
    struct tcb* head;
    _u32 size;
};

struct ucb
{
    _u32 remote_ip;
    _u32 local_ip;
    _u16 remote_port;
    _u16 local_port;

    _u16 ip_id;
    _u16 res;
};

struct tcb* search_tcb(_u32 remote_ip, _u32 local_ip, _u16 remote_port, _u16 local_port);
int add_tcb_to_rcvd_queue(struct tcb* tcb);
int add_tcb_to_estb_queue(struct tcb* tcb);
struct tcb* find_tcb_in_rcvd_queue(_u32 remote_ip, _u32 local_ip, _u16 remote_port, _u16 local_port);
struct tcb* find_tcb_in_estb_queue(_u32 remote_ip, _u32 local_ip, _u16 remote_port, _u16 local_port);
int take_tcb_from_rcvd_queue(struct tcb* tcb);
int take_tcb_from_estb_queue(struct tcb* tcb);

#endif