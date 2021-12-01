#include "uns_proto.h"


static _u16 tcp_get_payload_len(struct tcp_packet* tcp)
{
    _u16 tcp_len = ntohs(tcp->ip.total_len) - tcp->ip.header_len*4;  // ip数据报总长度减去ip首部长度得到TCP报文长度
    return tcp_len - tcp->tcp.header_len*4;       // 减掉TCP首部长度就是紧跟其后的实体数据长度
}

static struct tcb* tcp_new_tcb(struct tcp_packet* packet)
{
    struct tcb* new_conn_tcb = (struct tcb*)malloc(sizeof(struct tcb));
    if(!new_conn_tcb)
    {
        log("malloc new_conn_tcb failed.\n");
        return NULL;
    }

    memset(new_conn_tcb, 0, sizeof(struct tcb));
    new_conn_tcb->remote_ip = packet->ip.src_ip;
    new_conn_tcb->local_ip = packet->ip.dst_ip;
    new_conn_tcb->remote_port = packet->tcp.src_port;
    new_conn_tcb->local_port = packet->tcp.dst_port;
    new_conn_tcb->win_size = TCP_MAX_WIN_SIZE;
    return new_conn_tcb;
}

// 将一个半连接队列的连接转移到全连接队列
static int tcp_handle_to_estb(struct nm_desc *nmr, struct tcp_packet* tcp, struct tcb* tcb)
{
    _u32 recv_seq_num = ntohl(tcp->tcp.seq_num);
    _u32 recv_ack_num = ntohl(tcp->tcp.ack_num);

    // 加调试打印
    log("tcp_handle_to_estb from ");print_mac(tcp->eth.src_mac);
    log("(");print_ip(tcp->ip.src_ip);log(")\n");

    if(recv_ack_num != tcb->ack_recv_next)
    {
        log("tcp_handle_to_estb error: recv_ack_num[%d] != tcb->seq_num[%d].\n", recv_ack_num, tcb->seq_num);
        free(tcb);
        return -1;
    }

    // 数据没问题，完成三次握手，进入全连接队列
    add_tcb_to_estb_queue(tcb);
    tcb->status = TCP_STATUS_ESTABLISHED;
    return 0;
}

static int tcp_handle_last_ack(struct tcp_packet* tcp, struct tcb* tcb)
{
    // 加调试打印
    log("tcp_handle_last_ack to ");print_mac(tcp->eth.src_mac);
    log("(");print_ip(tcp->ip.src_ip);log(")\n");

    if(ntohl(tcp->tcp.ack_num) == tcb->ack_recv_next)
    {
        take_tcb_from_estb_queue(tcb);
        free(tcb);
        return 0;
    }
    return -1;
}

/* 对发起 SYN 的新连接的回复 SYN ACK */
static int tcp_handle_to_rcvd(struct nm_desc *nmr, struct tcp_packet* tcp, struct tcb* tcb)
{
    // 加调试打印
    log("tcp_handle_to_rcvd with ");print_mac(tcp->eth.src_mac);
    log("(");print_ip(tcp->ip.src_ip);log(")\n");

    tcb->seq_num = 0;
    tcb->ack_num = ntohl(tcp->tcp.seq_num) + 1;
    tcb->ack_recv_next = tcb->seq_num + 1;    // 下一次接收的 ACK 应该是 + 1（由SYN消耗）
    tcb->ip_id = tcp->ip.id;

    struct tcp_flags flags = {0};
    flags.ack = 1;
    flags.syn = 1;

    struct eth_header eth = {0};
    memcpy(eth.src_mac, tcp->eth.dst_mac, ETH_LEN);
    memcpy(eth.dst_mac, tcp->eth.src_mac, ETH_LEN);
    eth.proto = tcp->eth.proto;

    tcp_handle_estb_send(nmr, tcb, &flags, &eth, NULL, 0);

    tcb->status = TCP_STATUS_SYN_REVD;
    return 0;
}

/* TCP发送数据 */
int tcp_handle_estb_send(struct nm_desc *nmr, struct tcb* tcb, struct tcp_flags* flags, struct eth_header* eth, 
                                _u8* sendbuf, _u16 tcp_datalen)
{
    struct tcp_packet* tcp = (struct tcp_packet*)malloc(sizeof(struct tcp_packet) + tcp_datalen);
    if(tcp == NULL)
    {
        log("[%d]malloc tcp failed.\n", __LINE__);
        return -1;  // 暂时先直接返回
    }
    memset(tcp, 0, sizeof(struct tcp_packet));

    // TCP头部与数据
    tcp->tcp.src_port = tcb->local_port;
    tcp->tcp.dst_port = tcb->remote_port;
    tcp->tcp.header_len = sizeof(struct tcp_header)/4;
    tcp->tcp.ack = flags->ack;
    tcp->tcp.fin = flags->fin;
    tcp->tcp.rst = flags->rst;
    tcp->tcp.syn = flags->syn;
    tcp->tcp.psh = flags->psh;

    tcp->tcp.seq_num = htonl(tcb->seq_num);
    tcp->tcp.ack_num = htonl(tcb->ack_num);

    tcp->tcp.win_size = htons(tcb->win_size);
    if(tcp_datalen > 0 && sendbuf != NULL)
        memcpy(tcp->payload, sendbuf, tcp_datalen); // 数据拷贝过来
    tcp->tcp.check = tcp_udp_calculate_checksum((_u16*)&tcp->tcp, sizeof(struct tcp_header) + tcp_datalen, 
                                                            tcb->remote_ip, tcb->local_ip, IPPROTO_TCP);    // 校验包括数据
    
    // IP 头部
    _u16 tcp_send_len = sizeof(struct tcp_header) + tcp_datalen; // ip报文长度包括 TCP头部和 数据长度
    ip_enpack_header(&tcp->ip, tcb->ip_id, IPPROTO_TCP, tcp_send_len, tcb->local_ip, tcb->remote_ip);
    
    // ETH 头部
    memcpy(tcp->eth.src_mac, eth->src_mac, ETH_LEN);
    memcpy(tcp->eth.dst_mac, eth->dst_mac, ETH_LEN);
    tcp->eth.proto = eth->proto;

    nm_inject(nmr, tcp, sizeof(struct tcp_packet) + tcp_datalen);

    free(tcp);
}

/* 建立连接后 接受数据的处理，此处目前简单地将接收到数据回传 */
int tcp_handle_estb_recv(struct nm_desc *nmr, struct tcp_packet* tcp, struct tcb* tcb)
{
    _u16 tcp_datalen = tcp_get_payload_len(tcp);
    int add_ack_len = (tcp->tcp.syn || tcp->tcp.fin) ? 1:0;

    // 加调试打印
    log("tcp_handle_estb_recv tcp(datalen=%d) from ", tcp_datalen);print_mac(tcp->eth.src_mac);
    log("(");print_ip(tcp->ip.src_ip);log(")\ndata: %s\n", tcp_datalen>0?tcp->payload:NULL);

    _u32 recv_seq_num = ntohl(tcp->tcp.seq_num);
    tcb->ack_num = recv_seq_num + tcp_datalen + add_ack_len;
    tcb->seq_num = ntohl(tcp->tcp.ack_num);
    tcb->ack_recv_next = tcb->seq_num + tcp_datalen + tcp->tcp.fin;  // 如果有 fin 则会消耗一个 seq
    tcb->ip_id = tcp->ip.id;

    struct tcp_flags flags = {0};
    flags.ack = 1;
    flags.fin = tcp->tcp.fin;   // 对端发 fin 我们也立即回 fin
    flags.psh = 1;

    struct eth_header eth = {0};
    memcpy(eth.src_mac, tcp->eth.dst_mac, ETH_LEN);
    memcpy(eth.dst_mac, tcp->eth.src_mac, ETH_LEN);
    eth.proto = tcp->eth.proto;

    // 此处目前简单地将接收到的数据回传
    tcp_handle_estb_send(nmr, tcb, &flags, &eth, tcp->payload, tcp_datalen);

    // 如果收到 fin ，要改变状态机
    if(tcp->tcp.fin)
    {
        // tcb->status = TCP_STATUS_CLOSE_WAIT;
        tcb->status = TCP_STATUS_LAST_ACK;  // 此处我们跳过 CLOSE_WAIT 直接到 LAST_ACK
    }

    return 0;
}

int tcp_process(struct nm_desc *nmr, _u8* stream)
{
    struct tcp_packet* tcp = (struct tcp_packet*)stream;

    // 此处提取数据长度, 加个调试打印
    _u16 tcp_datalen = tcp_get_payload_len(tcp);
    log("recv tcp(datalen=%d, SYN[%d] ACK[%d] FIN[%d] PSH[%d]) from ", tcp_datalen, tcp->tcp.syn, tcp->tcp.ack, tcp->tcp.fin, tcp->tcp.psh);
    print_mac(tcp->eth.src_mac);log("(");print_ip(tcp->ip.src_ip);log(")\n");

    /* 1 - 有 SYN 标志，则表明是一个新的连接 */
    if(tcp->tcp.syn)
    {
        // 1.1 新建一个 tcb 
        struct tcb* tcb= tcp_new_tcb(tcp);
        if(tcb == NULL)
            return -1;
        // 1.2 回复 SYN ACK 并挂到半连接队列
        tcp_handle_to_rcvd(nmr, tcp, tcb);
        add_tcb_to_rcvd_queue(tcb);
        return 0;
    }

    /* 2 - 非新连接，先到半连接队列中找，后到全连接队列中找 */
    struct tcb* tcb = search_tcb(tcp->ip.src_ip, tcp->ip.dst_ip, tcp->tcp.src_port, tcp->tcp.dst_port);
    if(tcb == NULL)
    {   // 没有则出错
        log("search_tcb error, tcb not exists...\n");
        return -1;
    }

    /* 3 - 按状态机处理 */
    switch (tcb->status)
    {
        case TCP_STATUS_SYN_REVD:
            tcp_handle_to_estb(nmr, tcp, tcb);
            break;

        case TCP_STATUS_ESTABLISHED:
            tcp_handle_estb_recv(nmr, tcp, tcb);
            break;
        
        case TCP_STATUS_CLOSE_WAIT:
            
            break;

        case TCP_STATUS_LAST_ACK:
            // 接收到最后一个 ack ，将连接的 tcb 删除
            tcp_handle_last_ack(tcp, tcb);
            break;
        
        default:
            break;
    }

    return 0;
}
