#include "uns_proto.h"

int udp_handle_send(struct nm_desc *nmr, struct ucb* ucb, struct eth_header* eth, _u8* sendbuf, _u16 datalen)
{
    struct udp_packet* udp = (struct udp_packet*)malloc(sizeof(struct udp_packet) + datalen);
    if(udp == NULL)
    {
        log("malloc udp failed.\n");
        return -1;
    }
    memset(udp, 0, sizeof(struct udp_packet));

    // UDP 头部和数据
    udp->udp.src_port = ucb->local_port;
    udp->udp.dst_port = ucb->remote_port;
    udp->udp.length = htons(sizeof(struct udp_header) + datalen);
    memcpy(udp->payload, sendbuf, datalen);
    udp->udp.check = tcp_udp_calculate_checksum((_u16*)&udp->udp, sizeof(struct udp_header) + datalen, 
                                                    ucb->remote_ip, ucb->local_ip, IPPROTO_UDP);    // 校验包括数据

    // IP头部
    ip_enpack_header(&udp->ip, ucb->ip_id, IPPROTO_UDP, sizeof(struct udp_header) + datalen, ucb->local_ip, ucb->remote_ip);

    // ETH 头部
    memcpy(udp->eth.src_mac, eth->src_mac, ETH_LEN);
    memcpy(udp->eth.dst_mac, eth->dst_mac, ETH_LEN);
    udp->eth.proto = eth->proto;

    nm_inject(nmr, udp, sizeof(struct udp_packet) + datalen);

    free(udp);
    return 0;
}

int udp_handle_recv(struct nm_desc *nmr, struct udp_packet* udp)
{
    struct ucb ucb = {0};
    ucb.remote_ip = udp->ip.src_ip;
    ucb.local_ip = udp->ip.dst_ip;
    ucb.remote_port = udp->udp.src_port;
    ucb.local_port = udp->udp.dst_port;
    ucb.ip_id = udp->ip.id;

    struct eth_header eth = {0};
    memcpy(eth.src_mac, udp->eth.dst_mac, ETH_LEN);
    memcpy(eth.dst_mac, udp->eth.src_mac, ETH_LEN);
    eth.proto = udp->eth.proto;

    // 此处目前简单地将接收到的数据回传
    udp_handle_send(nmr, &ucb, &eth, udp->payload, ntohs(udp->udp.length) - sizeof(struct udp_header));

    return 0;
}

int udp_process(struct nm_desc *nmr, _u8* stream)
{
    struct udp_packet* udp = (struct udp_packet*)stream;  // 直接取出整个UDP协议下三层的所有首部

    // 调试打印
    log("udp recv payload[len=%lu]: %s\n", ntohs(udp->udp.length) - sizeof(struct udp_header), udp->payload);

    udp_handle_recv(nmr, udp);

    return 0;
}
