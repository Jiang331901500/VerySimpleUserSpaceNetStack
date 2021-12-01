#include "uns_proto.h"

int icmp_process(struct nm_desc *nmr, _u8* stream)
{
    struct icmp_packet* icmp = (struct icmp_packet*)stream;
    _u16 icmp_len = ntohs(icmp->ip.total_len) - icmp->ip.header_len*4;  // ip数据报总长度减去ip首部长度得到ICMP报文长度
    _u16 icmp_datalen = icmp_len - sizeof(struct icmp_ping_header);     // 减掉ICMP首部就是紧跟其后的其他数据长度

    if(icmp->icmp.type == 8)    // 目前只处理ping请求
    {
        // 加个调试打印
        log("recv ping(icmp_len=%d,datalen=%d) from ", icmp_len, icmp_datalen);print_mac(icmp->eth.src_mac);
        log("(");print_ip(icmp->ip.src_ip);log(")\n");

        struct icmp_ping_packet* icmp_ping = (struct icmp_ping_packet*)stream;

        // 由于ICMP报文最后带的数据长度是动态变化的，因此此处动态申请内存
        _u8* icmp_buf = (_u8*)malloc(sizeof(struct icmp_ping_packet) + icmp_datalen);
        if(icmp_buf == NULL)
            return -1;
        
        struct icmp_ping_packet* icmp_ping_ack = (struct icmp_ping_packet*)icmp_buf;
        memcpy(icmp_ping_ack, icmp_ping, sizeof(struct icmp_ping_packet) + icmp_datalen);  // 整个请求包拷贝过来再修改

        icmp_ping_ack->icmp_ping.icmp.code = 0; // 回显代码是0
        icmp_ping_ack->icmp_ping.icmp.type = 0; // 回显类型是0
        icmp_ping_ack->icmp_ping.icmp.checkSum = 0; // 检验和先置位0

        // 源和目的端IP地址互换，调用数据位置并不影响校验和，因此不需要重新计算IP首部校验
        icmp_ping_ack->ip.dst_ip = icmp_ping->ip.src_ip;
        icmp_ping_ack->ip.src_ip = icmp_ping->ip.dst_ip;

        // 源和目的端MAC地址互换
        memcpy(icmp_ping_ack->eth.dst_mac, icmp_ping->eth.src_mac, ETH_LEN);
        memcpy(icmp_ping_ack->eth.src_mac, icmp_ping->eth.dst_mac, ETH_LEN);

        icmp_ping_ack->icmp_ping.icmp.checkSum = ip_header_calculate_checksum((_u16*)&icmp_ping_ack->icmp_ping, \
                                                          sizeof(struct icmp_ping_header) + icmp_datalen);
        nm_inject(nmr, icmp_buf, sizeof(struct icmp_ping_packet) + icmp_datalen);

        free(icmp_buf);
    }

    return 0;
}
