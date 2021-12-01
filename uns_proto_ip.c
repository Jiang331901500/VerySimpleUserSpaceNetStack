#include "uns_proto.h"

int ip_enpack_header(struct ip_header* ip, _u16 id, _u8 proto, _u16 send_len, _u32 src_ip, _u32 dst_ip)
{
    ip->header_len = sizeof(struct ip_header)/4;
    ip->version = 4;
    ip->tos = 0;
    ip->header_check = 0;
    ip->total_len = htons(sizeof(struct ip_header) + send_len);
    ip->id = id;
    ip->flag_off = 0x40; // 目前都不做分片处理
    ip->ttl = 128;
    ip->proto = proto;
    ip->src_ip = src_ip;
    ip->dst_ip = dst_ip;
    ip->header_check = ip_header_calculate_checksum((_u16*)ip, sizeof(struct ip_header));

    return 0;
}

int ip_process(struct nm_desc *nmr, _u8* stream)
{
    struct ip_packet* ip = (struct ip_packet*)stream;   // 取 eth+ip 首部

    switch (ip->ip.proto)
    {
    case IPPROTO_UDP:
        udp_process(nmr, stream);
        break;

    case IPPROTO_ICMP:
        icmp_process(nmr, stream);
        break;
    
    case IPPROTO_TCP:
        tcp_process(nmr, stream);
        break;
    
    default:
        break;
    }

    return 0;
}