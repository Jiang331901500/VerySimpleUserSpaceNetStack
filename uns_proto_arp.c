#include "uns_proto.h"

int arp_process(struct nm_desc *nmr, _u8* stream, _u8* localmac, _u32 localip)
{
    struct arp_packet* arp = (struct arp_packet*)stream;
    _u16 op = ntohs(arp->arp.op);

    // ARP包中的目的PI地址与本机的IP地址是否一致
    if(arp->arp.dst_ip != localip)  
    {
        return -1;
    }

    // 调试打印
    log("confirmed arp to me: ");print_mac(localmac);log(" (");print_ip(localip);log(")\n");

    struct arp_packet arp_ack = {0};
    if(op == arp_op_request) // ARP请求
    {
        memcpy(&arp_ack, arp, sizeof(struct arp_packet));

        memcpy(arp_ack.arp.dst_mac, arp->arp.src_mac, ETH_LEN); // arp报文填入目的 mac
        arp_ack.arp.dst_ip = arp->arp.src_ip;                   // arp报文填入目的 ip
        memcpy(arp_ack.eth.dst_mac, arp->arp.src_mac, ETH_LEN); // 以太网首部填入目的 mac

        memcpy(arp_ack.arp.src_mac, localmac, ETH_LEN); // arp报文填入发送端 mac
        arp_ack.arp.src_ip = localip;                   // arp报文填入发送端 ip
        memcpy(arp_ack.eth.src_mac, localmac, ETH_LEN); // 以太网首部填入源 mac

        arp_ack.arp.op = htons(arp_op_reply);  // ARP响应
    }
    else   
    {   // 其他op暂时未实现
        log("op not implemented.\n");
        return -1;
    }

    nm_inject(nmr, &arp_ack, sizeof(struct arp_packet));    // 发送一个数据包

    return 0;
}