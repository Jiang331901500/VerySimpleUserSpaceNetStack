#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/poll.h>

#include "uns_common.h"
#include "uns_proto.h"

/* 获取本地的 MAC 的二进制形式到 mac, eth_inf 形式如 "eth0" */
int get_local_mac_and_ip(const char *eth_inf, _u8 *mac, _u32* ip)
{
    struct ifreq ifr;
    struct sockaddr_in sin;
    int sd;
 
    bzero(&ifr, sizeof(struct ifreq));
    if( (sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("get %s mac address socket creat error\n", eth_inf);
        return -1;
    }
    strncpy(ifr.ifr_name, eth_inf, sizeof(ifr.ifr_name) - 1);

    // if error: No such device
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
    {
        printf("ioctl error: %s\n", strerror(errno));
        close(sd);
        return -1;
    }
    // 获取到 IP
    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    *ip = sin.sin_addr.s_addr;
    
    if(ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        printf("get %s mac address error\n", eth_inf);
        close(sd);
        return -1;
    }
    // 获取到 MAC
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_LEN);

    close(sd);
    return 0;
}

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        printf("Usage: %s <ifname such as eth0>.\n", argv[0]);
        return -1;
    }

    _u8 mac[ETH_LEN];
    _u32 ip;

    if(get_local_mac_and_ip(argv[1], mac, &ip) < 0)
    {
        printf("get_local_mac_and_ip failed.\n");
        return -1;
    }

    char netmap_ifname[32] = {0};
    snprintf(netmap_ifname, 31, "netmap:%s", argv[1]);  // example: "netmap:eth1"
    struct nm_desc *nmr = nm_open(netmap_ifname, NULL, 0, NULL);
    if(nmr == NULL)
        return -1;

    struct pollfd pfd = {0};
    pfd.fd = nmr->fd;   // 这个fd实际指向/dev/netmap
    pfd.events = POLLIN;

    while (1)
    {
        int ret = poll(&pfd, 1, -1);
        if(ret < 0) continue;

        if(pfd.revents & POLLIN)
        {
            struct nm_pkthdr nmhead = {0};
            _u8* stream = nm_nextpkt(nmr, &nmhead);  // 取一个数据包

            struct eth_header* eh = (struct eth_header*)stream;  // 先取出链路层首部
            _u16 proto = ntohs(eh->proto);
            if(proto == PROTO_IP)    // 验证链路层的协议字段
                ip_process(nmr, stream);  // IP协议处理
            else if(proto == PROTO_ARP)
                arp_process(nmr, stream, mac, ip); // ARP协议处理
            else
                printf("error: unknown protocal.\n");
        }
    }
    
    nm_close(nmr);

    return 0;
}