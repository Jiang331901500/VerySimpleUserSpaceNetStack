/* 所有协议通用的辅助函数 */

#include "uns_proto.h"

void print_mac(_u8* mac)
{
    int i;
    for(i = 0; i < ETH_LEN - 1; i++)
    {
        log("%02x:", mac[i]);
    }

    log("%02x", mac[i]);
}

void print_ip(_u32 ip)
{
    _u8* p = (_u8*)&ip;
    int i;
    for(i = 0; i < IP_LEN - 1; i++)
    {
        log("%d.", p[i]);
    }

    log("%d", p[i]);
}

/* 计算 ip 首部校验和 */
_u16 ip_header_calculate_checksum(_u16 *addr, int len)
{
	register int nleft = len;
	register _u16 *w = addr;
	register int sum = 0;
	_u16 answer = 0;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(_u8*)(&answer) = *(_u8*)w ;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);	
	sum += (sum >> 16);			
	answer = ~sum;
	
	return answer;
}

/* TCP 和 UDP 数据报的校验和计算，注意与IP头部校验和不同，需要增加伪首部 */
_u16 tcp_udp_calculate_checksum(_u16 *buf, _u16 len, _u32 saddr, _u32 daddr, _u8 proto)
{
	_u32 sum;
	_u16 *w;
	int nleft;
	
	sum = 0;
	nleft = len;
	w = buf;
	
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	
	// add padding for odd length   // 补齐16 bits
	if (nleft)
		sum += *w & ntohs(0xFF00);
	
	// add pseudo header // 增加伪首部
	sum += (saddr & 0x0000FFFF) + (saddr >> 16);
	sum += (daddr & 0x0000FFFF) + (daddr >> 16);
	sum += htons(len);
	sum += htons(proto);
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	sum = ~sum;
	
	return (_u16)sum;
}

/* 将字符串表示形式的MAC地址转换成二进制格式 */
int str2mac(_u8* mac, char* macstr)
{
    if(macstr == NULL || mac == NULL)
        return -1;

    char* p = macstr;
    int idx = 0;
    _u8 val = 0;

    while(*p != '\0' && idx < ETH_LEN)
    {
        if(*p != ':')
        {
            char c = *p;
            if(c >= 'a' && c <= 'f')
                val = (val << 4) + (c - 'a' + 10);
            else if(c >= 'A' && c <= 'F')
                val = (val << 4) + (c - 'A' + 10);
            else if(c >= '0' && c <= '9')   // 数字0~9
                val = (val << 4) + (c - '0');
            else
                return -1; // 非法字符
        }
        else    // 读到一个字节
        {
            mac[idx++] = val;
            val = 0;
        }

        p++;
    }
    if(idx < ETH_LEN)
        mac[idx] = val; // 最后一个字节
    else
        return -1; // 字节数不对

    return 0;
}