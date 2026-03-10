#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>


void fill_iphdr(struct ip *ip_hdr, const char* dst_ip)
{
    ip_hdr->ip_v = 4; 
    ip_hdr->ip_hl = 7;  //28/4=7,28 bytes Header, 包含 8 bytes Option
    ip_hdr->ip_tos = 0; 
    
    ip_hdr->ip_len = htons(PACKET_SIZE); //define in fill_packet.h(92)
    
    ip_hdr->ip_id = 0;               
    ip_hdr->ip_off = htons(IP_DF);   
    ip_hdr->ip_ttl = 1;             
    ip_hdr->ip_p = IPPROTO_ICMP; //protocol=icmp  
    
    ip_hdr->ip_src.s_addr = INADDR_ANY; //kernel會幫我填ip
    inet_pton(AF_INET, dst_ip, &(ip_hdr->ip_dst)); //dst_ip轉二進位放進ip_dst
    ip_hdr->ip_sum = 0;             
    ip_hdr->ip_sum = fill_cksum((unsigned short*)ip_hdr, 28); 
}

extern pid_t pid; 

void fill_icmphdr(struct icmphdr *icmp_hdr)
{
    static int seq = 1;

    icmp_hdr->type = ICMP_ECHO; //icmp echo request     
    icmp_hdr->code = 0;               
    icmp_hdr->un.echo.id = htons(pid); //ID=process id
    icmp_hdr->un.echo.sequence = htons(seq++); //sequence number要遞增

    char *data = (char *)(icmp_hdr + 1);//在icmp header結束後的位址放data:student id
    strncpy(data, "M143040050", ICMP_DATA_SIZE); //student ID
    
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = fill_cksum((unsigned short*)icmp_hdr, ICMP_PACKET_SIZE);
}

u16 fill_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;
    //將資料看成16-bit的數字一直相加
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    //若長度是奇數，處理最後一byte
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }
    //溢位加回來
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum; //not
}

