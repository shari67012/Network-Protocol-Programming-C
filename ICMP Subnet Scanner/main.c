#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "fill_packet.h"
#include "pcap.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <getopt.h> 

#include <sys/time.h>


pid_t pid;

int main(int argc, char* argv[])
{
    int sockfd;
    int on = 1;
    pid = getpid();
    
    char *device = NULL;
    int timeout = DEFAULT_TIMEOUT;
    int c;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    char my_ip[INET_ADDRSTRLEN];
    char my_mask[INET_ADDRSTRLEN];
    
    struct in_addr ip_addr, mask_addr;

    //解析-i 和 -t
    while ((c = getopt(argc, argv, "i:t:")) != -1) {
        switch (c) {
            case 'i':
                device = optarg;
                break;
            case 't':
                timeout = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s -i [interface] -t [timeout]\n", argv[0]);
                exit(1);
        }
    }

    if (device == NULL) {
        fprintf(stderr, "Please specify an interface with -i\n");
        exit(1);
    }

    printf("Scanner ready on device: %s, timeout: %d ms\n", device, timeout);

    //建立一個暫時的 UDP socket
    int ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl_sock < 0) {
        perror("socket for ioctl");
        exit(1);
    }

    // 設定 ifreq 結構的介面名稱
    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);

    //取得 IP Address
    if (ioctl(ioctl_sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        exit(1);
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    ip_addr = sin->sin_addr;
    inet_ntop(AF_INET, &ip_addr, my_ip, INET_ADDRSTRLEN);//轉成字串
    printf("My IP: %s\n", my_ip);

    //取得 Netmask
    if (ioctl(ioctl_sock, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK");
        exit(1);
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    mask_addr = sin->sin_addr;
    inet_ntop(AF_INET, &mask_addr, my_mask, INET_ADDRSTRLEN);//轉成字串
    printf("My Mask: %s\n", my_mask);

    close(ioctl_sock); //關掉這個 socket

    //計算掃描範圍
    // 網路位址 = IP & Mask
    unsigned long net_ip = ip_addr.s_addr & mask_addr.s_addr;
    // 廣播位址 = Network | (~Mask)
    unsigned long broadcast_ip = net_ip | (~mask_addr.s_addr);

    // 計算 Start IP (Network + 1) 和 End IP (Broadcast - 1)
    uint32_t start_ip_h = ntohl(net_ip) + 1;
    uint32_t end_ip_h = ntohl(broadcast_ip) - 1;

    my_pcap_init(device, my_ip, timeout); 

    //準備 Raw Socket (用來發送)
    if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(1);
    }
    //轉成字串
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
    memset(packet, 0, PACKET_SIZE); //清乾淨放packet
    //設定socket 目的地結構
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;

    printf("Start scanning...\n");

    struct timeval start, end;
    
    //掃描迴圈
    for (uint32_t current_ip_h = start_ip_h; current_ip_h <= end_ip_h; current_ip_h++) {
        struct in_addr current_in_addr;
        current_in_addr.s_addr = htonl(current_ip_h);
        
        // 跳過自己的 IP
        if (current_in_addr.s_addr == ip_addr.s_addr) continue;

        char current_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &current_in_addr, current_ip_str, INET_ADDRSTRLEN);//轉成字串

        //設定sendto的目標
        dst.sin_addr = current_in_addr;

        memset(packet, 0, PACKET_SIZE);

        fill_iphdr(&(packet->ip_hdr), current_ip_str);
        fill_icmphdr(&(packet->icmp_hdr));

        printf("PING %s (data size = 10, id = 0x%x, seq = %d , timeout = %d ms)\n", 
               current_ip_str, 
               ntohs(packet->icmp_hdr.un.echo.id), 
               ntohs(packet->icmp_hdr.un.echo.sequence), 
               timeout);

        fflush(stdout);
        
        gettimeofday(&start, NULL);

        if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto");
            continue;
        }

        // 接收回應
        int received = pcap_get_reply(current_ip_str);
        
        gettimeofday(&end, NULL);
        double rtt_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
        
        if (received) {
            printf("\tReply from : %s , time : %.5f ms\n", current_ip_str, rtt_ms);
        } else {
            printf("\tDestination unreachable\n");
        }

    }




    free(packet);
    close(sockfd);
    return 0;
}

