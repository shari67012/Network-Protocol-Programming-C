#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <errno.h>

#define PACKET_SIZE 4096

// 計算 Checksum,ICMP協定規定的檢查碼算法
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
    // 每次抓 2 bytes加進 sum
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    // 如果資料長度是奇數，要處理剩下的最後 1 byte
    if (len == 1)
        sum += *(unsigned char *)buf;
    // 將溢位的高位元加回低位元
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    // 取反
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    // 檢查輸入格式
    if (argc != 3) {
        printf("Usage: %s <hop-distance> <destination>\n", argv[0]);
        printf("Example: %s 3 140.117.11.1\n", argv[0]);
        return 1;
    }

    int ttl_val = atoi(argv[1]);
    char *dest_ip_str = argv[2];

    if (ttl_val <= 0) {
        fprintf(stderr, "Error: Hop distance must be > 0\n");
        return 1;
    }

    struct sockaddr_in dest_addr; //要放目的地的ip資訊
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET; //用ipv4

    //ip轉二進位
    if (inet_pton(AF_INET, dest_ip_str, &dest_addr.sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid IP address format: %s\n", dest_ip_str);
        return 1;
    }

    // AF_INET: IPv4 ； SOCK_RAW: 原始接口，我們要手動處理ICMP ；IPPROTO_ICMP: 指定ICMP 協定
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("要加sudo");
        return 1;
    }
    //指定修改ip header裡的TTL欄位
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
        perror("Setsockopt TTL failed");
        close(sockfd);
        return 1;
    }

    // 避免封包寄丟時，程式卡住
    struct timeval timeout;
    timeout.tv_sec = 2; // 等 2 秒
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        perror("Setsockopt Timeout failed");
        close(sockfd);
        return 1;
    }

    //ICMP Echo Request
    char send_buf[PACKET_SIZE];
    memset(send_buf, 0, sizeof(send_buf)); //清空

    struct icmp *icmp_hdr = (struct icmp *)send_buf; // 將這塊記憶體轉成 icmp 結構
    //設定ICMP header
    icmp_hdr->icmp_type = ICMP_ECHO; //echo request
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = getpid() & 0xFFFF; // 用 Process ID 當作識別碼
    icmp_hdr->icmp_seq = 1; //第幾號封包(我只送了一個封包，直接寫1)
    icmp_hdr->icmp_cksum = 0; 
    icmp_hdr->icmp_cksum = checksum(icmp_hdr, sizeof(struct icmp));

    //送封包!!!
    ssize_t bytes_sent = sendto(sockfd, send_buf, sizeof(struct icmp), 0, 
                                (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent <= 0) {
        perror("Sendto failed");
        close(sockfd);
        return 1;
    }

    //收包裹
    char recv_buf[PACKET_SIZE];
    struct sockaddr_in rcv_addr; // 用來存是誰寄來的
    socklen_t addr_len = sizeof(rcv_addr);

    // 從 socket讀取資料
    ssize_t n = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, 
                         (struct sockaddr *)&rcv_addr, &addr_len);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("hop %d: *\n", ttl_val); //timeout了沒收到資料，就印*
        } else {
            perror("Recvfrom error");
        }
    } else {
        //二進位ip轉回人看的ip
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &rcv_addr.sin_addr, src_ip, sizeof(src_ip));

        // 跳過 IP Header，指標移到 ICMP Header 的開頭
        struct ip *ip_header = (struct ip *)recv_buf;
        int ip_header_len = ip_header->ip_hl * 4;
        struct icmp *icmp_reply = (struct icmp *)(recv_buf + ip_header_len);

        //最後輸出
        if (icmp_reply->icmp_type == ICMP_TIMXCEED) {
             printf("Hop %d Router: %s (Time Exceeded)\n", ttl_val, src_ip);
        } else if (icmp_reply->icmp_type == ICMP_ECHOREPLY) {
             printf("Hop %d Destination Reached: %s\n", ttl_val, src_ip);
        } else {
             printf("Hop %d Router: %s (Type: %d)\n", ttl_val, src_ip, icmp_reply->icmp_type);
        }
    }

    close(sockfd);
    return 0;
}
