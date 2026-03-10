#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <unistd.h>


extern pid_t pid;

static char filter_string[FILTER_STRING_SIZE] = "";
static pcap_t *p;
static struct pcap_pkthdr hdr;
static int sys_timeout = 1000;


void my_pcap_init(const char* dev, const char* my_ip, int timeout)
{	
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct bpf_program fcode;
	sys_timeout = timeout;
	
	if(pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1){
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}

	//監聽
	p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	}
	//設Non-blocking
	if (pcap_setnonblock(p, 1, errbuf) == -1){
	  fprintf(stderr, "pcap_setnonblock: %s\n", errbuf);
          exit(1);
        }

	
	// 過濾規則：接收 "ICMP" 且 "目的地是自己" 且 是" Echo Reply"
	snprintf(filter_string, FILTER_STRING_SIZE, "icmp and dst host %s and icmp[icmptype] == 0", my_ip);
    printf("PCAP Filter: %s\n", filter_string);
	//編譯成 BPF bytecode
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p, "pcap_compile");
		exit(1);
	}
	//套用規則到 Kernel
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p, "pcap_setfilter");
		exit(1);
	}
}

int pcap_get_reply(const char *target_ip)
{
    const u_char *ptr;
    struct ip *ip_hdr;
    struct icmphdr *icmp_hdr;
    struct timeval start, now;
    long elapsed_ms;

    // 紀錄開始時間
    gettimeofday(&start, NULL);

    while (1) {
        // 抓封包
        ptr = pcap_next(p, &hdr);

        if (ptr != NULL) {
            ip_hdr = (struct ip *)(ptr + 14);//跳過ethernet header(14 bytes)
            int ip_header_len = ip_hdr->ip_hl * 4;
            icmp_hdr = (struct icmphdr *)(ptr + 14 + ip_header_len);//icmp header的位址
            //確認是echo reply且id=process id
        if (icmp_hdr->type == ICMP_ECHOREPLY && ntohs(icmp_hdr->un.echo.id) == pid) {
                
                //檢查來源 IP 是否正確
                char src_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip_str, INET_ADDRSTRLEN);

                if (strcmp(src_ip_str, target_ip) == 0) {
                    return 1;
                }
            }
        }

        // --- 檢查是否超時 ---
        gettimeofday(&now, NULL);
        elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;

        if (elapsed_ms > sys_timeout) {
            return 0; 
        }
        
        usleep(100); 

    }
}




