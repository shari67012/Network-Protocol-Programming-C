#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void set_hard_type(struct ether_arp *packet, unsigned short int type)
{
    packet->ea_hdr.ar_hrd = htons(type);
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
    packet->ea_hdr.ar_pro = htons(type);
}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{
    packet->ea_hdr.ar_hln = size;
}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{
    packet->ea_hdr.ar_pln = size;
}
void set_op_code(struct ether_arp *packet, short int code)
{
    packet->ea_hdr.ar_op = htons(code);
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{
    memcpy(packet->arp_sha, address, ETH_ALEN);
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
    memcpy(packet->arp_spa, address, 4);
}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
    memcpy(packet->arp_tha, address, ETH_ALEN);
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
    memcpy(packet->arp_tpa, address, 4);
}

static char *mac_bytes_to_str(const unsigned char mac[6])
{
    char *s = (char*)malloc(18);
    if (!s) return NULL;
    snprintf(s, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return s;
}

char* get_target_protocol_addr(struct ether_arp *packet)
{
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, packet->arp_tpa, buf, sizeof(buf))) return NULL;
    return strdup(buf);
}

char* get_sender_protocol_addr(struct ether_arp *packet)
{
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, packet->arp_spa, buf, sizeof(buf))) return NULL;
    return strdup(buf);
}

char* get_sender_hardware_addr(struct ether_arp *packet)
{
    return mac_bytes_to_str(packet->arp_sha);
}

char* get_target_hardware_addr(struct ether_arp *packet)
{
    return mac_bytes_to_str(packet->arp_tha);
}

void print_usage() {
    printf("[ ARP sniffer and spoof program ]\n");
    printf("Format :\n");
    printf("1) ./arp -l -a\n");
    printf("2) ./arp -l <filter_ip_address>\n");
    printf("3) ./arp -q <query_ip_address>\n");
    printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
}




