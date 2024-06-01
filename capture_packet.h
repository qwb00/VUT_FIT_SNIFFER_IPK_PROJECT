//
// Created by Aleksander on 20.04.2024.
//

#ifndef PROJECT2_CAPTURE_PACKET_H
#define PROJECT2_CAPTURE_PACKET_H

#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <ctype.h>
#include <time.h>

#include "main.h"

pcap_t* create_handle(char *device, char *filter_exp);
void get_link_header_type(pcap_t *handle);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif //PROJECT2_CAPTURE_PACKET_H
