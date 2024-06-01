//
// Created by Aleksander on 20.04.2024.
//

#include "capture_packet.h"

// Function to print all available devices
pcap_t* create_handle(char *device, char *filter_exp) {
    char errbuf[MAX_BUFFER];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (device[0] == '\0') {
        fprintf(stderr, "Error: No device specified\n");
        return NULL;
    }

    // Getting the network address and the netmask of the device
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Error getting netmask for device %s: %s\n", device, errbuf);
        return NULL;
    }

    // Opening the device for sniffing
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
        return NULL;
    }

    // Converting the filter expression to a filter program
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter expression: %s\n", pcap_geterr(handle));
        return NULL;
    }

    // Setting the filter program
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

// Get the link header type
void get_link_header_type(pcap_t *handle) {
    int link_type = pcap_datalink(handle);
    switch (link_type) {
        case DLT_EN10MB:
            linkhdrlen = 14;
            break;
        case DLT_IEEE802_11:
            linkhdrlen = 22;
            break;
        case DLT_NULL:
            linkhdrlen = 4;
            break;
        case DLT_SLIP:
        case DLT_PPP:
            linkhdrlen = 24;
            break;
        default:
            fprintf(stderr, "Unsupported link type: %d\n", link_type);
            linkhdrlen = 0;
    }
}

// Function to print all available devices
void print_ethernet_info(const struct ether_header *eth_header, const struct pcap_pkthdr *header) {
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4],
           eth_header->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4],
           eth_header->ether_dhost[5]);
    printf("frame length: %u bytes\n", header->len);
}

void print_timestamp(const struct pcap_pkthdr *header) {
    struct timeval tv = header->ts;
    struct tm *tm_info = localtime(&tv.tv_sec);
    int milliseconds = tv.tv_usec / 1000;
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tm_info);
    int tz_hour = 0, tz_min = 0;
    char tz_sign = '+';
    long timezone_offset = tm_info->tm_gmtoff;
    if (timezone_offset < 0) {
        tz_sign = '-';
        timezone_offset = -timezone_offset;
    }
    tz_hour = timezone_offset / 3600;
    tz_min = (timezone_offset % 3600) / 60;

    sprintf(timestamp + strlen(timestamp), ".%03d%c%02d:%02d", milliseconds, tz_sign, tz_hour, tz_min);

    printf("timestamp: %s\n", timestamp);
}

void print_tcp_info(const u_char *packet, int header_len) {
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + header_len);
    printf("src port: %d\n", ntohs(tcp->th_sport));
    printf("dst port: %d\n", ntohs(tcp->th_dport));
    printf("info: TCP\n");
}

void print_udp_info(const u_char *packet, int header_len) {
    const struct udphdr *udp = (const struct udphdr *)(packet + header_len);
    printf("src port: %d\n", ntohs(udp->uh_sport));
    printf("dst port: %d\n", ntohs(udp->uh_dport));
    printf("info: UDP\n");
}

void process_ipv4_packet(const u_char *packet) {
    const struct ip *ip_header = (const struct ip *)(packet + linkhdrlen);
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

    // Convert the IP addresses from binary to text form
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // IP address of the source and destination
    printf("src IP: %s\n", src_ip);
    printf("dst IP: %s\n", dst_ip);

    // Length of the IP header
    int ip_header_length = ip_header->ip_hl * 4;

    // Print the protocol
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            print_tcp_info(packet, linkhdrlen + ip_header_length);
            break;
        case IPPROTO_UDP:
            print_udp_info(packet, linkhdrlen + ip_header_length);
            break;
        case IPPROTO_ICMP:
            printf("info: ICMP\n");
            break;
        case IPPROTO_IGMP:
            printf("info: IGMP:\n");
            break;
        default:
            printf("IP protocol: %d\n", ip_header->ip_p);
            break;
    }
}

void process_ipv6_packet(const u_char *packet) {
    const struct ip6_hdr *ip6_header = (const struct ip6_hdr *)(packet + linkhdrlen);
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];

    // Convert the IP addresses from binary to text form
    inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

    // IP address of the source and destination
    printf("src IP: %s\n", src_ip);
    printf("dst IP: %s\n", dst_ip);

    // Length of the IP header
    int header_len = sizeof(struct ip6_hdr);


    // Print the protocol
    switch (ip6_header->ip6_nxt) {
        case IPPROTO_TCP:
            print_tcp_info(packet, linkhdrlen + header_len);
            break;
        case IPPROTO_UDP:
            print_udp_info(packet, linkhdrlen + header_len);
            break;
        case IPPROTO_ICMPV6:
        {
            printf("info: ICMPv6:\n");
        }
            break;
        default:
            printf("Unknown or Unsupported IPv6 protocol: %d\n", ip6_header->ip6_nxt);
            break;
    }
}

void process_arp_packet(const u_char *packet) {
    const struct ether_arp *arp_header = (struct ether_arp *)(packet + linkhdrlen);

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->arp_spa, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, dst_ip, INET_ADDRSTRLEN);

    printf("src IP: %s\n", src_ip);
    printf("dst IP: %s\n", dst_ip);
    printf("info: ARP\n");
}

void print_packet_content(const u_char *packet, int caplen) {
    printf("\n");

    for (int i = 0; i < caplen; i++) {
        if (i % 16 == 0) {
            printf("0x%04x: ", i);
        }
        printf("%02x ", packet[i]);

        if ((i % 16 == 15) || i == caplen - 1) {
            int j = 16 - (i % 16);
            while (j-- > 1) printf("   ");

            printf(" ");
            for (j = i - (i % 16); j <= i; j++) {
                printf("%c", isprint(packet[j]) ? packet[j] : '.');
            }

            printf("\n");
        }
    }
    printf("\n");
}

// Main packet handler function
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ether_header *eth_header = (struct ether_header *) packet;
    u_int16_t eth_type = ntohs(eth_header->ether_type);

    print_timestamp(header);
    print_ethernet_info(eth_header, header);
    switch (eth_type) {
        case ETHERTYPE_IP:
            process_ipv4_packet(packet);
            break;
        case ETHERTYPE_IPV6:
            process_ipv6_packet(packet);
            break;
        case ETHERTYPE_ARP:
            process_arp_packet(packet);
            break;
        default:
            printf("Unsupported Ethernet type: %04x\n", eth_type);
            break;
    }
    print_packet_content(packet, header->caplen);
}
