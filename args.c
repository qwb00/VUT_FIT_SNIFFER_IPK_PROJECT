//
// Created by Aleksander on 20.04.2024.
//

#include "args.h"

// Prints help message
void print_help(void) {
    printf("Usage: ipk-sniffer [OPTIONS]\n");
    printf("\nOptions:\n");
    printf("  -i, --interface <name>      Specify the network interface to capture packets from.\n");
    printf("  -t, --tcp                   Capture only TCP segments.\n");
    printf("  -u, --udp                   Capture only UDP datagrams.\n");
    printf("  -a, --arp                   Capture only ARP frames.\n");
    printf("  -4, --icmp4                 Capture only ICMPv4 packets.\n");
    printf("  -6, --icmp6                 Capture only ICMPv6 packets.\n");
    printf("  -g, --igmp                  Capture only IGMP packets.\n");
    printf("  -m, --mld                   Capture only MLD packets.\n");
    printf("  -d, --ndp                   Capture only NDP packets.\n");
    printf("  -p, --port <port>           Filter packets to include only those with the specified port in either source or destination.\n");
    printf("  --port-source <port>        Filter packets based on the source port.\n");
    printf("  --port-destination <port>   Filter packets based on the destination port.\n");
    printf("  -n, --num <count>           Specify the number of packets to capture before terminating.\n");
    printf("  -h, --help                  Display this help and exit.\n");
    exit(EXIT_SUCCESS);
}

// Function to parse command line arguments
int parse_arguments(int argc, char *argv[], char *device, char *filter_exp, int *packets_count) {
    int opt, long_index = 0;
    device[0] = '\0'; // Initialize the device string to be empty
    filter_exp[0] = '\0'; // Initialize the filter expression string to be empty
    int dst_port = -1, src_port = -1, port = -1;
    int tcp_flag = 0, udp_flag = 0, mld_flag = 0, ndp_flag = 0, icmp6_flag = 0;

    static struct option long_options[] = {
            {"interface", required_argument, 0, 'i'},
            {"tcp", no_argument, 0, 't'},
            {"udp", no_argument, 0, 'u'},
            {"arp", no_argument, 0, 'a'},
            {"icmp4", no_argument, 0, '4'},
            {"icmp6", no_argument, 0, '6'},
            {"igmp", no_argument, 0, 'g'},
            {"mld", no_argument, 0, 'm'},
            {"ndp", no_argument, 0, 'd'},
            {"port-destination", required_argument, 0, 'D'},
            {"port-source", required_argument, 0, 'S'},
            {"n", required_argument, 0, 'n'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
    };

    if ((argc == 2 && (!strcmp(argv[1], "-i") || !strncmp(argv[1], "--interface", 11))) || argc == 1) {
        print_all_devices();
        exit(0);
    }

    while ((opt = getopt_long(argc, argv, "i:tua4dgm6n:p:D:S:h", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'i':
                strncpy(device, optarg, MAX_BUFFER - 1);
                device[MAX_BUFFER - 1] = '\0';
                break;
            case 't':
                tcp_flag = 1;
                break;
            case 'u':
                udp_flag = 1;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'D':
                dst_port = atoi(optarg);
                break;
            case 'S':
                src_port = atoi(optarg);
                break;
            case 'n':
                *packets_count = atoi(optarg);
                break;
            case 'g':
                strcat(filter_exp, strlen(filter_exp) > 0 ? " or igmp" : "igmp");
                break;
            case 'm':
                mld_flag = 1;
                break;
            case '4':
                strcat(filter_exp, strlen(filter_exp) > 0 ? " or icmp" : "icmp");
                break;
            case '6':
                icmp6_flag = 1;
                break;
            case 'a':
                strcat(filter_exp, strlen(filter_exp) > 0 ? " or arp" : "arp");
                break;
            case 'd':
                ndp_flag = 1;
                break;
            case 'h':
                print_help();
                break;
            default:
                return -1; // Indicates error in parsing
        }
    }

    if (tcp_flag || udp_flag) {
        create_tcp_udp_filter(filter_exp, tcp_flag, udp_flag);
        int res = create_port_filter(filter_exp, port, src_port, dst_port);
        if (res == -1) {
            fprintf(stderr, "Error: -p option can't be used with --port-source or --port-destination\n");
            return -1;
        }
    }
    else if(port != -1 || src_port != -1 || dst_port != -1) {
        fprintf(stderr, "Error: -p, --port-source, --port-destination options can only be used with -t or -u options\n");
        return -1;
    }

    if (mld_flag) {
        create_mld_filter(filter_exp);
    }

    if (ndp_flag) {
        create_ndp_filter(filter_exp);
    }

    if (icmp6_flag) {
        create_icmp6_filter(filter_exp);
    }

    return 0; // Success
}

void create_tcp_udp_filter(char *filter_exp, int tcp_flag, int udp_flag) {
    if (tcp_flag && udp_flag) {
        strcat(filter_exp, strlen(filter_exp) > 0 ? " or tcp or udp" : "tcp or udp");
    }
    else if (tcp_flag) strcat(filter_exp, strlen(filter_exp) > 0 ? " or tcp" : "tcp");
    else if (udp_flag) strcat(filter_exp, strlen(filter_exp) > 0 ? " or udp" : "udp");
}

int create_port_filter(char *filter_exp, int port, int src_port, int dst_port) {
    if (port != -1) {
        if (dst_port == -1 && src_port == -1) {
            char port_str[20];
            sprintf(port_str, " and port %d", port);
            strcat(filter_exp, port_str);
        }
        else {
            return -1;
        }
    }
    if (src_port != -1) {
        char port_str[20];
        sprintf(port_str, " and src port %d", src_port);
        strcat(filter_exp, port_str);
    }
    if (dst_port != -1) {
        char port_str[20];
        sprintf(port_str, " and dst port %d", dst_port);
        strcat(filter_exp, port_str);
    }
    return 1;
}

void create_mld_filter(char *filter_exp) {
    strcat(filter_exp, strlen(filter_exp) > 0 ? " or icmp6 and ip6[40] == 130" : "icmp6 and ip6[40] == 130"); // for mld query
    strcat(filter_exp, " or icmp6 and ip6[40] == 131"); // for mld report
    strcat(filter_exp, " or icmp6 and ip6[40] == 132"); // for mld done
}

void create_ndp_filter(char *filter_exp) {
    // Check if there are any other filters already present
    const char *prefix = strlen(filter_exp) > 0 ? " or " : "";
    // Add filter for NDP messages
    strcat(filter_exp, prefix);
    strcat(filter_exp, "icmp6 and (");
    strcat(filter_exp, "ip6[40] == 133"); // Router Solicitation
    strcat(filter_exp, " or ip6[40] == 134"); // Router Advertisement
    strcat(filter_exp, " or ip6[40] == 135"); // Neighbor Solicitation
    strcat(filter_exp, " or ip6[40] == 136"); // Neighbor Advertisement
    strcat(filter_exp, " or ip6[40] == 137"); // Redirect
    strcat(filter_exp, ")");
}


void create_icmp6_filter(char *filter_exp) {
    // Check if there are any other filters already present
    if (strlen(filter_exp) > 0) {
        strcat(filter_exp, " or ");
    }

    // Add filter for icmp6 type 128 (echo request) and 129 (echo reply)
    strcat(filter_exp, "(icmp6 and (ip6[40] == 128 or ip6[40] == 129))");
}
