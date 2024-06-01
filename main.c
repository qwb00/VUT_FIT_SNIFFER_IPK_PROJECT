//
// Created by Aleksander on 06.04.2024.
//

#include "main.h"

pcap_t* handle = NULL;
int linkhdrlen = 0;

void close_program() {
    if (handle != NULL) {
        pcap_close(handle);
    }
    exit(0);
}

// Print all available devices
void print_all_devices() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[MAX_BUFFER];

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }

    printf("Available devices:\n");
    for(d = alldevs; d; d = d->next) {
        printf("%s\n", d->name);
        if(d->description) printf(" (%s)\n", d->description);
    }
    pcap_freealldevs(alldevs);
}

int main(int argc, char *argv[]) {
    char device[MAX_BUFFER];
    char filter_exp[MAX_BUFFER];
    int packets_count = 1;

    device[0] = '\0';
    filter_exp[0] = '\0';

    // Parse the command line arguments
    if (parse_arguments(argc, argv, device, filter_exp, &packets_count) != 0) {
        fprintf(stderr, "Error parsing arguments\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, close_program);

    handle = create_handle(device, filter_exp);
    if (handle == NULL) {
        return EXIT_FAILURE;
    }

    // Get the link header type
    get_link_header_type(handle);
    if(linkhdrlen == 0) {
        return EXIT_FAILURE;
    }

    if(pcap_loop(handle, packets_count, packet_handler, NULL) == -1) {
        fprintf(stderr, "Error in pcap_loop: %s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    close_program();
}

