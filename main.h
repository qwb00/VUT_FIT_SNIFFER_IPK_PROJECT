//
// Created by Aleksander on 06.04.2024.
//

#ifndef PROJECT2_MAIN_H
#define PROJECT2_MAIN_H

#include <stdlib.h>
#include <pcap/pcap.h>
#include "args.h"
#include "capture_packet.h"

extern pcap_t* handle;
extern int linkhdrlen;

#define MAX_BUFFER 256
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

void print_all_devices();
void close_program();

#endif //PROJECT2_MAIN_H
