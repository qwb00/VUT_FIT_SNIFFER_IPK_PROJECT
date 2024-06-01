//
// Created by Aleksander on 20.04.2024.
//

#ifndef PROJECT2_ARGS_H
#define PROJECT2_ARGS_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "main.h"

int parse_arguments(int argc, char *argv[], char *device, char *filter_exp, int *packets_count);
void print_all_devices();
void create_tcp_udp_filter(char *filter_exp, int tcp_flag, int udp_flag);
int create_port_filter(char *filter_exp, int port, int src_port, int dst_port);
void create_mld_filter(char *filter_exp);
void create_ndp_filter(char *filter_exp);
void create_icmp6_filter(char *filter_exp);

#endif //PROJECT2_ARGS_H
