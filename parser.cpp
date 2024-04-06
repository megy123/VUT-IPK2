/*
Project:    IPK 2. projekt
File:       parser.cpp
Authors:    Dominik Sajko (xsajko01)
Date:       04.04.2024
*/
#include <stdio.h>
#include <stdlib.h>
#include "parser.h"
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <algorithm>

int parseArgs(int argc, char *argv[], ArgValues_t *p_args)
{
    //set default values
    p_args->tcp = false;
    p_args->udp = false;
    p_args->n = 1;

    p_args->icmp4 = false;
    p_args->icmp6 = false;
    p_args->arp = false;
    p_args->ndp = false;
    p_args->igmp = false;
    p_args->mld = false;

    //print available interfaces
    if(argc == 2 && ((strcmp(argv[1], "-i") == 0) || (strcmp(argv[1], "--interface") == 0)))
    {
        std::cout << "\n";
        std::vector<std::string> ifcs = getInterfaceNames();
        for(int i = 0; i < ifcs.size(); i++)
        {
            std::cout << ifcs[i] << "\n";
        }
        std::cout << "\n";
        return 1;
    }

    //no arguments specified
    //TODO: čokoľvel čo nemá - môže byť passnute ako argument bez postihu...
    if(argc == 1)
    {
        std::cout << "Usage:\n"
                  << "./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n";
        return 1;
    }

    //get arguments
    static struct option long_options[] =
    {
        {"interface",           required_argument , 0, 'i'},
        {"tcp",                 no_argument,        0, 't'},
        {"udp",                 no_argument,        0, 'u'},
        {"port-destination",    required_argument,  0, 0},
        {"port-source",         required_argument,  0, 0},
        {"icmp4",               no_argument,        0, 0},
        {"icmp6",               no_argument,        0, 0},
        {"arp",                 no_argument,        0, 0},
        {"ndp",                 no_argument,        0, 0},
        {"igmp",                no_argument,        0, 0},
        {"mld",                 no_argument,        0, 0},
        {0, 0, 0, 0}
    };

    int c;
    int option_index;
    while ((c = getopt_long(argc, argv, "i:p:tun:",long_options, &option_index)) != -1)
    {
        switch(c)
        {
        case 0:
            if(option_index == 3)p_args->dest_port = optarg;
            if(option_index == 4)p_args->source_port = optarg;
            if(option_index == 5)p_args->icmp4 = true;
            if(option_index == 6)p_args->icmp6 = true;
            if(option_index == 7)p_args->arp = true;
            if(option_index == 8)p_args->ndp = true;
            if(option_index == 9)p_args->igmp = true;
            if(option_index == 10)p_args->mld = true;
            break;
        case 'i':
            if(optarg)p_args->interface = optarg;
            break;
        case 'p':
            p_args->port = optarg;
            break;
        case 't':
            p_args->tcp = true;
            break;
        case 'u':
            p_args->udp = true;
            break;
        case 'n':
            p_args->n = std::stoi(optarg);
            if(p_args->n <= 0)
            {
                std::cerr << "ERR: -n argument must be >= 0\n";
                return 1;
            }
            break;
        case '?':
        default:
            std::cout << "Usage:\n"
                      << "./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n";
            return 1;
        }
    }
    return 0;
}

std::vector<std::string> getInterfaceNames()
{
    std::vector<std::string> output;

    //get all interfaces
    struct ifaddrs *interface_addrs;
    if (getifaddrs(&interface_addrs) == -1) {
        std::cerr << "ERR: Could not resolve interface!\n";
        exit(1);
    }

    //get interface names
    for (struct ifaddrs *ifa = interface_addrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)continue;

        if (std::find(output.begin(), output.end(), ifa->ifa_name) == output.end())
        {
            output.push_back(ifa->ifa_name);
        }
    }

    freeifaddrs(interface_addrs);

    return output;
}

