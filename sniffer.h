/*
Project:    IPK 2. projekt
File:       sniffer.h
Authors:    Dominik Sajko (xsajko01)
Date:       04.04.2024
*/

#ifndef SNIFFER_H
#define SNIFFER_H

#include "parser.h"
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <iostream>


class Sniffer{
private:
    std::string interface;
    std::string filters;
    int pakcets_count;

    std::string getFilterString(ArgValues_t inputArgs);
    pcap_t* getReceiveHandle(const char* device, const char* filter);
public:
    Sniffer(ArgValues_t inputArgs);
    void sniff();
};

#endif