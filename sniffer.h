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
    ArgValues_t inputArgs;

    pcap_t* getReceiveHandle(const char* device, const char* filter);
    //static void parsePacket(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr);
public:
    Sniffer(ArgValues_t inputArgs);
    void sniff();
};

#endif