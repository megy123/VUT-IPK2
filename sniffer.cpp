/*
Project:    IPK 2. projekt
File:       sniffer.cpp
Authors:    Dominik Sajko (xsajko01)
Date:       04.04.2024
*/

#include "sniffer.h"

Sniffer::Sniffer(ArgValues_t inputArgs)
{
    this->inputArgs = inputArgs;
    //TODO: Ctrl+C interrupt
}

pcap_t* Sniffer::getReceiveHandle(const char* device,const char* filter)
{
    //init variables
    pcap_t *sniffer = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netmask, source_ip;
    struct bpf_program bpf;
    

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &source_ip, &netmask, error_buffer) == PCAP_ERROR) {
        std::cerr << "ERR: Error while IP/mask resolving. msg:" << error_buffer << "\n";
        return NULL;
    }

    // Open the device for live capture.
    sniffer = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (sniffer == NULL) {
        std::cerr << "ERR: Error while opening capture. msg:" << error_buffer << "\n";
        return NULL;
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(sniffer, &bpf, filter, 0, netmask) == PCAP_ERROR) {
        std::cerr << "ERR: Error while resolving filters. msg:" << pcap_geterr(sniffer) << "\n";
        return NULL;
    }

    // Bind the packet filter to the libpcap handle.
    if (pcap_setfilter(sniffer, &bpf) == PCAP_ERROR) {
        std::cerr << "ERR: Error while binding filters. msg:" << pcap_geterr(sniffer) << "\n";
        return NULL;
    }

    return sniffer;    
}

void parsePacket(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)
{
    std::cout << "Received packet\n";
}

void Sniffer::sniff()
{
    pcap_t *sniffer;

    //set up sniffer handle
    if((sniffer = getReceiveHandle(this->inputArgs.interface.c_str(), "")) == NULL)
    {
        std::cerr << "ERR: Could not create receive handle!\n";
        exit(1);
    }

    //receive packets
    if (pcap_loop(sniffer, this->inputArgs.n, parsePacket, (u_char*)NULL) < 0) {
        std::cerr << "ERR: Error while receiving packets! msg: " << pcap_geterr(sniffer) << "\n";
        exit(1);
    }

    //close sniffer_handle
    pcap_close(sniffer);
}