/*
Project:    IPK 2. projekt
File:       sniffer.cpp
Authors:    Dominik Sajko (xsajko01)
Date:       04.04.2024
*/

#include "sniffer.h"

Sniffer::Sniffer(ArgValues_t inputArgs)
{
    this->interface = inputArgs.interface;
    this->pakcets_count = inputArgs.n;
    this->filters = getFilterString(inputArgs);
    //TODO: Ctrl+C interrupt
}

std::string Sniffer::getFilterString(ArgValues_t inputArgs)
{
    std::string filter;

    if(inputArgs.tcp || inputArgs.udp)
    {
        filter+="(";
        if(inputArgs.tcp)//TCP
        {
            filter += " || tcp";
        }
        if(inputArgs.udp)//UDP
        {
            filter += " || udp";
        }
        filter+=")";
    }
    if(inputArgs.port.size())//set port
    {
        filter += " && port " + inputArgs.port;
    }
    if(inputArgs.source_port.size())//set src port
    {
        filter += " && src port " + inputArgs.source_port;
    }
    if(inputArgs.dest_port.size())//set dst port
    {
        filter += " && dst port " + inputArgs.dest_port;
    }
    
    //protocols
    if(inputArgs.icmp4 || inputArgs.icmp6 || inputArgs.arp || inputArgs.mld ||inputArgs.ndp || inputArgs.igmp)
    {
        if(inputArgs.icmp4)//ICMP4
        {
            filter += " && icmp";
        }
        if(inputArgs.arp)//ARP
        {
            filter += " && arp";
        }   
        if(inputArgs.igmp)//IGMP
        {
            filter += " && igmp";
        }
        if(inputArgs.icmp6)//ICMP6
        {
            filter += " && icmp6";
        }
        if(inputArgs.ndp)//NDP
        {
            // Type 134: Router Advertisement.
            // Type 133: Router Solicitation. ...
            // Type 135: Neighbor Solicitation. ...
            // Type 136: Neighbor Advertisement. ...
            // Type 137: Redirect.
            filter += " && (icmp6-routeradvert ||\
                            icmp6-routersolicit ||\
                            icmp6-neighborsolicit ||\
                            icmp6-neighboradvert ||\
                            icmp6-ineighbordiscoverysolicit ||\
                            icmp6-ineighbordiscoveryadvert ||\
                            icmp6-redirect)";
        }
        if(inputArgs.mld)//MLD
        {
            // Multicast Listener Query	130
            // MLDv1 Multicast Listener Report	131
            // MLDv2 Multicast Listener Report	143
            // Multicast Listener Done	132
            filter += " && (icmp6-multicastlistenerquery ||\
                            icmp6-multicastlistenerreportv1 ||\
                            icmp6-multicastlistenerreportv2 ||\
                            icmp6-multicastlistenerdone)";
        }
    }


    if(filter.size())// remove || from the begining
    {
        if(filter[0] == '(')
        {
            filter.erase(1,4);
        }
        else
        {
            filter.erase(0,4);
        }
    }

    return filter;
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
    if((sniffer = getReceiveHandle(this->interface.c_str(), this->filters.c_str())) == NULL)
    {
        std::cerr << "ERR: Could not create receive handle!\n";
        exit(1);
    }

    //receive packets
    if (pcap_loop(sniffer, this->pakcets_count, parsePacket, (u_char*)NULL) < 0) {
        std::cerr << "ERR: Error while receiving packets! msg: " << pcap_geterr(sniffer) << "\n";
        exit(1);
    }

    //close sniffer_handle
    pcap_close(sniffer);
}