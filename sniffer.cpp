/*
Project:    IPK 2. projekt
File:       sniffer.cpp
Authors:    Dominik Sajko (xsajko01)
Date:       04.04.2024
*/

#include "sniffer.h"
#include <cmath>
#include <iomanip>
#include <netinet/ether.h>
#include <sys/time.h>
#include <string.h>


#define PACKET_PRINT_LINE_LEN 0x10


//helper functions
std::string formatTimestamp(struct timeval time)
{
    std::string output;
    char value[128] = { 0 };

    time_t nowtime = time.tv_sec;
    struct tm *gm = localtime(&nowtime);
    int off_char = '+';
    int off = (int)gm->tm_gmtoff;
    if (gm->tm_gmtoff < 0) {
            off_char = '-';
            off = -off;
    }

    strftime(value, sizeof(value), "%Y-%m-%dT%H:%M:%S.", gm);

    output += value;
    output += std::to_string(time.tv_usec/1000);
    output += off_char;
    if(off / 3600 < 10)output+="0";
    output += std::to_string(off / 3600);
    output += ":";
    if(off % 3600 < 10)output+="0";
    output += std::to_string(off % 3600);
    return output;
}

void printIpsPorts(const u_char *packetptr)
{
    packetptr += 14;//LINKTYPE_ETHERNET

    //IPs
    struct ip* iphdr = (struct ip*)packetptr;
    
    std::cout << "src IP: " << inet_ntoa(iphdr->ip_src) << "\n";
    std::cout << "dst IP: " << inet_ntoa(iphdr->ip_dst) << "\n";

    //PORTs
    int srcPort;
    int dstPort;
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
    {
        struct tcphdr *tcphdr = (struct tcphdr*)packetptr;
        srcPort = ntohs(tcphdr->th_sport);
        dstPort = ntohs(tcphdr->th_dport);
        break;
    }
    case IPPROTO_UDP:
    {
        struct udphdr *udphdr = (struct udphdr*)packetptr;
        srcPort = ntohs(udphdr->uh_sport);
        dstPort = ntohs(udphdr->uh_dport);
        break;
    }
    case IPPROTO_ICMP:
    {
        struct icmp *icmphdr = (struct icmp*)packetptr;
        // srcPort = ntohs(udphdr->th_sport);
        // dstPort = ntohs(udphdr->th_dport);
        break;
    }
    }

    std::cout << "src port: " << srcPort << "\n";
    std::cout << "dst port: " << dstPort << "\n";

}

void printMacAddresses(const u_char *packetptr)
{
    auto eptr = (struct ether_header *)packetptr;

    std::cout << "src MAC: " << ether_ntoa((struct ether_addr *)eptr->ether_shost) << "\n";
    std::cout << "dst MAC: " << ether_ntoa((struct ether_addr *)eptr->ether_dhost) << "\n";
}

char getPacketChar(uint8_t c)
{
    if(c >= 32 && c <= 126)
    {
        return static_cast<char>(c);
    }
    else
    {
        return '.';
    }
}

void printPacket(const uint8_t *packet, int len)
{
    std::stringstream hexLine;
    std::string charLine;

    for(int i = 0 ; i <= std::ceil(len / PACKET_PRINT_LINE_LEN) ; i++)
    {
        int actualChar = 0;
        //getLines
        for(int j = 0 ; j < PACKET_PRINT_LINE_LEN ; j++)
        {
            actualChar = (i * PACKET_PRINT_LINE_LEN + j);
            
            if(actualChar >= len)
            {
                //fill the empty space
                hexLine << std::string((PACKET_PRINT_LINE_LEN - j)*3, ' ');
                break;
            }

            charLine += getPacketChar(packet[actualChar]);
            hexLine << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(packet[actualChar]) << " ";
        }

        //print to output
        std::cout << "0x" << std::setfill('0') << std::setw(4) << std::hex << i * PACKET_PRINT_LINE_LEN;
        std::cout << " ";
        std::cout << hexLine.str();
        std::cout << charLine;
        std::cout << "\n";
        //clear variables
        hexLine.str("");
        hexLine.clear();
        charLine.clear();
    }
}

//Class methods
void parsePacket(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)
{
    std::cout << "timestamp: " << formatTimestamp(packethdr->ts) << "\n";
    printMacAddresses(packetptr);
    std::cout << "frame length: " << packethdr->len << " bytes\n";
    printIpsPorts(packetptr);
    std::cout << "\n";
    printPacket(packetptr, packethdr->len);
}

Sniffer::Sniffer(ArgValues_t inputArgs)
{
    this->interface = inputArgs.interface;
    this->pakcets_count = inputArgs.n;
    this->filters = getFilterString(inputArgs);
    this->sniffer = NULL;
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

void Sniffer::closeConnection()
{
    pcap_close(this->sniffer);
}

void Sniffer::sniff()
{
    //set up sniffer handle
    if((this->sniffer = getReceiveHandle(this->interface.c_str(), this->filters.c_str())) == NULL)
    {
        std::cerr << "ERR: Could not create receive handle!\n";
        exit(1);
    }

    //receive packets
    if (pcap_loop(this->sniffer, this->pakcets_count, parsePacket, (u_char*)NULL) < 0) {
        std::cerr << "ERR: Error while receiving packets! msg: " << pcap_geterr(this->sniffer) << "\n";
        exit(1);
    }

    //close sniffer_handle
    closeConnection();
}
