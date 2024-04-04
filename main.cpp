/*
Project:    IPK 2. projekt
File:       main.cpp
Authors:    Dominik Sajko (xsajko01)
Date:       04.04.2024
*/
#include <iostream>
#include "parser.h"
#include "sniffer.h"
#include <signal.h>

Sniffer *sniffer;

void printArgs(ArgValues_t args)
{
    std::cout << "Interface: " << args.interface << "\n";
    std::cout << "Port: " << args.port << "\n";
    std::cout << "TCP: " << args.tcp << "\n";
    std::cout << "UDP: " << args.udp << "\n";
    std::cout << "Source port: " << args.source_port << "\n";
    std::cout << "Destination port: " << args.dest_port << "\n";
    std::cout << "n: " << args.n << "\n";
    std::cout << "ICMP4: " << args.icmp4 << "\n";
    std::cout << "ICMP6: " << args.icmp6 << "\n";
    std::cout << "ARP: " << args.arp << "\n";
    std::cout << "NDP: " << args.ndp << "\n";
    std::cout << "IGMP: " << args.igmp << "\n";
    std::cout << "MLD: " << args.mld << "\n";
}

void interruptHandler(int errorCode)
{
    sniffer->closeConnection();
    exit(errorCode);
}

int main(int argc, char *argv[])
{
    //parse arguments
    ArgValues_t args;
    if(parseArgs(argc, argv, &args) == 1)exit(1);

    //printArgs(args);

    //sniffing packets
    sniffer = new Sniffer(args);
    signal(SIGINT, interruptHandler);//interrupt signal
    sniffer->sniff();

}

