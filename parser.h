/*
Project:    IPK 2. projekt
File:       parser.h
Authors:    Dominik Sajko (xsajko01)
Date:       04.04.2024
*/
#ifndef PARSER_H
#define PARSER_H

#include <iostream>
#include <vector>

//structruce used to store arguments
typedef struct {
    std::string interface;
    std::string port;
    bool tcp;
    bool udp;
    std::string source_port;
    std::string dest_port;
    int n;
    //protocols
    bool icmp4;
    bool icmp6;
    bool arp;
    bool ndp;
    bool igmp;
    bool mld;
} ArgValues_t;

std::vector<std::string> getInterfaceNames();
int parseArgs(int argc, char *argv[], ArgValues_t *p_args);

#endif
