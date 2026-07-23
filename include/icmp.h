#ifndef ICMP_H
#define ICMP_H

struct ICMPHeader
{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short identifier;
    unsigned short sequence;
};

void buildICMPEchoRequest(unsigned char packet[], unsigned short identifier,
                          unsigned short sequence);

void parseICMP(unsigned char packet[], unsigned int start, unsigned int packetSize);

#endif
