#include <stdio.h>
#include "ipv4.h"
#include "checksum.h"

#define IPV4_CHECKSUM_OFFSET 10

struct IPv4Header
{
    unsigned char version;
    unsigned char ihl;
    unsigned short totalLength;
    unsigned short identification;
    unsigned char flags;
    unsigned short fragmentOffset;
    unsigned char ttl;
    unsigned char protocol;

    unsigned char sourceIP[4];
    unsigned char destinationIP[4];
};

const char *getProtocolName(unsigned char protocol)
{
    switch (protocol)
    {
    case 1:
        return "ICMP";

    case 6:
        return "TCP";

    case 17:
        return "UDP";

    default:
        return "Unknown";
    }
}

void parseIPv4Header(unsigned char packet[], int start, int packetSize)
{
    struct IPv4Header ip;

    if (packetSize < start + 20)
    {
        printf("Packet too small for IPv4 header\n");
        return;
    }

    ip.version = packet[start] >> 4;

    ip.ihl = packet[start] & 0x0F;

    if (ip.version != 4)
    {
        printf("Not IPv4\n");
        return;
    }

    if (ip.ihl < 5)
    {
        printf("Invalid IHL\n");
        return;
    }

    unsigned int headerLength = ip.ihl * 4;

    if (packetSize < start + headerLength)
    {
        printf("Incomplete IPv4 header\n");
        return;
    }

    unsigned short receivedChecksum =
        (packet[start + IPV4_CHECKSUM_OFFSET] << 8) | packet[start + IPV4_CHECKSUM_OFFSET + 1];

    unsigned short verification = calculateIPv4Checksum(&packet[start], headerLength);

    printf("\nReceived Checksum: 0x%04X\n", receivedChecksum);

    if (verification == 0)
    {
        printf("Checksum Status:   Valid\n");
    }
    else
    {
        printf("Checksum Status:   Invalid\n");
    }

    ip.totalLength = (packet[start + 2] << 8) | packet[start + 3];

    if (ip.totalLength > packetSize - start)
    {
        printf("Invalid IPv4 total length\n");
        return;
    }

    ip.identification = (packet[start + 4] << 8) | packet[start + 5];

    unsigned short flagsAndOffset = (packet[start + 6] << 8) | packet[start + 7];

    ip.flags = flagsAndOffset >> 13;
    ip.fragmentOffset = flagsAndOffset & 0x1FFF;

    unsigned char moreFragments = ip.flags & 0x1;

    if (moreFragments || ip.fragmentOffset != 0)
    {
        printf("Fragmented IPv4 packets are not supported\n");
        return;
    }

    ip.ttl = packet[start + 8];

    ip.protocol = packet[start + 9];

    ip.sourceIP[0] = packet[start + 12];
    ip.sourceIP[1] = packet[start + 13];
    ip.sourceIP[2] = packet[start + 14];
    ip.sourceIP[3] = packet[start + 15];

    ip.destinationIP[0] = packet[start + 16];
    ip.destinationIP[1] = packet[start + 17];
    ip.destinationIP[2] = packet[start + 18];
    ip.destinationIP[3] = packet[start + 19];

    printf("Version:         %u\n", ip.version);
    printf("IHL:             %u\n", ip.ihl);
    printf("Header Length:   %u bytes\n", headerLength);
    printf("Total Length:    %u bytes\n", ip.totalLength);
    printf("Identification:  0x%04X\n", ip.identification);
    printf("Flags:           0x%X\n", ip.flags);
    printf("Fragment Offset: %u\n", ip.fragmentOffset);
    printf("TTL:             %u\n", ip.ttl);
    printf("Protocol:        %s\n", getProtocolName(ip.protocol));

    printf("Source IP:       %u.%u.%u.%u\n", ip.sourceIP[0], ip.sourceIP[1], ip.sourceIP[2],
           ip.sourceIP[3]);

    printf("Destination IP:  %u.%u.%u.%u\n", ip.destinationIP[0], ip.destinationIP[1],
           ip.destinationIP[2], ip.destinationIP[3]);
}