#include <stdio.h>

#define ETHERNET_HEADER_SIZE 14


struct IPv4Header
{
    unsigned char version;
    unsigned char ihl;
    unsigned short totalLength;
    unsigned char ttl;
    unsigned char protocol;

    unsigned char sourceIP[4];
    unsigned char destinationIP[4];
};


void parseEthernetHeader(unsigned char packet[])
{
    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[0], packet[1], packet[2],
           packet[3], packet[4], packet[5]);

    printf("Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[6], packet[7], packet[8],
           packet[9], packet[10], packet[11]);


    unsigned short etherType =
        (packet[12] << 8) | packet[13];


    printf("EtherType:       0x%04X\n", etherType);


    if (etherType == 0x0800)
    {
        printf("Protocol:        IPv4\n");
    }
    else if (etherType == 0x0806)
    {
        printf("Protocol:        ARP\n");
    }
    else
    {
        printf("Protocol:        Unknown\n");
    }
}


void parseIPv4Header(unsigned char packet[], int start, int packetSize)
{
    if (packetSize < start + 20)
    {
        printf("Packet too small for IPv4 header\n");
        return;
    }


    struct IPv4Header ip;


    ip.version = packet[start] >> 4;

    ip.ihl = packet[start] & 0x0F;


    if (ip.version != 4)
    {
        printf("Not an IPv4 packet\n");
        return;
    }


    if (ip.ihl < 5)
    {
        printf("Invalid IPv4 header length\n");
        return;
    }


    unsigned int headerLength = ip.ihl * 4;


    if (packetSize < start + headerLength)
    {
        printf("Incomplete IPv4 header\n");
        return;
    }


    ip.totalLength =
        (packet[start + 2] << 8) | packet[start + 3];


    if (ip.totalLength > packetSize - start)
    {
        printf("Invalid IPv4 total length\n");
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
    printf("TTL:             %u\n", ip.ttl);
    printf("Protocol ID:     %u\n", ip.protocol);


    if (ip.protocol == 1)
    {
        printf("Next Protocol:   ICMP\n");
    }
    else if (ip.protocol == 6)
    {
        printf("Next Protocol:   TCP\n");
    }
    else if (ip.protocol == 17)
    {
        printf("Next Protocol:   UDP\n");
    }
    else
    {
        printf("Next Protocol:   Unknown\n");
    }


    printf("Source IP:       %u.%u.%u.%u\n",
           ip.sourceIP[0],
           ip.sourceIP[1],
           ip.sourceIP[2],
           ip.sourceIP[3]);


    printf("Destination IP:  %u.%u.%u.%u\n",
           ip.destinationIP[0],
           ip.destinationIP[1],
           ip.destinationIP[2],
           ip.destinationIP[3]);
}


int main(void)
{
    unsigned char packet[] = {

        // Ethernet Header

        // Destination MAC
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

        // Source MAC
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,

        // EtherType IPv4
        0x08, 0x00,


        // IPv4 Header

        // Version + IHL
        0x45,

        // DSCP + ECN
        0x00,

        // Total Length = 60 bytes
        0x00, 0x3C,

        // Identification
        0x12, 0x34,

        // Flags + Fragment Offset
        0x00, 0x00,

        // TTL
        0x40,

        // Protocol TCP
        0x06,

        // Header Checksum
        0x00, 0x00,

        // Source IP: 192.168.1.100
        0xC0, 0xA8, 0x01, 0x64,

        // Destination IP: 8.8.8.8
        0x08, 0x08, 0x08, 0x08,


        // Payload (40 bytes)

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };


    parseEthernetHeader(packet);

    parseIPv4Header(
        packet,
        ETHERNET_HEADER_SIZE,
        sizeof(packet)
    );


    return 0;
}