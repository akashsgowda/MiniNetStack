#include <stdio.h>
#include "checksum.h"

#define ETHERNET_HEADER_SIZE 14
#define IPV4_CHECKSUM_OFFSET 10


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
}


void parseIPv4Header(unsigned char packet[], int start, int packetSize)
{
    struct IPv4Header ip;


    ip.version = packet[start] >> 4;

    ip.ihl = packet[start] & 0x0F;


    unsigned int headerLength = ip.ihl * 4;


    unsigned short receivedChecksum =
        (packet[start + IPV4_CHECKSUM_OFFSET] << 8) |
        packet[start + IPV4_CHECKSUM_OFFSET + 1];


    unsigned short verification =
        calculateIPv4Checksum(
            &packet[start],
            headerLength
        );


    printf("\nReceived Checksum: 0x%04X\n",
           receivedChecksum);


    if (verification == 0)
    {
        printf("Checksum Status:   Valid\n");
    }
    else
    {
        printf("Checksum Status:   Invalid\n");
    }


    ip.totalLength =
        (packet[start + 2] << 8) |
        packet[start + 3];


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
    unsigned char packet[] =
    {
        // Ethernet Header
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x12,0x34,0x56,0x78,0x9A,0xBC,
        0x08,0x00,


        // IPv4 Header
        0x45,
        0x00,

        0x00,0x3C,

        0x12,0x34,

        0x00,0x00,

        0x40,

        0x06,

        // checksum initially zero
        0x00,0x00,


        // Source IP
        0xC0,0xA8,0x01,0x64,


        // Destination IP
        0x08,0x08,0x08,0x08,


        // Payload
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };


    unsigned char ipv4Start = ETHERNET_HEADER_SIZE;


    unsigned int headerLength =
        (packet[ipv4Start] & 0x0F) * 4;


    unsigned short checksum =
        calculateIPv4Checksum(
            &packet[ipv4Start],
            headerLength
        );


    packet[ipv4Start + IPV4_CHECKSUM_OFFSET] =
        checksum >> 8;


    packet[ipv4Start + IPV4_CHECKSUM_OFFSET + 1] =
        checksum & 0xFF;


    printf("Inserted Checksum: 0x%04X\n\n",
           checksum);


    parseEthernetHeader(packet);


    parseIPv4Header(
        packet,
        ETHERNET_HEADER_SIZE,
        sizeof(packet)
    );


    return 0;
}