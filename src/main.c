#include <stdio.h>
#include "checksum.h"
#include "ipv4.h"

#define ETHERNET_HEADER_SIZE 14
#define IPV4_CHECKSUM_OFFSET 10


void parseEthernetHeader(unsigned char packet[])
{
    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", packet[0], packet[1], packet[2],
           packet[3], packet[4], packet[5]);

    printf("Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n", packet[6], packet[7], packet[8],
           packet[9], packet[10], packet[11]);

    unsigned short etherType = (packet[12] << 8) | packet[13];

    printf("EtherType:       0x%04X\n", etherType);

    if (etherType == 0x0800)
    {
        printf("Protocol:        IPv4\n");
    }
}

int main(void)
{
    unsigned char packet[] = {
        // Ethernet Header
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0x08, 0x00,

        // IPv4 Header
        0x45, 0x00,

        0x00, 0x3C,

        0x12, 0x34,

        0x00, 0x00,

        0x40,

        0x06,

        // checksum initially zero
        0x00, 0x00,

        // Source IP
        0xC0, 0xA8, 0x01, 0x64,

        // Destination IP
        0x08, 0x08, 0x08, 0x08,

        // Payload
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    unsigned char ipv4Start = ETHERNET_HEADER_SIZE;

    unsigned int headerLength = (packet[ipv4Start] & 0x0F) * 4;

    unsigned short checksum = calculateIPv4Checksum(&packet[ipv4Start], headerLength);

    packet[ipv4Start + IPV4_CHECKSUM_OFFSET] = checksum >> 8;

    packet[ipv4Start + IPV4_CHECKSUM_OFFSET + 1] = checksum & 0xFF;

    printf("Inserted Checksum: 0x%04X\n\n", checksum);

    parseEthernetHeader(packet);

    parseIPv4Header(packet, ETHERNET_HEADER_SIZE, sizeof(packet));

    return 0;
}