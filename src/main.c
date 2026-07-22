#include <stdio.h>

void parseEthernetHeader(unsigned char packet[])
{
    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[0], packet[1], packet[2],
           packet[3], packet[4], packet[5]);

    printf("Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[6], packet[7], packet[8],
           packet[9], packet[10], packet[11]);

    unsigned short etherType = (packet[12] << 8) | packet[13];

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

    void parseIPv4Header(unsigned char packet[])
{
    int ipv4Start = 14;

    unsigned char version = packet[ipv4Start] >> 4;
    printf("Version:         %u\n", version);

    unsigned char ihl = packet[ipv4Start] & 0x0F;
    printf("IHL:             %u\n", ihl);

    unsigned short totalLength =
        (packet[ipv4Start + 2] << 8) | packet[ipv4Start + 3];
    printf("Total Length:    %u bytes\n", totalLength);

    unsigned char ttl = packet[ipv4Start + 8];
    printf("TTL:             %u\n", ttl);

    unsigned char protocol = packet[ipv4Start + 9];

    printf("Protocol ID:     %u\n", protocol);

    if (protocol == 1)
    {
        printf("Next Protocol:   ICMP\n");
    }
    else if (protocol == 6)
    {
        printf("Next Protocol:   TCP\n");
    }
    else if (protocol == 17)
    {
        printf("Next Protocol:   UDP\n");
    }
    else
    {
        printf("Next Protocol:   Unknown\n");
    }

    printf("Source IP:       %u.%u.%u.%u\n",
           packet[ipv4Start + 12],
           packet[ipv4Start + 13],
           packet[ipv4Start + 14],
           packet[ipv4Start + 15]);

    printf("Destination IP:  %u.%u.%u.%u\n",
           packet[ipv4Start + 16],
           packet[ipv4Start + 17],
           packet[ipv4Start + 18],
           packet[ipv4Start + 19]);
}

int main(void)
{
    unsigned char packet[] = {
        // =========================
        // Ethernet Header (14 bytes)
        // =========================

        // Destination MAC
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

        // Source MAC
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,

        // EtherType (IPv4)
        0x08, 0x00,

        // ======================
        // IPv4 Header (20 bytes)
        // ======================

        // Version + IHL
        0x45,

        // DSCP + ECN
        0x00,

        // Total Length
        0x00, 0x3C,

        // Identification
        0x12, 0x34,

        // Flags + Fragment Offset
        0x00, 0x00,

        // TTL
        0x40,

        // Protocol (TCP)
        0x06,

        // Header Checksum
        0x00, 0x00,

        // Source IP (192.168.1.100)
        0xC0, 0xA8, 0x01, 0x64,

        // Destination IP (8.8.8.8)
        0x08, 0x08, 0x08, 0x08
    };

    parseEthernetHeader(packet);

    parseIPv4Header(packet);

    return 0;
}