#include "icmp.h"
#include "checksum.h"
#include <stdio.h>

#define ICMP_CHECKSUM_OFFSET 2
#define ICMP_HEADER_SIZE 8

void buildICMPEchoRequest(unsigned char packet[], unsigned short identifier,
                          unsigned short sequence)
{
    packet[0] = 8; // Echo Request
    packet[1] = 0; // Code

    // Checksum initially zero
    packet[2] = 0;
    packet[3] = 0;

    // Identifier
    packet[4] = identifier >> 8;
    packet[5] = identifier & 0xFF;

    // Sequence number
    packet[6] = sequence >> 8;
    packet[7] = sequence & 0xFF;

    unsigned short checksum = calculateIPv4Checksum(packet, ICMP_HEADER_SIZE);

    packet[ICMP_CHECKSUM_OFFSET] = checksum >> 8;
    packet[ICMP_CHECKSUM_OFFSET + 1] = checksum & 0xFF;
}

void parseICMP(unsigned char packet[], unsigned int start, unsigned int packetSize)
{
    if (packetSize < start + 8)
    {
        printf("Packet too small for ICMP header\n");
        return;
    }

    unsigned char type = packet[start];
    unsigned char code = packet[start + 1];

    unsigned short checksum = (packet[start + 2] << 8) | packet[start + 3];

    unsigned short receivedChecksum = checksum;

    packet[start + 2] = 0;
    packet[start + 3] = 0;

    unsigned short calculatedChecksum = calculateIPv4Checksum(&packet[start], packetSize - start);

    if (receivedChecksum == calculatedChecksum)
    {
        printf("Checksum Status: Valid\n");
    }
    else
    {
        printf("Checksum Status: Invalid\n");
    }

    packet[start + 2] = receivedChecksum >> 8;
    packet[start + 3] = receivedChecksum & 0xFF;

    unsigned short identifier = (packet[start + 4] << 8) | packet[start + 5];

    unsigned short sequence = (packet[start + 6] << 8) | packet[start + 7];

    printf("ICMP Type:       %d\n", type);
    printf("ICMP Code:       %d\n", code);
    printf("ICMP Checksum:   0x%04X\n", checksum);
    printf("Identifier:      0x%04X\n", identifier);
    printf("Sequence:        %d\n", sequence);
}